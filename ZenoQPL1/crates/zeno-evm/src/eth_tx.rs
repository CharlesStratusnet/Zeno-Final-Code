//! Ethereum raw transaction decoding with ECDSA sender recovery.
//!
//! Supports legacy (pre-EIP-2718) and EIP-1559 (type 0x02) transactions
//! as sent by MetaMask via `eth_sendRawTransaction`.

use anyhow::{anyhow, Result};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

/// Decoded Ethereum transaction with recovered sender.
#[derive(Debug, Clone)]
pub struct DecodedEthTx {
    /// Recovered sender address (20 bytes).
    pub sender: [u8; 20],
    /// Transaction nonce.
    pub nonce: u64,
    /// Gas price (legacy) or max fee per gas (EIP-1559).
    pub gas_price: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient address (`None` for contract creation).
    pub to: Option<[u8; 20]>,
    /// Value in wei.
    pub value: u128,
    /// Calldata or init code.
    pub data: Vec<u8>,
    /// Chain ID from the transaction.
    pub chain_id: u64,
    /// Transaction hash (keccak256 of the raw bytes).
    pub tx_hash: [u8; 32],
}

/// Decodes a hex-encoded raw Ethereum transaction and recovers the sender.
pub fn decode_raw_tx(raw_hex: &str) -> Result<DecodedEthTx> {
    let raw_hex = raw_hex.strip_prefix("0x").unwrap_or(raw_hex);
    let raw = hex::decode(raw_hex).map_err(|e| anyhow!("invalid hex: {e}"))?;
    if raw.is_empty() {
        return Err(anyhow!("empty transaction"));
    }

    let tx_hash = keccak256(&raw);

    if raw[0] == 0x02 {
        decode_eip1559(&raw, tx_hash)
    } else {
        decode_legacy(&raw, tx_hash)
    }
}

// ---------------------------------------------------------------------------
// Legacy transaction decoding
// ---------------------------------------------------------------------------

fn decode_legacy(raw: &[u8], tx_hash: [u8; 32]) -> Result<DecodedEthTx> {
    let items = rlp_decode_list(raw)?;
    if items.len() != 9 {
        return Err(anyhow!("legacy tx must have 9 RLP fields, got {}", items.len()));
    }

    let nonce = rlp_to_u64(&items[0]);
    let gas_price = rlp_to_u128(&items[1]);
    let gas_limit = rlp_to_u64(&items[2]);
    let to = rlp_to_address(&items[3]);
    let value = rlp_to_u128(&items[4]);
    let data = items[5].clone();
    let v = rlp_to_u64(&items[6]);
    let r = items[7].clone();
    let s = items[8].clone();

    // EIP-155: chain_id = (v - 35) / 2
    let chain_id = if v >= 35 { (v - 35) / 2 } else { 0 };

    // Build signing hash: RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
    let signing_payload = rlp_encode_list(&[
        &items[0], &items[1], &items[2], &items[3], &items[4], &items[5],
        &rlp_from_u64(chain_id),
        &[],
        &[],
    ]);
    let signing_hash = keccak256(&signing_payload);

    // Recovery ID: v - 35 - 2*chainId for EIP-155, or v - 27 for pre-EIP-155
    let recovery_v = if v >= 35 {
        (v - 35 - 2 * chain_id) as u8
    } else {
        (v.saturating_sub(27)) as u8
    };

    let sender = recover_sender(&signing_hash, &r, &s, recovery_v)?;

    Ok(DecodedEthTx {
        sender,
        nonce,
        gas_price,
        gas_limit,
        to,
        value,
        data,
        chain_id,
        tx_hash,
    })
}

// ---------------------------------------------------------------------------
// EIP-1559 (type 2) transaction decoding
// ---------------------------------------------------------------------------

fn decode_eip1559(raw: &[u8], tx_hash: [u8; 32]) -> Result<DecodedEthTx> {
    // raw[0] == 0x02, the RLP list starts at raw[1..]
    let items = rlp_decode_list(&raw[1..])?;
    if items.len() != 12 {
        return Err(anyhow!("EIP-1559 tx must have 12 RLP fields, got {}", items.len()));
    }

    let chain_id = rlp_to_u64(&items[0]);
    let nonce = rlp_to_u64(&items[1]);
    let _max_priority_fee = rlp_to_u128(&items[2]);
    let max_fee_per_gas = rlp_to_u128(&items[3]);
    let gas_limit = rlp_to_u64(&items[4]);
    let to = rlp_to_address(&items[5]);
    let value = rlp_to_u128(&items[6]);
    let data = items[7].clone();
    // items[8] = access list (we skip it for signing hash construction)
    let v = rlp_to_u64(&items[9]);
    let r = items[10].clone();
    let s = items[11].clone();

    // Signing hash: keccak256(0x02 || RLP([chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, accessList]))
    let signing_list = rlp_encode_list(&[
        &items[0], &items[1], &items[2], &items[3], &items[4],
        &items[5], &items[6], &items[7], &items[8],
    ]);
    let mut signing_input = vec![0x02u8];
    signing_input.extend_from_slice(&signing_list);
    let signing_hash = keccak256(&signing_input);

    let sender = recover_sender(&signing_hash, &r, &s, v as u8)?;

    Ok(DecodedEthTx {
        sender,
        nonce,
        gas_price: max_fee_per_gas,
        gas_limit,
        to,
        value,
        data,
        chain_id,
        tx_hash,
    })
}

// ---------------------------------------------------------------------------
// ECDSA sender recovery
// ---------------------------------------------------------------------------

fn recover_sender(
    signing_hash: &[u8; 32],
    r_bytes: &[u8],
    s_bytes: &[u8],
    v: u8,
) -> Result<[u8; 20]> {
    let mut sig_bytes = [0u8; 64];
    // r and s are big-endian, possibly shorter than 32 bytes (strip leading zeros)
    let r_padded = left_pad_32(r_bytes);
    let s_padded = left_pad_32(s_bytes);
    sig_bytes[..32].copy_from_slice(&r_padded);
    sig_bytes[32..].copy_from_slice(&s_padded);

    let signature = Signature::from_bytes((&sig_bytes).into())
        .map_err(|e| anyhow!("invalid ECDSA signature: {e}"))?;
    let recovery_id = RecoveryId::from_byte(v)
        .ok_or_else(|| anyhow!("invalid recovery id: {v}"))?;
    let verifying_key = VerifyingKey::recover_from_prehash(signing_hash, &signature, recovery_id)
        .map_err(|e| anyhow!("ECDSA recovery failed: {e}"))?;

    // Ethereum address = keccak256(uncompressed_pubkey[1..])[12..32]
    let pubkey_uncompressed = verifying_key.to_encoded_point(false);
    let pubkey_bytes = pubkey_uncompressed.as_bytes();
    // pubkey_bytes[0] == 0x04 (uncompressed prefix), actual key is [1..65]
    let hash = keccak256(&pubkey_bytes[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Ok(addr)
}

fn left_pad_32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    let len = bytes.len().min(32);
    out[start..start + len].copy_from_slice(&bytes[..len]);
    out
}

// ---------------------------------------------------------------------------
// Minimal RLP codec (decode + encode for signing hash construction)
// ---------------------------------------------------------------------------

/// Decodes a top-level RLP list into its items (each item as raw bytes).
fn rlp_decode_list(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    if data.is_empty() {
        return Err(anyhow!("empty RLP"));
    }
    let (payload, _) = rlp_list_payload(data)?;
    let mut items = Vec::new();
    let mut pos = 0;
    while pos < payload.len() {
        let (item, consumed) = rlp_next_item(&payload[pos..])?;
        items.push(item);
        pos += consumed;
    }
    Ok(items)
}

/// Returns (list_payload, total_bytes_consumed).
fn rlp_list_payload(data: &[u8]) -> Result<(&[u8], usize)> {
    let prefix = data[0];
    if prefix >= 0xf8 {
        // Long list
        let len_len = (prefix - 0xf7) as usize;
        if data.len() < 1 + len_len {
            return Err(anyhow!("rlp: truncated long list length"));
        }
        let len = be_to_usize(&data[1..1 + len_len]);
        let start = 1 + len_len;
        if data.len() < start + len {
            return Err(anyhow!("rlp: truncated long list payload"));
        }
        Ok((&data[start..start + len], start + len))
    } else if prefix >= 0xc0 {
        // Short list
        let len = (prefix - 0xc0) as usize;
        if data.len() < 1 + len {
            return Err(anyhow!("rlp: truncated short list payload"));
        }
        Ok((&data[1..1 + len], 1 + len))
    } else {
        Err(anyhow!("rlp: expected list, got prefix 0x{prefix:02x}"))
    }
}

/// Decodes the next RLP item at `data`, returns (decoded_bytes, total_consumed).
fn rlp_next_item(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    if data.is_empty() {
        return Err(anyhow!("rlp: unexpected end"));
    }
    let prefix = data[0];
    if prefix < 0x80 {
        // Single byte
        Ok((vec![prefix], 1))
    } else if prefix <= 0xb7 {
        // Short string (0-55 bytes)
        let len = (prefix - 0x80) as usize;
        if data.len() < 1 + len {
            return Err(anyhow!("rlp: truncated short string"));
        }
        Ok((data[1..1 + len].to_vec(), 1 + len))
    } else if prefix <= 0xbf {
        // Long string (>55 bytes)
        let len_len = (prefix - 0xb7) as usize;
        if data.len() < 1 + len_len {
            return Err(anyhow!("rlp: truncated long string length"));
        }
        let len = be_to_usize(&data[1..1 + len_len]);
        let start = 1 + len_len;
        if data.len() < start + len {
            return Err(anyhow!("rlp: truncated long string payload"));
        }
        Ok((data[start..start + len].to_vec(), start + len))
    } else if prefix <= 0xf7 {
        // Short list — return the raw encoded list (including prefix)
        let len = (prefix - 0xc0) as usize;
        if data.len() < 1 + len {
            return Err(anyhow!("rlp: truncated short list"));
        }
        Ok((data[..1 + len].to_vec(), 1 + len))
    } else {
        // Long list
        let len_len = (prefix - 0xf7) as usize;
        if data.len() < 1 + len_len {
            return Err(anyhow!("rlp: truncated long list length"));
        }
        let len = be_to_usize(&data[1..1 + len_len]);
        let start = 1 + len_len;
        if data.len() < start + len {
            return Err(anyhow!("rlp: truncated long list"));
        }
        Ok((data[..start + len].to_vec(), start + len))
    }
}

/// Encodes a list of raw byte items as an RLP list.
fn rlp_encode_list(items: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    for item in items {
        rlp_encode_bytes(item, &mut payload);
    }
    let mut out = Vec::new();
    rlp_encode_list_header(payload.len(), &mut out);
    out.extend_from_slice(&payload);
    out
}

fn rlp_encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else if bytes.len() <= 55 {
        out.push(0x80 + bytes.len() as u8);
        out.extend_from_slice(bytes);
    } else {
        let len_bytes = usize_to_be(bytes.len());
        out.push(0xb7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(bytes);
    }
}

fn rlp_encode_list_header(payload_len: usize, out: &mut Vec<u8>) {
    if payload_len <= 55 {
        out.push(0xc0 + payload_len as u8);
    } else {
        let len_bytes = usize_to_be(payload_len);
        out.push(0xf7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn be_to_usize(bytes: &[u8]) -> usize {
    let mut value = 0usize;
    for &b in bytes {
        value = (value << 8) | (b as usize);
    }
    value
}

fn usize_to_be(mut value: usize) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let mut bytes = Vec::new();
    while value > 0 {
        bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    bytes.reverse();
    bytes
}

fn rlp_to_u64(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for &b in bytes {
        value = (value << 8) | (b as u64);
    }
    value
}

fn rlp_to_u128(bytes: &[u8]) -> u128 {
    let mut value = 0u128;
    for &b in bytes {
        value = (value << 8) | (b as u128);
    }
    value
}

fn rlp_to_address(bytes: &[u8]) -> Option<[u8; 20]> {
    if bytes.len() == 20 {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(bytes);
        Some(addr)
    } else {
        None // Empty → contract creation
    }
}

fn rlp_from_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlp_encode_decode_roundtrip() {
        let items: Vec<&[u8]> = vec![b"\x01", b"\x02", b"hello"];
        let encoded = rlp_encode_list(&items);
        let decoded = rlp_decode_list(&encoded).expect("decode");
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], vec![0x01]);
        assert_eq!(decoded[1], vec![0x02]);
        assert_eq!(decoded[2], b"hello".to_vec());
    }

    #[test]
    fn rlp_empty_string() {
        let items: Vec<&[u8]> = vec![b"", b"\x05"];
        let encoded = rlp_encode_list(&items);
        let decoded = rlp_decode_list(&encoded).expect("decode");
        assert_eq!(decoded.len(), 2);
        assert!(decoded[0].is_empty());
        assert_eq!(decoded[1], vec![0x05]);
    }

    #[test]
    fn rlp_to_u64_works() {
        assert_eq!(rlp_to_u64(&[]), 0);
        assert_eq!(rlp_to_u64(&[0x01]), 1);
        assert_eq!(rlp_to_u64(&[0x01, 0x00]), 256);
    }

    #[test]
    fn keccak256_known_vector() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let hash = keccak256(b"");
        assert_eq!(hash[0], 0xc5);
        assert_eq!(hash[1], 0xd2);
    }

    #[test]
    fn left_pad_short_input() {
        let result = left_pad_32(&[0x01, 0x02]);
        assert_eq!(result[30], 0x01);
        assert_eq!(result[31], 0x02);
        assert_eq!(result[29], 0x00);
    }

    #[test]
    fn decode_empty_tx_fails() {
        assert!(decode_raw_tx("").is_err());
    }

    #[test]
    fn decode_garbage_fails() {
        assert!(decode_raw_tx("0xdeadbeef").is_err());
    }
}
