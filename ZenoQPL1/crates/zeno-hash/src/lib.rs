//! Hashing and commitment helpers.

use core::{fmt, str::FromStr};

use hex::{FromHex, ToHex};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Fixed 32-byte digest used throughout the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// Returns the zero hash.
    pub const fn zero() -> Self {
        Self([0; 32])
    }

    /// Returns a reference to the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.encode_hex::<String>())
    }
}

/// Parse error for fixed-size digests.
#[derive(Debug, Error)]
pub enum HashParseError {
    #[error("invalid hex encoding: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid digest length")]
    Length,
}

impl FromStr for Hash32 {
    type Err = HashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = <Vec<u8>>::from_hex(value)?;
        if bytes.len() != 32 {
            return Err(HashParseError::Length);
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(Self(hash))
    }
}

/// Blake3 hash of arbitrary bytes.
pub fn hash_bytes(bytes: impl AsRef<[u8]>) -> Hash32 {
    let digest = blake3::hash(bytes.as_ref());
    Hash32(*digest.as_bytes())
}

/// SHA3-256 hash of arbitrary bytes, used where a NIST hash is preferable.
pub fn sha3_hash(bytes: impl AsRef<[u8]>) -> Hash32 {
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(bytes.as_ref());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Hash32(out)
}

/// Deterministic merkle root built from leaf hashes.
pub fn merkle_root(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return hash_bytes([]);
    }

    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(pair[0].as_bytes());
            bytes.extend_from_slice(right.as_bytes());
            next.push(hash_bytes(bytes));
        }
        layer = next;
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{hash_bytes, merkle_root, Hash32};

    #[test]
    fn merkle_root_is_stable() {
        let leaves = [hash_bytes("a"), hash_bytes("b"), hash_bytes("c")];
        assert_eq!(
            merkle_root(&leaves),
            Hash32::from_str("248af8bcc8de124ea6f136e2318c70dd1429f3ede1e4b3736cfd9fc2a085e1c7")
                .expect("hash")
        );
    }

    #[test]
    fn empty_hash_is_deterministic() {
        assert_eq!(hash_bytes(&[]), hash_bytes(&[]));
    }

    #[test]
    fn different_inputs_produce_different_hashes() {
        assert_ne!(hash_bytes("a"), hash_bytes("b"));
    }

    #[test]
    fn sha3_hash_differs_from_blake3() {
        assert_ne!(super::sha3_hash(b"x"), hash_bytes(b"x"));
    }

    #[test]
    fn merkle_root_single_leaf() {
        let leaf = hash_bytes("only");
        assert_eq!(merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn merkle_root_empty_is_deterministic() {
        assert_eq!(merkle_root(&[]), merkle_root(&[]));
    }

    #[test]
    fn hash32_display_roundtrips() {
        let h = hash_bytes("roundtrip");
        let s = h.to_string();
        let h2 = Hash32::from_str(&s).expect("parse");
        assert_eq!(h, h2);
    }

    #[test]
    fn hash32_zero_is_all_zeroes() {
        assert_eq!(Hash32::zero().0, [0u8; 32]);
    }
}
