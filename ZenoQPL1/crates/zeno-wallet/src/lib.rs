//! Wallet utilities for ML-DSA keys and transactions.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use zeno_crypto::{default_scheme, PublicKeyBytes, SecretKeyBytes};
use zeno_primitives::sign_transaction;
use zeno_types::{
    Address, ChainId, EvmAddress, EvmTransaction, EvmTransactionKind, Transaction, TransactionBody,
};

/// Stored wallet key file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletKeyFile {
    /// Derived address.
    pub address: Address,
    /// Public key bytes.
    pub public_key: Vec<u8>,
    /// Secret key bytes.
    pub secret_key: Vec<u8>,
}

/// Generates a new wallet.
pub fn generate_wallet() -> Result<WalletKeyFile> {
    let scheme = default_scheme();
    let (public_key, secret_key) = scheme.generate_keypair().context("wallet keypair")?;
    let address = Address(scheme.derive_address(&public_key).context("wallet address")?);
    Ok(WalletKeyFile {
        address,
        public_key: public_key.0,
        secret_key: secret_key.0.clone(),
    })
}

/// Signs a transfer transaction.
pub fn build_signed_transfer(
    wallet: &WalletKeyFile,
    chain_id: String,
    recipient: Address,
    amount: u128,
    nonce: u64,
    fee: u128,
    memo: Option<String>,
    valid_until: Option<u64>,
) -> Result<Transaction> {
    let scheme = default_scheme();
    sign_transaction(
        &*scheme,
        TransactionBody {
            chain_id: ChainId(chain_id),
            sender: wallet.address,
            recipient,
            amount,
            nonce,
            fee,
            evm: None,
            memo,
            valid_until,
        },
        PublicKeyBytes(wallet.public_key.clone()),
        &SecretKeyBytes(wallet.secret_key.clone()),
    )
}

/// Signs an EVM contract deployment transaction.
pub fn build_signed_contract_create(
    wallet: &WalletKeyFile,
    chain_id: String,
    nonce: u64,
    fee: u128,
    gas_limit: u64,
    gas_price: u128,
    bytecode: Vec<u8>,
    valid_until: Option<u64>,
) -> Result<Transaction> {
    let scheme = default_scheme();
    sign_transaction(
        &*scheme,
        TransactionBody {
            chain_id: ChainId(chain_id),
            sender: wallet.address,
            recipient: Address([0u8; 32]),
            amount: 0,
            nonce,
            fee,
            evm: Some(EvmTransaction {
                kind: EvmTransactionKind::Create { bytecode },
                value: 0,
                gas_limit,
                gas_price,
            }),
            memo: Some("evm-create".to_string()),
            valid_until,
        },
        PublicKeyBytes(wallet.public_key.clone()),
        &SecretKeyBytes(wallet.secret_key.clone()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeno_primitives::verify_transaction;

    #[test]
    fn generate_wallet_produces_valid_address() {
        let wallet = generate_wallet().expect("generate");
        assert_ne!(wallet.address.0, [0u8; 32]);
        assert!(!wallet.public_key.is_empty());
        assert!(!wallet.secret_key.is_empty());
    }

    #[test]
    fn build_signed_transfer_verifies() {
        let wallet = generate_wallet().expect("generate");
        let tx = build_signed_transfer(
            &wallet,
            "devnet".to_string(),
            Address([9; 32]),
            100,
            0,
            1,
            None,
            Some(50),
        )
        .expect("sign");
        let scheme = default_scheme();
        verify_transaction(
            &*scheme,
            &ChainId("devnet".to_string()),
            &tx,
            10,
        )
        .expect("verify");
    }

    #[test]
    fn build_signed_contract_create_has_evm_payload() {
        let wallet = generate_wallet().expect("generate");
        let tx = build_signed_contract_create(
            &wallet,
            "devnet".to_string(),
            0,
            1,
            1_000_000,
            0,
            vec![0x60, 0x00],
            None,
        )
        .expect("sign");
        assert!(tx.body.evm.is_some());
    }

    #[test]
    fn build_signed_contract_call_has_contract_address() {
        let wallet = generate_wallet().expect("generate");
        let contract = EvmAddress([7; 20]);
        let tx = super::build_signed_contract_call(
            &wallet,
            "devnet".to_string(),
            contract,
            vec![0xab],
            0,
            1,
            1_000_000,
            0,
            None,
        )
        .expect("sign");
        assert!(tx.body.evm.is_some());
    }
}

/// Signs an EVM contract call transaction.
pub fn build_signed_contract_call(
    wallet: &WalletKeyFile,
    chain_id: String,
    contract: EvmAddress,
    calldata: Vec<u8>,
    nonce: u64,
    fee: u128,
    gas_limit: u64,
    gas_price: u128,
    valid_until: Option<u64>,
) -> Result<Transaction> {
    let scheme = default_scheme();
    let mut recipient = [0u8; 32];
    recipient[12..32].copy_from_slice(&contract.0);
    sign_transaction(
        &*scheme,
        TransactionBody {
            chain_id: ChainId(chain_id),
            sender: wallet.address,
            recipient: Address(recipient),
            amount: 0,
            nonce,
            fee,
            evm: Some(EvmTransaction {
                kind: EvmTransactionKind::Call {
                    contract,
                    input: calldata,
                },
                value: 0,
                gas_limit,
                gas_price,
            }),
            memo: Some("evm-call".to_string()),
            valid_until,
        },
        PublicKeyBytes(wallet.public_key.clone()),
        &SecretKeyBytes(wallet.secret_key.clone()),
    )
}
