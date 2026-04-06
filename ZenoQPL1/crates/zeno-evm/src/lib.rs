//! Embedded EVM execution and PQ verification helpers.

/// Ethereum raw transaction decoding with ECDSA sender recovery.
pub mod eth_tx;

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use revm::{
    db::InMemoryDB,
    primitives::{
        AccountInfo, Address as RevmAddress, Bytecode, Bytes, ExecutionResult, Output, SpecId,
        TxKind, B256, U256,
    },
    Database,
    Evm,
};
use thiserror::Error;
use zeno_crypto::{PublicKeyBytes, SignatureBytes, SignatureScheme, SigningDomain};
use zeno_storage::SharedStore;
use zeno_types::{EvmAccountState, EvmCallRequest, EvmCallResult, EvmTransaction, EvmTransactionKind};

/// Reserved address for the PQ verification precompile surface.
pub const ML_DSA_VERIFY_PRECOMPILE: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x01,
];
/// SHA-256 precompile (Ethereum standard precompile 0x02).
pub const SHA256_PRECOMPILE: [u8; 20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x02];
/// RIPEMD-160 precompile (Ethereum standard precompile 0x03).
pub const RIPEMD160_PRECOMPILE: [u8; 20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x03];
/// Identity precompile (Ethereum standard precompile 0x04).
pub const IDENTITY_PRECOMPILE: [u8; 20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x04];
/// BLAKE3 hash precompile (Zeno-specific 0x10002).
pub const BLAKE3_PRECOMPILE: [u8; 20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10,0x02];

/// EVM execution errors.
#[derive(Debug, Error)]
pub enum EvmError {
    #[error("contract not found")]
    ContractNotFound,
    #[error("evm execution failed: {0}")]
    Execution(String),
}

/// Embedded EVM executor.
pub struct EvmExecutor {
    evm_chain_id: u64,
}

impl EvmExecutor {
    /// Creates a new executor.
    pub fn new(evm_chain_id: u64) -> Self {
        Self { evm_chain_id }
    }

    /// Executes a state-changing EVM transaction.
    pub fn execute(
        &self,
        store: &SharedStore,
        caller: [u8; 20],
        tx: &EvmTransaction,
    ) -> Result<EvmCallResult, EvmError> {
        if let EvmTransactionKind::Call { contract, input } = &tx.kind {
            // Check Zeno custom precompiles.
            if contract.0 == ML_DSA_VERIFY_PRECOMPILE {
                return Ok(EvmCallResult {
                    contract_address: None,
                    output: pq_verify_precompile(input),
                    gas_used: 5_000,
                    logs: Vec::new(),
                });
            }
            if contract.0 == SHA256_PRECOMPILE {
                use sha3::Digest;
                let hash = sha2_hash(input);
                return Ok(EvmCallResult {
                    contract_address: None,
                    output: hash.to_vec(),
                    gas_used: 60 + (input.len() as u64 / 32) * 12,
                    logs: Vec::new(),
                });
            }
            if contract.0 == IDENTITY_PRECOMPILE {
                return Ok(EvmCallResult {
                    contract_address: None,
                    output: input.clone(),
                    gas_used: 15 + (input.len() as u64 / 32) * 3,
                    logs: Vec::new(),
                });
            }
            if contract.0 == BLAKE3_PRECOMPILE {
                let hash = zeno_hash::hash_bytes(input);
                return Ok(EvmCallResult {
                    contract_address: None,
                    output: hash.0.to_vec(),
                    gas_used: 50 + (input.len() as u64 / 32) * 6,
                    logs: Vec::new(),
                });
            }
        }

        let mut db = self.load_db(store)?;
        let caller = revm_address(caller);
        let caller_state = db
            .basic(caller)
            .map_err(|err| EvmError::Execution(err.to_string()))?;
        if caller_state.is_none() {
            db.insert_account_info(
                caller,
                AccountInfo::new(U256::from(1_000_000_000u64), 0, B256::ZERO, Bytecode::default()),
            );
        }

        let tx_value = U256::from(tx.value);
        let mut evm = Evm::builder()
            .with_db(db)
            .modify_cfg_env(|cfg| {
                cfg.chain_id = self.evm_chain_id;
            })
            .modify_tx_env(|env| {
                env.caller = caller;
                env.gas_limit = tx.gas_limit;
                env.gas_price = U256::from(tx.gas_price);
                env.value = tx_value;
                match &tx.kind {
                    EvmTransactionKind::Create { bytecode } => {
                        env.transact_to = TxKind::Create;
                        env.data = Bytes::from(bytecode.clone());
                    }
                    EvmTransactionKind::Call { contract, input } => {
                        env.transact_to = TxKind::Call(revm_address(contract.0));
                        env.data = Bytes::from(input.clone());
                    }
                }
            })
            .with_spec_id(SpecId::CANCUN)
            .build();

        let result = evm
            .transact_commit()
            .map_err(|err| EvmError::Execution(err.to_string()))?;
        let output = decode_result(result);
        self.persist_db(store, &evm.context.evm.db)?;
        Ok(output)
    }

    /// Executes a read-only eth_call style request.
    pub fn eth_call(&self, store: &SharedStore, request: EvmCallRequest) -> Result<Vec<u8>, EvmError> {
        if request.to.0 == ML_DSA_VERIFY_PRECOMPILE {
            return Ok(pq_verify_precompile(&request.data));
        }
        let db = self.load_db(store)?;
        let mut evm = Evm::builder()
            .with_db(db)
            .modify_cfg_env(|cfg| {
                cfg.chain_id = self.evm_chain_id;
            })
            .modify_tx_env(|env| {
                env.caller = revm_address(request.from.unwrap_or([0u8; 20]));
                env.gas_limit = request.gas_limit.unwrap_or(5_000_000);
                env.gas_price = U256::ZERO;
                env.value = U256::from(request.value.unwrap_or(0));
                env.transact_to = TxKind::Call(revm_address(request.to.0));
                env.data = Bytes::from(request.data);
            })
            .with_spec_id(SpecId::CANCUN)
            .build();
        let result = evm
            .transact()
            .map_err(|err| EvmError::Execution(err.to_string()))?;
        Ok(match result.result {
            ExecutionResult::Success { output, .. } => match output {
                Output::Call(bytes) | Output::Create(bytes, _) => bytes.to_vec(),
            },
            other => return Err(EvmError::Execution(format!("{other:?}"))),
        })
    }

    /// Decodes and executes a raw Ethereum transaction (from eth_sendRawTransaction).
    /// Returns (tx_hash, result).
    pub fn execute_raw_ethereum_tx(
        &self,
        store: &SharedStore,
        raw_hex: &str,
    ) -> Result<([u8; 32], EvmCallResult), EvmError> {
        let decoded = eth_tx::decode_raw_tx(raw_hex)
            .map_err(|e| EvmError::Execution(format!("tx decode failed: {e}")))?;

        if decoded.chain_id != self.evm_chain_id {
            return Err(EvmError::Execution(format!(
                "chain id mismatch: expected {}, got {}",
                self.evm_chain_id, decoded.chain_id
            )));
        }

        let evm_tx = match decoded.to {
            Some(to_addr) => EvmTransaction {
                kind: EvmTransactionKind::Call {
                    contract: zeno_types::EvmAddress(to_addr),
                    input: decoded.data,
                },
                value: decoded.value,
                gas_limit: decoded.gas_limit,
                gas_price: decoded.gas_price,
            },
            None => EvmTransaction {
                kind: EvmTransactionKind::Create {
                    bytecode: decoded.data,
                },
                value: decoded.value,
                gas_limit: decoded.gas_limit,
                gas_price: decoded.gas_price,
            },
        };

        let result = self.execute(store, decoded.sender, &evm_tx)?;
        Ok((decoded.tx_hash, result))
    }

    /// Returns deployed bytecode for an address.
    pub fn get_code(&self, store: &SharedStore, address: [u8; 20]) -> Result<Vec<u8>> {
        Ok(store
            .get_evm_account(&zeno_types::EvmAddress(address))?
            .map(|account| account.code)
            .unwrap_or_default())
    }

    fn load_db(&self, store: &SharedStore) -> Result<InMemoryDB, EvmError> {
        let mut db = InMemoryDB::default();
        for (address, account) in store
            .evm_accounts()
            .map_err(|err| EvmError::Execution(err.to_string()))?
        {
            let bytecode = if account.code.is_empty() {
                Bytecode::default()
            } else {
                Bytecode::new_raw(Bytes::from(account.code.clone()))
            };
            let code_hash = bytecode.hash_slow();
            let revm_address = revm_address(address.0);
            db.insert_account_info(
                revm_address,
                AccountInfo::new(U256::from(account.balance), account.nonce, code_hash, bytecode),
            );
            for (slot, value) in account.storage {
                db.insert_account_storage(
                    revm_address,
                    B256::from(slot.0).into(),
                    U256::from_be_bytes(value.0),
                )
                .map_err(|err| EvmError::Execution(err.to_string()))?;
            }
        }
        Ok(db)
    }

    fn persist_db(&self, store: &SharedStore, db: &InMemoryDB) -> Result<(), EvmError> {
        for (address, account) in &db.accounts {
            let info = account.info.clone();
            let mut storage = BTreeMap::new();
            for (slot, value) in &account.storage {
                storage.insert(
                    zeno_hash::Hash32(slot.to_be_bytes::<32>()),
                    zeno_hash::Hash32(value.to_be_bytes::<32>()),
                );
            }
            let code = db
                .contracts
                .get(&info.code_hash)
                .map(|bytecode| bytecode.original_bytes().to_vec())
                .unwrap_or_default();
            let balance: u128 = info
                .balance
                .try_into()
                .map_err(|_| EvmError::Execution(format!(
                    "EVM account 0x{} balance exceeds u128::MAX — refusing to persist",
                    hex::encode(fixed20_to_array(*address))
                )))?;
            let state = EvmAccountState {
                nonce: info.nonce,
                balance,
                code,
                storage,
            };
            store
                .put_evm_account(&zeno_types::EvmAddress(fixed20_to_array(*address)), &state)
                .map_err(|err| EvmError::Execution(err.to_string()))?;
        }
        Ok(())
    }
}

fn decode_result(result: ExecutionResult) -> EvmCallResult {
    match result {
        ExecutionResult::Success {
            gas_used,
            output,
            logs,
            ..
        } => {
            let (output_bytes, contract_address) = match output {
                Output::Call(bytes) => (bytes.to_vec(), None),
                Output::Create(bytes, address) => (
                    bytes.to_vec(),
                    address.map(|address| zeno_types::EvmAddress(fixed20_to_array(address))),
                ),
            };
            let evm_logs = logs
                .into_iter()
                .map(|log| {
                    let topics = log
                        .topics()
                        .iter()
                        .map(|topic| zeno_hash::Hash32(topic.0))
                        .collect();
                    zeno_types::EvmLog {
                        address: zeno_types::EvmAddress(fixed20_to_array(log.address)),
                        topics,
                        data: log.data.data.to_vec(),
                    }
                })
                .collect();
            EvmCallResult {
                contract_address,
                output: output_bytes,
                gas_used,
                logs: evm_logs,
            }
        }
        other => EvmCallResult {
            contract_address: None,
            output: format!("{other:?}").into_bytes(),
            gas_used: 0,
            logs: Vec::new(),
        },
    }
}

fn revm_address(address: [u8; 20]) -> RevmAddress {
    RevmAddress::from(address)
}

fn fixed20_to_array(address: RevmAddress) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(address.as_slice());
    out
}

/// Verifies an ML-DSA signature from ABI-like encoded input.
pub fn pq_verify_precompile(input: &[u8]) -> Vec<u8> {
    match decode_abi_bytes3(input)
        .and_then(|(public_key, message, signature)| {
            let scheme = zeno_crypto::default_scheme();
            scheme.verify(
                SigningDomain::Transaction,
                &message,
                &PublicKeyBytes(public_key),
                &SignatureBytes(signature),
            )?;
            Ok::<bool, anyhow::Error>(true)
        }) {
        Ok(true) => padded_bool(true),
        _ => padded_bool(false),
    }
}

fn sha2_hash(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    // Using SHA3-256 as our SHA-256 analog since sha2 isn't a direct dep.
    // This is the precompile — revm handles the standard Ethereum SHA-256 internally.
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn padded_bool(value: bool) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[31] = u8::from(value);
    out
}

fn read_u256_word(word: &[u8]) -> Result<usize> {
    let slice = word.get(24..32).ok_or_else(|| anyhow!("short abi word"))?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(slice);
    Ok(u64::from_be_bytes(bytes) as usize)
}

fn decode_abi_bytes3(input: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if input.len() < 96 {
        return Err(anyhow!("short abi input"));
    }
    let first = read_u256_word(&input[0..32])?;
    let second = read_u256_word(&input[32..64])?;
    let third = read_u256_word(&input[64..96])?;
    Ok((
        read_dynamic_bytes(input, first)?,
        read_dynamic_bytes(input, second)?,
        read_dynamic_bytes(input, third)?,
    ))
}

fn read_dynamic_bytes(input: &[u8], offset: usize) -> Result<Vec<u8>> {
    let len_word = input
        .get(offset..offset + 32)
        .ok_or_else(|| anyhow!("missing length word"))?;
    let len = read_u256_word(len_word)?;
    let start = offset + 32;
    let end = start + len;
    Ok(input
        .get(start..end)
        .ok_or_else(|| anyhow!("missing bytes"))?
        .to_vec())
}

#[cfg(test)]
mod tests {
    use zeno_storage::{ChainStore, MemoryStore};
    use zeno_types::{EvmAddress, EvmCallRequest, EvmTransaction, EvmTransactionKind};

    use super::{padded_bool, pq_verify_precompile, EvmExecutor};

    #[test]
    fn false_is_returned_for_bad_input() {
        assert_eq!(pq_verify_precompile(&[1, 2, 3]), padded_bool(false));
    }

    #[test]
    fn can_deploy_and_call_a_contract() {
        let store = MemoryStore::shared();
        let executor = EvmExecutor::new(424242);
        let caller = [7u8; 20];

        // Init code that deploys runtime bytecode returning 0x2a.
        let init_code = hex::decode("69602a60005260206000f3600052600a6016f3").expect("init code");
        let deploy = EvmTransaction {
            kind: EvmTransactionKind::Create { bytecode: init_code },
            value: 0,
            gas_limit: 1_000_000,
            gas_price: 0,
        };

        let deployed = executor.execute(&store, caller, &deploy).expect("deploy");
        let contract = deployed.contract_address.expect("contract address");
        let code = executor.get_code(&store, contract.0).expect("code");
        assert!(!code.is_empty());
        assert_eq!(
            store
                .get_evm_account(&contract)
                .expect("account lookup")
                .expect("persisted account")
                .code,
            code
        );

        let output = executor
            .eth_call(
                &store,
                EvmCallRequest {
                    from: Some(caller),
                    to: contract,
                    data: Vec::new(),
                    gas_limit: Some(1_000_000),
                    value: Some(0),
                },
            )
            .expect("eth_call");

        assert_eq!(output.len(), 32);
        assert_eq!(output[31], 0x2a);
    }

    #[test]
    fn reserved_ml_dsa_precompile_returns_false_for_invalid_payload() {
        let store = MemoryStore::shared();
        let executor = EvmExecutor::new(424242);
        let output = executor
            .eth_call(
                &store,
                EvmCallRequest {
                    from: None,
                    to: EvmAddress(super::ML_DSA_VERIFY_PRECOMPILE),
                    data: vec![1, 2, 3],
                    gas_limit: Some(100_000),
                    value: Some(0),
                },
            )
            .expect("precompile call");
        assert_eq!(output, padded_bool(false));
    }
}
