//! Storage backends for chain data.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::Arc,
};

use anyhow::Context;
use parking_lot::RwLock;
use rocksdb::{IteratorMode, Options, WriteBatch, DB};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use tracing::info;
use zeno_hash::Hash32;
use zeno_types::{
    Account, ConsensusSnapshot, ConsensusWalEntry, EvmAccountState, EvmAddress, EvmLog,
    FinalizedBlock, EpochTransition, Genesis, GovernanceState, Receipt, StakingState,
};

/// Storage errors.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("codec error: {0}")]
    Codec(String),
    #[error("backend error: {0}")]
    Backend(String),
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, StorageError> {
    zeno_codec::encode(value).map_err(|err| StorageError::Codec(err.to_string()))
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, StorageError> {
    zeno_codec::decode(bytes).map_err(|err| StorageError::Codec(err.to_string()))
}

fn key(namespace: &str, suffix: impl AsRef<[u8]>) -> Vec<u8> {
    let mut out = namespace.as_bytes().to_vec();
    out.push(b':');
    out.extend_from_slice(suffix.as_ref());
    out
}

/// Shared storage interface.
pub trait ChainStore: Send + Sync {
    /// Stores genesis metadata.
    fn put_genesis(&self, genesis: &Genesis) -> Result<(), StorageError>;
    /// Loads genesis metadata.
    fn get_genesis(&self) -> Result<Option<Genesis>, StorageError>;
    /// Reads an account.
    fn get_account(&self, address: &zeno_types::Address) -> Result<Option<Account>, StorageError>;
    /// Writes an account.
    fn put_account(&self, address: &zeno_types::Address, account: &Account) -> Result<(), StorageError>;
    /// Iterates all accounts.
    fn accounts(&self) -> Result<BTreeMap<zeno_types::Address, Account>, StorageError>;
    /// Reads an EVM account.
    fn get_evm_account(&self, address: &EvmAddress) -> Result<Option<EvmAccountState>, StorageError>;
    /// Writes an EVM account.
    fn put_evm_account(&self, address: &EvmAddress, account: &EvmAccountState) -> Result<(), StorageError>;
    /// Iterates all EVM accounts.
    fn evm_accounts(&self) -> Result<BTreeMap<EvmAddress, EvmAccountState>, StorageError>;
    /// Stores a finalized block.
    fn put_finalized_block(&self, block: &FinalizedBlock) -> Result<(), StorageError>;
    /// Fetches a block by height.
    fn get_block_by_height(&self, height: u64) -> Result<Option<FinalizedBlock>, StorageError>;
    /// Fetches a block by hash.
    fn get_block_by_hash(&self, hash: &Hash32) -> Result<Option<FinalizedBlock>, StorageError>;
    /// Returns the latest finalized block.
    fn latest_block(&self) -> Result<Option<FinalizedBlock>, StorageError>;
    /// Writes a receipt.
    fn put_receipt(&self, receipt: &Receipt) -> Result<(), StorageError>;
    /// Reads a receipt.
    fn get_receipt(&self, tx_hash: &Hash32) -> Result<Option<Receipt>, StorageError>;
    /// Saves consensus snapshot.
    fn put_consensus_snapshot(&self, snapshot: &ConsensusSnapshot) -> Result<(), StorageError>;
    /// Loads consensus snapshot.
    fn get_consensus_snapshot(&self) -> Result<Option<ConsensusSnapshot>, StorageError>;
    /// Appends a consensus WAL entry.
    fn append_consensus_wal(&self, entry: &ConsensusWalEntry) -> Result<(), StorageError>;
    /// Loads the consensus WAL.
    fn load_consensus_wal(&self) -> Result<Vec<ConsensusWalEntry>, StorageError>;
    /// Loads staking state.
    fn get_staking_state(&self) -> Result<Option<StakingState>, StorageError>;
    /// Saves staking state.
    fn put_staking_state(&self, staking_state: &StakingState) -> Result<(), StorageError>;
    /// Loads governance state.
    fn get_governance_state(&self) -> Result<Option<GovernanceState>, StorageError>;
    /// Saves governance state.
    fn put_governance_state(&self, governance_state: &GovernanceState) -> Result<(), StorageError>;
    /// Loads the latest epoch transition.
    fn latest_epoch_transition(&self) -> Result<Option<EpochTransition>, StorageError>;
    /// Saves an epoch transition record.
    fn put_epoch_transition(&self, epoch_transition: &EpochTransition) -> Result<(), StorageError>;
    /// Atomically commits a finalized block with all its receipts and state.
    /// This is crash-safe — either all writes succeed or none do.
    fn atomic_commit_block(
        &self,
        block: &FinalizedBlock,
        accounts: &BTreeMap<zeno_types::Address, Account>,
    ) -> Result<(), StorageError>;
    /// Stores EVM logs for a block height.
    fn put_evm_logs(&self, height: u64, logs: &[EvmLog]) -> Result<(), StorageError>;
    /// Loads EVM logs for a single block height.
    fn get_evm_logs_by_height(&self, height: u64) -> Result<Vec<EvmLog>, StorageError>;
    /// Loads EVM logs across a height range (inclusive).
    fn get_evm_logs_range(&self, from_height: u64, to_height: u64) -> Result<Vec<(u64, EvmLog)>, StorageError>;
}

/// Shared storage handle.
pub type SharedStore = Arc<dyn ChainStore>;

#[derive(Default)]
struct MemoryInner {
    genesis: Option<Genesis>,
    accounts: BTreeMap<zeno_types::Address, Account>,
    evm_accounts: BTreeMap<EvmAddress, EvmAccountState>,
    blocks_by_height: BTreeMap<u64, FinalizedBlock>,
    blocks_by_hash: BTreeMap<Hash32, FinalizedBlock>,
    receipts: BTreeMap<Hash32, Receipt>,
    snapshot: Option<ConsensusSnapshot>,
    consensus_wal: Vec<ConsensusWalEntry>,
    staking_state: Option<StakingState>,
    governance_state: Option<GovernanceState>,
    epoch_transitions: BTreeMap<u64, EpochTransition>,
    evm_logs: BTreeMap<u64, Vec<EvmLog>>,
}

/// In-memory store for testing.
#[derive(Default)]
pub struct MemoryStore {
    inner: RwLock<MemoryInner>,
}

impl MemoryStore {
    /// Creates a shared memory store.
    pub fn shared() -> SharedStore {
        Arc::new(Self::default())
    }
}

impl ChainStore for MemoryStore {
    fn put_genesis(&self, genesis: &Genesis) -> Result<(), StorageError> {
        self.inner.write().genesis = Some(genesis.clone());
        Ok(())
    }

    fn get_genesis(&self) -> Result<Option<Genesis>, StorageError> {
        Ok(self.inner.read().genesis.clone())
    }

    fn get_account(&self, address: &zeno_types::Address) -> Result<Option<Account>, StorageError> {
        Ok(self.inner.read().accounts.get(address).cloned())
    }

    fn put_account(&self, address: &zeno_types::Address, account: &Account) -> Result<(), StorageError> {
        self.inner.write().accounts.insert(*address, account.clone());
        Ok(())
    }

    fn accounts(&self) -> Result<BTreeMap<zeno_types::Address, Account>, StorageError> {
        Ok(self.inner.read().accounts.clone())
    }

    fn get_evm_account(&self, address: &EvmAddress) -> Result<Option<EvmAccountState>, StorageError> {
        Ok(self.inner.read().evm_accounts.get(address).cloned())
    }

    fn put_evm_account(&self, address: &EvmAddress, account: &EvmAccountState) -> Result<(), StorageError> {
        self.inner.write().evm_accounts.insert(*address, account.clone());
        Ok(())
    }

    fn evm_accounts(&self) -> Result<BTreeMap<EvmAddress, EvmAccountState>, StorageError> {
        Ok(self.inner.read().evm_accounts.clone())
    }

    fn put_finalized_block(&self, block: &FinalizedBlock) -> Result<(), StorageError> {
        let mut guard = self.inner.write();
        guard.blocks_by_hash.insert(block.block.hash(), block.clone());
        guard.blocks_by_height.insert(block.block.header.height, block.clone());
        Ok(())
    }

    fn get_block_by_height(&self, height: u64) -> Result<Option<FinalizedBlock>, StorageError> {
        Ok(self.inner.read().blocks_by_height.get(&height).cloned())
    }

    fn get_block_by_hash(&self, hash: &Hash32) -> Result<Option<FinalizedBlock>, StorageError> {
        Ok(self.inner.read().blocks_by_hash.get(hash).cloned())
    }

    fn latest_block(&self) -> Result<Option<FinalizedBlock>, StorageError> {
        Ok(self.inner.read().blocks_by_height.last_key_value().map(|(_, block)| block.clone()))
    }

    fn put_receipt(&self, receipt: &Receipt) -> Result<(), StorageError> {
        self.inner.write().receipts.insert(receipt.tx_hash, receipt.clone());
        Ok(())
    }

    fn get_receipt(&self, tx_hash: &Hash32) -> Result<Option<Receipt>, StorageError> {
        Ok(self.inner.read().receipts.get(tx_hash).cloned())
    }

    fn put_consensus_snapshot(&self, snapshot: &ConsensusSnapshot) -> Result<(), StorageError> {
        self.inner.write().snapshot = Some(snapshot.clone());
        Ok(())
    }

    fn get_consensus_snapshot(&self) -> Result<Option<ConsensusSnapshot>, StorageError> {
        Ok(self.inner.read().snapshot.clone())
    }

    fn append_consensus_wal(&self, entry: &ConsensusWalEntry) -> Result<(), StorageError> {
        self.inner.write().consensus_wal.push(entry.clone());
        Ok(())
    }

    fn load_consensus_wal(&self) -> Result<Vec<ConsensusWalEntry>, StorageError> {
        Ok(self.inner.read().consensus_wal.clone())
    }

    fn get_staking_state(&self) -> Result<Option<StakingState>, StorageError> {
        Ok(self.inner.read().staking_state.clone())
    }

    fn put_staking_state(&self, staking_state: &StakingState) -> Result<(), StorageError> {
        self.inner.write().staking_state = Some(staking_state.clone());
        Ok(())
    }

    fn get_governance_state(&self) -> Result<Option<GovernanceState>, StorageError> {
        Ok(self.inner.read().governance_state.clone())
    }

    fn put_governance_state(&self, governance_state: &GovernanceState) -> Result<(), StorageError> {
        self.inner.write().governance_state = Some(governance_state.clone());
        Ok(())
    }

    fn latest_epoch_transition(&self) -> Result<Option<EpochTransition>, StorageError> {
        Ok(self
            .inner
            .read()
            .epoch_transitions
            .last_key_value()
            .map(|(_, transition)| transition.clone()))
    }

    fn put_epoch_transition(&self, epoch_transition: &EpochTransition) -> Result<(), StorageError> {
        self.inner
            .write()
            .epoch_transitions
            .insert(epoch_transition.epoch, epoch_transition.clone());
        Ok(())
    }

    fn atomic_commit_block(
        &self,
        block: &FinalizedBlock,
        accounts: &BTreeMap<zeno_types::Address, Account>,
    ) -> Result<(), StorageError> {
        let mut guard = self.inner.write();
        // Write all accounts.
        for (address, account) in accounts {
            guard.accounts.insert(*address, account.clone());
        }
        // Write all receipts.
        for receipt in &block.receipts {
            guard.receipts.insert(receipt.tx_hash, receipt.clone());
        }
        // Write block by height and hash.
        guard.blocks_by_hash.insert(block.block.hash(), block.clone());
        guard.blocks_by_height.insert(block.block.header.height, block.clone());
        Ok(())
    }

    fn put_evm_logs(&self, height: u64, logs: &[EvmLog]) -> Result<(), StorageError> {
        self.inner.write().evm_logs.insert(height, logs.to_vec());
        Ok(())
    }

    fn get_evm_logs_by_height(&self, height: u64) -> Result<Vec<EvmLog>, StorageError> {
        Ok(self.inner.read().evm_logs.get(&height).cloned().unwrap_or_default())
    }

    fn get_evm_logs_range(&self, from_height: u64, to_height: u64) -> Result<Vec<(u64, EvmLog)>, StorageError> {
        let guard = self.inner.read();
        let mut result = Vec::new();
        for (&height, logs) in guard.evm_logs.range(from_height..=to_height) {
            for log in logs {
                result.push((height, log.clone()));
            }
        }
        Ok(result)
    }
}

/// RocksDB-backed store.
pub struct RocksStore {
    db: DB,
}

impl RocksStore {
    /// Opens or creates the database at the provided path.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<SharedStore> {
        let path = path.as_ref();
        std::fs::create_dir_all(path).with_context(|| format!("unable to create {}", path.display()))?;
        let mut options = Options::default();
        options.create_if_missing(true);
        let db = DB::open(&options, path).with_context(|| format!("unable to open rocksdb {}", path.display()))?;
        info!(path = %path.display(), "opened rocksdb storage");
        Ok(Arc::new(Self { db }))
    }

    fn get_value<T: DeserializeOwned>(&self, key: &[u8]) -> Result<Option<T>, StorageError> {
        self.db
            .get(key)
            .map_err(|err| StorageError::Backend(err.to_string()))?
            .map(|value| decode(&value))
            .transpose()
    }

    fn put_value<T: Serialize>(&self, key: &[u8], value: &T) -> Result<(), StorageError> {
        self.db
            .put(key, encode(value)?)
            .map_err(|err| StorageError::Backend(err.to_string()))
    }
}

impl ChainStore for RocksStore {
    fn put_genesis(&self, genesis: &Genesis) -> Result<(), StorageError> {
        self.put_value(b"meta:genesis", genesis)
    }

    fn get_genesis(&self) -> Result<Option<Genesis>, StorageError> {
        self.get_value(b"meta:genesis")
    }

    fn get_account(&self, address: &zeno_types::Address) -> Result<Option<Account>, StorageError> {
        self.get_value(&key("acct", address.0))
    }

    fn put_account(&self, address: &zeno_types::Address, account: &Account) -> Result<(), StorageError> {
        self.put_value(&key("acct", address.0), account)
    }

    fn accounts(&self) -> Result<BTreeMap<zeno_types::Address, Account>, StorageError> {
        let mut out = BTreeMap::new();
        for entry in self.db.iterator(IteratorMode::Start) {
            let (key_bytes, value) = entry.map_err(|err| StorageError::Backend(err.to_string()))?;
            if !key_bytes.starts_with(b"acct:") {
                continue;
            }
            let mut address = [0u8; 32];
            address.copy_from_slice(&key_bytes[5..37]);
            out.insert(zeno_types::Address(address), decode::<Account>(&value)?);
        }
        Ok(out)
    }

    fn get_evm_account(&self, address: &EvmAddress) -> Result<Option<EvmAccountState>, StorageError> {
        self.get_value(&key("evm-acct", address.0))
    }

    fn put_evm_account(&self, address: &EvmAddress, account: &EvmAccountState) -> Result<(), StorageError> {
        self.put_value(&key("evm-acct", address.0), account)
    }

    fn evm_accounts(&self) -> Result<BTreeMap<EvmAddress, EvmAccountState>, StorageError> {
        let mut out = BTreeMap::new();
        for entry in self.db.iterator(IteratorMode::Start) {
            let (key_bytes, value) = entry.map_err(|err| StorageError::Backend(err.to_string()))?;
            if !key_bytes.starts_with(b"evm-acct:") {
                continue;
            }
            let mut address = [0u8; 20];
            address.copy_from_slice(&key_bytes[9..29]);
            out.insert(EvmAddress(address), decode::<EvmAccountState>(&value)?);
        }
        Ok(out)
    }

    fn put_finalized_block(&self, block: &FinalizedBlock) -> Result<(), StorageError> {
        let hash = block.block.hash();
        self.put_value(&key("block-h", block.block.header.height.to_le_bytes()), block)?;
        self.put_value(&key("block-b", hash.0), block)?;
        self.put_value(b"meta:latest", block)
    }

    fn get_block_by_height(&self, height: u64) -> Result<Option<FinalizedBlock>, StorageError> {
        self.get_value(&key("block-h", height.to_le_bytes()))
    }

    fn get_block_by_hash(&self, hash: &Hash32) -> Result<Option<FinalizedBlock>, StorageError> {
        self.get_value(&key("block-b", hash.0))
    }

    fn latest_block(&self) -> Result<Option<FinalizedBlock>, StorageError> {
        self.get_value(b"meta:latest")
    }

    fn put_receipt(&self, receipt: &Receipt) -> Result<(), StorageError> {
        self.put_value(&key("rcpt", receipt.tx_hash.0), receipt)
    }

    fn get_receipt(&self, tx_hash: &Hash32) -> Result<Option<Receipt>, StorageError> {
        self.get_value(&key("rcpt", tx_hash.0))
    }

    fn put_consensus_snapshot(&self, snapshot: &ConsensusSnapshot) -> Result<(), StorageError> {
        self.put_value(b"meta:consensus", snapshot)
    }

    fn get_consensus_snapshot(&self) -> Result<Option<ConsensusSnapshot>, StorageError> {
        self.get_value(b"meta:consensus")
    }

    fn append_consensus_wal(&self, entry: &ConsensusWalEntry) -> Result<(), StorageError> {
        let next_index = self
            .get_value::<u64>(b"meta:consensus-wal-next")?
            .unwrap_or(0);
        self.put_value(&key("consensus-wal", next_index.to_le_bytes()), entry)?;
        self.put_value(b"meta:consensus-wal-next", &(next_index + 1))
    }

    fn load_consensus_wal(&self) -> Result<Vec<ConsensusWalEntry>, StorageError> {
        let mut entries = BTreeMap::new();
        for entry in self.db.iterator(IteratorMode::Start) {
            let (key_bytes, value) = entry.map_err(|err| StorageError::Backend(err.to_string()))?;
            if !key_bytes.starts_with(b"consensus-wal:") {
                continue;
            }
            let index_bytes = key_bytes
                .get(14..22)
                .ok_or_else(|| StorageError::Backend("malformed consensus wal index".to_string()))?;
            let mut raw = [0u8; 8];
            raw.copy_from_slice(index_bytes);
            entries.insert(u64::from_le_bytes(raw), decode::<ConsensusWalEntry>(&value)?);
        }
        Ok(entries.into_values().collect())
    }

    fn get_staking_state(&self) -> Result<Option<StakingState>, StorageError> {
        self.get_value(b"meta:staking")
    }

    fn put_staking_state(&self, staking_state: &StakingState) -> Result<(), StorageError> {
        self.put_value(b"meta:staking", staking_state)
    }

    fn get_governance_state(&self) -> Result<Option<GovernanceState>, StorageError> {
        self.get_value(b"meta:governance")
    }

    fn put_governance_state(&self, governance_state: &GovernanceState) -> Result<(), StorageError> {
        self.put_value(b"meta:governance", governance_state)
    }

    fn latest_epoch_transition(&self) -> Result<Option<EpochTransition>, StorageError> {
        self.get_value(b"meta:epoch-latest")
    }

    fn put_epoch_transition(&self, epoch_transition: &EpochTransition) -> Result<(), StorageError> {
        self.put_value(&key("epoch", epoch_transition.epoch.to_le_bytes()), epoch_transition)?;
        self.put_value(b"meta:epoch-latest", epoch_transition)
    }

    fn atomic_commit_block(
        &self,
        block: &FinalizedBlock,
        accounts: &BTreeMap<zeno_types::Address, Account>,
    ) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();
        // Accounts.
        for (address, account) in accounts {
            batch.put(key("acct", address.0), encode(account)?);
        }
        // Receipts.
        for receipt in &block.receipts {
            batch.put(key("rcpt", receipt.tx_hash.0), encode(receipt)?);
        }
        // Block by height and hash.
        let hash = block.block.hash();
        let encoded_block = encode(block)?;
        batch.put(key("block-h", block.block.header.height.to_le_bytes()), &encoded_block);
        batch.put(key("block-b", hash.0), &encoded_block);
        batch.put(b"meta:latest", &encoded_block);
        self.db
            .write(batch)
            .map_err(|err| StorageError::Backend(err.to_string()))
    }

    fn put_evm_logs(&self, height: u64, logs: &[EvmLog]) -> Result<(), StorageError> {
        self.put_value(&key("evm-logs", height.to_le_bytes()), &logs.to_vec())
    }

    fn get_evm_logs_by_height(&self, height: u64) -> Result<Vec<EvmLog>, StorageError> {
        Ok(self.get_value::<Vec<EvmLog>>(&key("evm-logs", height.to_le_bytes()))?.unwrap_or_default())
    }

    fn get_evm_logs_range(&self, from_height: u64, to_height: u64) -> Result<Vec<(u64, EvmLog)>, StorageError> {
        let mut result = Vec::new();
        for height in from_height..=to_height {
            for log in self.get_evm_logs_by_height(height)? {
                result.push((height, log));
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use zeno_types::{
        Account, Address, Block, BlockHeader, ChainId, CommitCertificate, ConsensusSnapshot,
        ConsensusWalEntry, EvmAccountState, EvmAddress, EvmLog, ExecutionOutcome, FinalizedBlock,
        Receipt,
    };
    use zeno_hash::Hash32;

    use super::{ChainStore, MemoryStore};

    #[test]
    fn memory_store_account_roundtrip() {
        let store = MemoryStore::shared();
        let address = Address([1; 32]);
        let account = Account { nonce: 5, balance: 100 };
        store.put_account(&address, &account).expect("put");
        assert_eq!(store.get_account(&address).expect("get").expect("some"), account);
    }

    #[test]
    fn memory_store_missing_account_returns_none() {
        let store = MemoryStore::shared();
        assert!(store.get_account(&Address([99; 32])).expect("get").is_none());
    }

    #[test]
    fn memory_store_accounts_lists_all() {
        let store = MemoryStore::shared();
        store.put_account(&Address([1; 32]), &Account { nonce: 0, balance: 1 }).expect("put");
        store.put_account(&Address([2; 32]), &Account { nonce: 0, balance: 2 }).expect("put");
        assert_eq!(store.accounts().expect("accounts").len(), 2);
    }

    fn test_block(height: u64) -> FinalizedBlock {
        FinalizedBlock {
            block: Block {
                header: BlockHeader {
                    height,
                    round: 0,
                    chain_id: ChainId("test".to_string()),
                    parent_hash: Hash32::zero(),
                    tx_root: Hash32::zero(),
                    state_root: Hash32::zero(),
                    receipt_root: Hash32::zero(),
                    proposer: Address([1; 32]),
                    timestamp_ms: 1,
                },
                transactions: Vec::new(),
                proposer_public_key: Vec::new(),
                proposer_signature: vec![height as u8],
            },
            certificate: CommitCertificate {
                block_hash: Hash32::zero(),
                height,
                round: 0,
                votes: Vec::new(),
            },
            receipts: Vec::new(),
            epoch_transition: None,
        }
    }

    #[test]
    fn memory_store_block_by_height_roundtrip() {
        let store = MemoryStore::shared();
        let block = test_block(1);
        store.put_finalized_block(&block).expect("put");
        let loaded = store.get_block_by_height(1).expect("get").expect("some");
        assert_eq!(loaded.block.header.height, 1);
    }

    #[test]
    fn memory_store_block_by_hash_roundtrip() {
        let store = MemoryStore::shared();
        let block = test_block(2);
        let hash = block.block.hash();
        store.put_finalized_block(&block).expect("put");
        assert!(store.get_block_by_hash(&hash).expect("get").is_some());
    }

    #[test]
    fn memory_store_latest_block_tracks_highest() {
        let store = MemoryStore::shared();
        store.put_finalized_block(&test_block(1)).expect("put");
        store.put_finalized_block(&test_block(3)).expect("put");
        let latest = store.latest_block().expect("get").expect("some");
        assert_eq!(latest.block.header.height, 3);
    }

    #[test]
    fn memory_store_receipt_roundtrip() {
        let store = MemoryStore::shared();
        let receipt = Receipt {
            tx_hash: Hash32([7; 32]),
            height: 1,
            fee_charged: 10,
            outcome: ExecutionOutcome::Success,
            evm: None,
        };
        store.put_receipt(&receipt).expect("put");
        assert_eq!(store.get_receipt(&Hash32([7; 32])).expect("get").expect("some").fee_charged, 10);
    }

    #[test]
    fn memory_store_consensus_snapshot_roundtrip() {
        let store = MemoryStore::shared();
        let snap = ConsensusSnapshot { height: 5, round: 2 };
        store.put_consensus_snapshot(&snap).expect("put");
        let loaded = store.get_consensus_snapshot().expect("get").expect("some");
        assert_eq!(loaded.height, 5);
        assert_eq!(loaded.round, 2);
    }

    #[test]
    fn memory_store_wal_append_and_load() {
        let store = MemoryStore::shared();
        store.append_consensus_wal(&ConsensusWalEntry::HeightAdvanced { next_height: 2 }).expect("append");
        store.append_consensus_wal(&ConsensusWalEntry::RoundAdvanced { height: 2, next_round: 1 }).expect("append");
        let entries = store.load_consensus_wal().expect("load");
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn memory_store_evm_account_roundtrip() {
        let store = MemoryStore::shared();
        let addr = EvmAddress([3; 20]);
        let state = EvmAccountState {
            nonce: 1,
            balance: 42,
            code: vec![0x60, 0x00],
            storage: Default::default(),
        };
        store.put_evm_account(&addr, &state).expect("put");
        let loaded = store.get_evm_account(&addr).expect("get").expect("some");
        assert_eq!(loaded.balance, 42);
    }

    #[test]
    fn memory_store_evm_logs_roundtrip() {
        let store = MemoryStore::shared();
        let logs = vec![EvmLog {
            address: EvmAddress([1; 20]),
            topics: vec![Hash32([9; 32])],
            data: vec![0xab],
        }];
        store.put_evm_logs(5, &logs).expect("put");
        let loaded = store.get_evm_logs_by_height(5).expect("get");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].data, vec![0xab]);
    }

    #[test]
    fn memory_store_evm_logs_range() {
        let store = MemoryStore::shared();
        store.put_evm_logs(1, &[EvmLog { address: EvmAddress([1; 20]), topics: vec![], data: vec![1] }]).expect("put");
        store.put_evm_logs(3, &[EvmLog { address: EvmAddress([2; 20]), topics: vec![], data: vec![3] }]).expect("put");
        let range = store.get_evm_logs_range(1, 3).expect("range");
        assert_eq!(range.len(), 2);
        assert_eq!(range[0].0, 1);
        assert_eq!(range[1].0, 3);
    }
}
