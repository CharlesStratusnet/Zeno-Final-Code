//! Deterministic mempool with per-sender replacement rules.

use std::collections::{BTreeSet, HashMap};

use anyhow::Result;
use parking_lot::RwLock;
use thiserror::Error;
use zeno_types::{Address, Transaction};

/// Maximum number of transactions in the mempool.
pub const MAX_MEMPOOL_SIZE: usize = 10_000;
/// Maximum transactions per sender.
pub const MAX_PER_SENDER: usize = 64;

/// Mempool errors.
#[derive(Debug, Error)]
pub enum MempoolError {
    /// Transaction already present.
    #[error("duplicate transaction")]
    Duplicate,
    /// Replacement fee not high enough.
    #[error("replacement fee too low")]
    ReplacementFeeTooLow,
    /// Pool is at capacity and the new transaction's fee is too low.
    #[error("mempool full")]
    Full,
    /// Sender has too many pending transactions.
    #[error("sender limit exceeded")]
    SenderLimitExceeded,
    /// Transaction nonce creates a gap.
    #[error("nonce gap: expected <= {expected}, got {actual}")]
    NonceGap {
        /// Maximum expected nonce.
        expected: u64,
        /// Actual nonce received.
        actual: u64,
    },
}

#[derive(Default)]
struct Inner {
    by_hash: HashMap<zeno_hash::Hash32, Transaction>,
    by_sender_nonce: HashMap<(Address, u64), zeno_hash::Hash32>,
    order: BTreeSet<(u128, zeno_hash::Hash32)>,
    by_sender_count: HashMap<Address, usize>,
    /// Tracks the highest nonce seen per sender to detect gaps.
    highest_nonce: HashMap<Address, u64>,
}

/// Shared mempool.
#[derive(Default)]
pub struct Mempool {
    inner: RwLock<Inner>,
}

impl Mempool {
    /// Creates a new mempool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a transaction with same-sender replacement-by-fee semantics.
    pub fn insert(&self, tx: Transaction) -> Result<(), MempoolError> {
        let hash = tx.id();
        let key = (tx.body.sender, tx.body.nonce);
        let mut guard = self.inner.write();
        if guard.by_hash.contains_key(&hash) {
            return Err(MempoolError::Duplicate);
        }

        let is_replacement = guard.by_sender_nonce.contains_key(&key);

        if let Some(existing_hash) = guard.by_sender_nonce.get(&key).copied() {
            let existing_fee = guard
                .by_hash
                .get(&existing_hash)
                .expect("indexed tx must exist")
                .body
                .fee;
            if tx.body.fee <= existing_fee {
                return Err(MempoolError::ReplacementFeeTooLow);
            }
            guard.order.remove(&(existing_fee, existing_hash));
            guard.by_hash.remove(&existing_hash);
        }

        // Per-sender limit check (only for non-replacements).
        if !is_replacement {
            let sender_count = guard.by_sender_count.get(&tx.body.sender).copied().unwrap_or(0);
            if sender_count >= MAX_PER_SENDER {
                return Err(MempoolError::SenderLimitExceeded);
            }
            // Nonce gap detection — reject nonces that skip too far ahead.
            let highest = guard.highest_nonce.get(&tx.body.sender).copied().unwrap_or(0);
            if tx.body.nonce > highest.saturating_add(MAX_PER_SENDER as u64) {
                return Err(MempoolError::NonceGap {
                    expected: highest.saturating_add(MAX_PER_SENDER as u64),
                    actual: tx.body.nonce,
                });
            }
        }

        // Pool capacity check (only for non-replacements since replacements don't grow the pool).
        if !is_replacement && guard.by_hash.len() >= MAX_MEMPOOL_SIZE {
            // Only accept if fee > lowest fee in pool. Evict the lowest.
            if let Some(&(lowest_fee, lowest_hash)) = guard.order.iter().next() {
                if tx.body.fee <= lowest_fee {
                    return Err(MempoolError::Full);
                }
                // Evict the lowest-fee transaction.
                if let Some(evicted) = guard.by_hash.remove(&lowest_hash) {
                    guard
                        .by_sender_nonce
                        .remove(&(evicted.body.sender, evicted.body.nonce));
                    guard.order.remove(&(lowest_fee, lowest_hash));
                    let count = guard
                        .by_sender_count
                        .get_mut(&evicted.body.sender)
                        .expect("sender count must exist for evicted tx");
                    *count = count.saturating_sub(1);
                }
            } else {
                return Err(MempoolError::Full);
            }
        }

        guard.order.insert((tx.body.fee, hash));
        guard.by_sender_nonce.insert(key, hash);
        if !is_replacement {
            *guard.by_sender_count.entry(tx.body.sender).or_insert(0) += 1;
        }
        let highest = guard.highest_nonce.entry(tx.body.sender).or_insert(0);
        if tx.body.nonce > *highest {
            *highest = tx.body.nonce;
        }
        guard.by_hash.insert(hash, tx);
        Ok(())
    }

    /// Returns up to `limit` highest-fee transactions.
    pub fn select_for_block(&self, limit: usize) -> Vec<Transaction> {
        self.inner
            .read()
            .order
            .iter()
            .rev()
            .take(limit)
            .filter_map(|(_, hash)| self.inner.read().by_hash.get(hash).cloned())
            .collect()
    }

    /// Removes committed transactions.
    pub fn remove_committed(&self, transactions: &[Transaction]) {
        let mut guard = self.inner.write();
        for tx in transactions {
            let hash = tx.id();
            if guard.by_hash.remove(&hash).is_some() {
                guard
                    .by_sender_nonce
                    .remove(&(tx.body.sender, tx.body.nonce));
                guard.order.remove(&(tx.body.fee, hash));
                if let Some(count) = guard.by_sender_count.get_mut(&tx.body.sender) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        guard.by_sender_count.remove(&tx.body.sender);
                    }
                }
            }
        }
    }

    /// Returns whether the mempool contains a hash.
    pub fn contains(&self, hash: &zeno_hash::Hash32) -> bool {
        self.inner.read().by_hash.contains_key(hash)
    }

    /// Returns the current size.
    pub fn len(&self) -> usize {
        self.inner.read().by_hash.len()
    }

    /// Returns whether the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use zeno_crypto::default_scheme;
    use zeno_primitives::sign_transaction;
    use zeno_types::{ChainId, TransactionBody};

    use super::{Mempool, MempoolError};

    #[test]
    fn higher_fee_replaces_same_nonce() {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let sender = zeno_types::Address(scheme.derive_address(&pk).expect("address"));
        let pool = Mempool::new();
        let low = sign_transaction(
            &*scheme,
            TransactionBody {
                chain_id: ChainId("devnet".to_string()),
                sender,
                recipient: zeno_types::Address([1; 32]),
                amount: 10,
                nonce: 0,
                fee: 1,
                evm: None,
                memo: None,
                valid_until: None,
            },
            pk.clone(),
            &sk,
        )
        .expect("sign");
        let high = sign_transaction(
            &*scheme,
            TransactionBody {
                chain_id: ChainId("devnet".to_string()),
                sender,
                recipient: zeno_types::Address([1; 32]),
                amount: 10,
                nonce: 0,
                fee: 2,
                evm: None,
                memo: None,
                valid_until: None,
            },
            pk,
            &sk,
        )
        .expect("sign");
        pool.insert(low).expect("insert low");
        pool.insert(high).expect("replace");
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn equal_fee_replacement_rejected() {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let sender = zeno_types::Address(scheme.derive_address(&pk).expect("address"));
        let pool = Mempool::new();
        let first = sign_transaction(
            &*scheme,
            TransactionBody {
                chain_id: ChainId("devnet".to_string()),
                sender,
                recipient: zeno_types::Address([1; 32]),
                amount: 10,
                nonce: 0,
                fee: 1,
                evm: None,
                memo: None,
                valid_until: None,
            },
            pk.clone(),
            &sk,
        )
        .expect("sign");
        let second = sign_transaction(
            &*scheme,
            TransactionBody {
                chain_id: ChainId("devnet".to_string()),
                sender,
                recipient: zeno_types::Address([1; 32]),
                amount: 10,
                nonce: 0,
                fee: 1,
                evm: None,
                memo: None,
                valid_until: None,
            },
            pk,
            &sk,
        )
        .expect("sign");
        pool.insert(first).expect("insert");
        let err = pool.insert(second).expect_err("must reject");
        assert!(matches!(err, MempoolError::ReplacementFeeTooLow));
    }
}
