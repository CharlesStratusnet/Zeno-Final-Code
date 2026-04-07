//! Deterministic block execution.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;
use zeno_crypto::SignatureScheme;
use zeno_evm::EvmExecutor;
use zeno_primitives::{receipt_root, transaction_root, verify_block, verify_transaction};
use zeno_state::{GovernanceSnapshot, StakingSnapshot, StateSnapshot};
use zeno_storage::SharedStore;
use zeno_types::{
    Address, Block, BlockHeader, ChainId, EconomicsParams, EpochTransition, ExecutionOutcome,
    FinalizedBlock, GasPricingState, Receipt, Transaction, TransactionError, Validator,
};

/// Errors raised by the execution engine.
#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("transaction invalid: {0}")]
    Transaction(String),
    #[error("block invalid: {0}")]
    Block(String),
    #[error("state error: {0}")]
    State(String),
}

/// Result of executing a block — not yet finalized (no certificate).
#[derive(Debug, Clone)]
pub struct BlockExecutionResult {
    /// The executed block.
    pub block: Block,
    /// Receipts from execution.
    pub receipts: Vec<Receipt>,
    /// Optional epoch transition.
    pub epoch_transition: Option<EpochTransition>,
    /// Collected proposer fees.
    pub proposer_fees: u128,
    /// State snapshot after execution, used for atomic commit.
    pub state: StateSnapshot,
}

#[derive(Debug, Clone)]
struct AccountingArtifacts {
    staking: Option<StakingSnapshot>,
    governance: Option<GovernanceSnapshot>,
    epoch_transition: Option<EpochTransition>,
}

#[derive(Debug, Clone)]
struct PreparedBlock {
    state: StateSnapshot,
    receipts: Vec<Receipt>,
    proposer_fees: u128,
    accounting: AccountingArtifacts,
}

/// Native transaction gas costs.
pub const NATIVE_TRANSFER_GAS: u64 = 21_000;
/// Gas per byte of transaction data.
pub const GAS_PER_BYTE: u64 = 16;
/// EIP-1559 base fee adjustment denominator.
pub const BASE_FEE_CHANGE_DENOMINATOR: u128 = 8;
/// Minimum base fee.
pub const MIN_BASE_FEE: u128 = 1;

/// Execution engine.
pub struct ExecutionEngine {
    chain_id: ChainId,
    evm_chain_id: Option<u64>,
    economics: Option<EconomicsParams>,
    validators: Vec<Validator>,
    target_gas_per_block: u64,
}

impl ExecutionEngine {
    /// Computes gas cost for a native (non-EVM) transaction.
    pub fn compute_native_gas(tx: &Transaction) -> u64 {
        let base = NATIVE_TRANSFER_GAS;
        let memo_gas = tx.body.memo.as_ref().map(|m| m.len() as u64 * GAS_PER_BYTE).unwrap_or(0);
        let sig_gas = (tx.signature.len() as u64 / 32) * 10;
        base + memo_gas + sig_gas
    }

    /// Updates EIP-1559 base fee based on gas usage.
    pub fn update_base_fee(current: &GasPricingState, target_gas: u64) -> GasPricingState {
        let base = if current.base_fee == 0 { MIN_BASE_FEE } else { current.base_fee };
        let new_base = if current.last_block_gas_used > target_gas {
            let excess = current.last_block_gas_used.saturating_sub(target_gas) as u128;
            let delta = base.saturating_mul(excess) / (target_gas as u128) / BASE_FEE_CHANGE_DENOMINATOR;
            base.saturating_add(delta.max(1))
        } else {
            let deficit = target_gas.saturating_sub(current.last_block_gas_used) as u128;
            let delta = base.saturating_mul(deficit) / (target_gas as u128) / BASE_FEE_CHANGE_DENOMINATOR;
            base.saturating_sub(delta).max(MIN_BASE_FEE)
        };
        GasPricingState {
            base_fee: new_base,
            last_block_gas_used: 0,
        }
    }

    /// Creates a new engine.
    pub fn new(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            evm_chain_id: None,
            economics: None,
            validators: Vec::new(),
            target_gas_per_block: 15_000_000,
        }
    }

    /// Creates a new engine with optional EVM support.
    pub fn with_evm(chain_id: ChainId, evm_chain_id: Option<u64>) -> Self {
        Self {
            chain_id,
            evm_chain_id,
            economics: None,
            validators: Vec::new(),
            target_gas_per_block: 15_000_000,
        }
    }

    /// Creates a new engine with protocol economics enabled.
    pub fn with_protocol(
        chain_id: ChainId,
        evm_chain_id: Option<u64>,
        economics: EconomicsParams,
        validators: Vec<Validator>,
    ) -> Self {
        Self {
            chain_id,
            evm_chain_id,
            economics: Some(economics),
            validators,
            target_gas_per_block: 15_000_000,
        }
    }

    /// Validates a transaction against the current state.
    pub fn validate_transaction(
        &self,
        scheme: &dyn SignatureScheme,
        state: &StateSnapshot,
        current_height: u64,
        tx: &Transaction,
    ) -> Result<(), TransactionError> {
        verify_transaction(scheme, &self.chain_id, tx, current_height)?;
        let sender = state.account(&tx.body.sender);
        if sender.nonce != tx.body.nonce {
            return Err(TransactionError::InvalidNonce {
                expected: sender.nonce,
                actual: tx.body.nonce,
            });
        }
        let total = tx.body.amount.saturating_add(tx.body.fee);
        if sender.balance < total {
            return Err(TransactionError::InsufficientBalance);
        }
        Ok(())
    }

    /// Applies a single transaction.
    pub fn apply_transaction(
        &self,
        scheme: &dyn SignatureScheme,
        store: &SharedStore,
        state: &mut StateSnapshot,
        height: u64,
        tx: &Transaction,
    ) -> Result<Receipt, ExecutionError> {
        self.validate_transaction(scheme, state, height, tx)
            .map_err(|err| ExecutionError::Transaction(err.to_string()))?;
        let mut sender = state.account(&tx.body.sender);
        let total_cost = tx.body.amount.checked_add(tx.body.fee)
            .ok_or_else(|| ExecutionError::Transaction("amount + fee overflow".to_string()))?;
        sender.balance = sender.balance.checked_sub(total_cost)
            .ok_or_else(|| ExecutionError::Transaction("insufficient balance (checked)".to_string()))?;
        sender.nonce = sender.nonce.checked_add(1)
            .ok_or_else(|| ExecutionError::Transaction("nonce overflow".to_string()))?;
        state.put_account(tx.body.sender, sender);
        let mut evm_result = None;
        if let Some(evm_tx) = &tx.body.evm {
            let Some(evm_chain_id) = self.evm_chain_id else {
                return Err(ExecutionError::Transaction("evm execution not enabled".to_string()));
            };
            let result = EvmExecutor::new(evm_chain_id)
                .execute(store, last20(tx.body.sender.0), evm_tx)
                .map_err(|err| ExecutionError::Transaction(err.to_string()))?;
            evm_result = Some(result);
        } else {
            let mut recipient = state.account(&tx.body.recipient);
            recipient.balance = recipient.balance.saturating_add(tx.body.amount);
            state.put_account(tx.body.recipient, recipient);
        }
        Ok(Receipt {
            tx_hash: tx.id(),
            height,
            fee_charged: tx.body.fee,
            outcome: ExecutionOutcome::Success,
            evm: evm_result,
        })
    }

    /// Executes a proposed block.
    pub fn execute_block(
        &self,
        scheme: &dyn SignatureScheme,
        store: &SharedStore,
        block: Block,
    ) -> Result<BlockExecutionResult, ExecutionError> {
        let prepared = self.prepare_block(scheme, store, &block)?;
        // Persist staking/governance side-effects.
        self.persist_accounting(store, &prepared)
            .map_err(|err| ExecutionError::State(err.to_string()))?;
        debug!(height = block.header.height, "executed block");
        Ok(BlockExecutionResult {
            block,
            receipts: prepared.receipts,
            epoch_transition: prepared.accounting.epoch_transition,
            proposer_fees: prepared.proposer_fees,
            state: prepared.state,
        })
    }

    /// Replays and commits an externally supplied finalized block after deterministic validation.
    pub fn validate_and_commit_finalized_block(
        &self,
        scheme: &dyn SignatureScheme,
        store: &SharedStore,
        finalized: &FinalizedBlock,
    ) -> Result<(), ExecutionError> {
        let prepared = self.prepare_block(scheme, store, &finalized.block)?;
        if prepared.receipts != finalized.receipts {
            return Err(ExecutionError::Block("receipt bundle mismatch".to_string()));
        }
        if prepared.accounting.epoch_transition != finalized.epoch_transition {
            return Err(ExecutionError::Block("epoch transition mismatch".to_string()));
        }
        // Verify roots BEFORE any persistence (prepare_block already checked them).
        // Commit block + accounts atomically first (critical path).
        self.commit_finalized_block(store, finalized, &prepared.state)
            .map_err(|err| ExecutionError::State(err.to_string()))?;
        // Then persist staking/governance (can be replayed from blocks if lost).
        self.persist_accounting(store, &prepared)
            .map_err(|err| ExecutionError::State(err.to_string()))?;
        Ok(())
    }

    /// Atomically commits a finalized block with all accounts and receipts.
    pub fn commit_finalized_block(
        &self,
        store: &SharedStore,
        finalized: &FinalizedBlock,
        state: &StateSnapshot,
    ) -> Result<()> {
        store.atomic_commit_block(finalized, &state.accounts)?;
        Ok(())
    }

    /// Builds a new candidate header.
    pub fn build_header(
        &self,
        store: &SharedStore,
        proposer: Address,
        height: u64,
        round: u32,
        timestamp_ms: u64,
        transactions: &[Transaction],
        state_after: &StateSnapshot,
        receipts: &[Receipt],
    ) -> Result<BlockHeader> {
        let parent_hash = store
            .latest_block()?
            .map(|entry| entry.block.hash())
            .unwrap_or_default();
        Ok(BlockHeader {
            height,
            round,
            chain_id: self.chain_id.clone(),
            parent_hash,
            tx_root: transaction_root(transactions),
            state_root: state_after.state_root(),
            receipt_root: receipt_root(receipts),
            proposer,
            timestamp_ms,
        })
    }

    /// Simulates transactions for proposal construction.
    pub fn dry_run_transactions(
        &self,
        scheme: &dyn SignatureScheme,
        store: &SharedStore,
        height: u64,
        transactions: &[Transaction],
        proposer: Address,
    ) -> Result<(StateSnapshot, Vec<Receipt>)> {
        let mut state = StateSnapshot::load(store).map_err(|err| anyhow!(err.to_string()))?;
        let mut receipts = Vec::with_capacity(transactions.len());
        let mut fees = 0u128;
        for tx in transactions {
            let receipt = self
                .apply_transaction(scheme, store, &mut state, height, tx)
                .map_err(|err| anyhow!(err.to_string()))?;
            fees += receipt.fee_charged;
            receipts.push(receipt);
        }
        let _ = self
            .apply_block_accounting(store, &mut state, proposer, fees, height)
            .map_err(|err| anyhow!(err.to_string()))?;
        Ok((state, receipts))
    }

    fn prepare_block(
        &self,
        scheme: &dyn SignatureScheme,
        store: &SharedStore,
        block: &Block,
    ) -> Result<PreparedBlock, ExecutionError> {
        verify_block(scheme, block).map_err(|err| ExecutionError::Block(err.to_string()))?;
        let expected_parent = store
            .latest_block()
            .map_err(|err| ExecutionError::State(err.to_string()))?
            .map(|entry| entry.block.hash())
            .unwrap_or_default();
        if block.header.parent_hash != expected_parent {
            return Err(ExecutionError::Block("parent hash mismatch".to_string()));
        }

        let mut state = StateSnapshot::load(store).map_err(|err| ExecutionError::State(err.to_string()))?;
        let mut receipts = Vec::with_capacity(block.transactions.len());
        let mut proposer_fees = 0u128;
        for tx in &block.transactions {
            let receipt = self.apply_transaction(scheme, store, &mut state, block.header.height, tx)?;
            proposer_fees += receipt.fee_charged;
            receipts.push(receipt);
        }

        let accounting = self
            .apply_block_accounting(store, &mut state, block.header.proposer, proposer_fees, block.header.height)
            .map_err(|err| ExecutionError::State(err.to_string()))?;

        let computed_tx_root = transaction_root(&block.transactions);
        let computed_receipt_root = receipt_root(&receipts);
        let computed_state_root = state.state_root();
        if block.header.tx_root != computed_tx_root {
            return Err(ExecutionError::Block("tx root mismatch".to_string()));
        }
        if block.header.receipt_root != computed_receipt_root {
            return Err(ExecutionError::Block("receipt root mismatch".to_string()));
        }
        if block.header.state_root != computed_state_root {
            return Err(ExecutionError::Block("state root mismatch".to_string()));
        }

        Ok(PreparedBlock {
            state,
            receipts,
            proposer_fees,
            accounting,
        })
    }

    fn persist_accounting(&self, store: &SharedStore, prepared: &PreparedBlock) -> Result<()> {
        prepared.state.persist(store)?;
        if let Some(staking) = &prepared.accounting.staking {
            staking.persist(store)?;
        }
        if let Some(governance) = &prepared.accounting.governance {
            governance.persist(store)?;
        }
        if let Some(epoch_transition) = &prepared.accounting.epoch_transition {
            store.put_epoch_transition(epoch_transition)?;
        }
        Ok(())
    }

    fn apply_block_accounting(
        &self,
        store: &SharedStore,
        state: &mut StateSnapshot,
        proposer: Address,
        total_fees: u128,
        height: u64,
    ) -> Result<AccountingArtifacts> {
        if let Some(economics) = &self.economics {
            let mut staking = StakingSnapshot::load(store)?;
            staking.ensure_validators(&self.validators);
            let mut governance = GovernanceSnapshot::load(store, economics)?;
            let treasury_cut = total_fees.saturating_mul(economics.treasury_bps as u128) / 10_000u128;
            let proposer_reward = total_fees.saturating_sub(treasury_cut);

            let mut proposer_account = state.account(&proposer);
            proposer_account.balance = proposer_account.balance.saturating_add(proposer_reward);
            state.put_account(proposer, proposer_account);

            let mut treasury_account = state.account(&treasury_address());
            treasury_account.balance = treasury_account.balance.saturating_add(treasury_cut);
            state.put_account(treasury_address(), treasury_account);
            staking.state.treasury_balance = staking.state.treasury_balance.saturating_add(treasury_cut);

            let mut epoch_transition = None;
            if economics.epoch_length != 0 && height % economics.epoch_length == 0 {
                staking
                    .apply_downtime_slashing(&governance.state.economics)
                    .map_err(|err| anyhow!(err.to_string()))?;
                let _ = staking.settle_epoch_rewards(0, 0, &governance.state.economics);
                let _ = governance.activate_ready_updates(staking.state.epoch);
                epoch_transition = Some(staking.build_epoch_transition(height, &governance.state.economics));
            }
            Ok(AccountingArtifacts {
                staking: Some(staking),
                governance: Some(governance),
                epoch_transition,
            })
        } else {
            let mut proposer_account = state.account(&proposer);
            proposer_account.balance += total_fees;
            state.put_account(proposer, proposer_account);
            Ok(AccountingArtifacts {
                staking: None,
                governance: None,
                epoch_transition: None,
            })
        }
    }
}

use zeno_hash::Hash32;

fn last20(bytes: [u8; 32]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes[12..32]);
    out
}

fn treasury_address() -> Address {
    Address([0u8; 32])
}

#[cfg(test)]
mod tests {
    use zeno_crypto::default_scheme;
    use zeno_primitives::{sign_block, sign_transaction};
    use zeno_storage::MemoryStore;
    use zeno_types::{BlockHeader, ChainId, TransactionBody};

    use super::{ExecutionEngine, Hash32};
    use zeno_types::FinalizedBlock;

    #[test]
    fn rejects_bad_nonce() {
        let store = MemoryStore::shared();
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let sender = zeno_types::Address(scheme.derive_address(&pk).expect("address"));
        store
            .put_account(&sender, &zeno_types::Account { nonce: 1, balance: 100 })
            .expect("account");
        let tx = sign_transaction(
            &*scheme,
            TransactionBody {
                chain_id: ChainId("devnet".to_string()),
                sender,
                recipient: zeno_types::Address([2; 32]),
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
        let engine = ExecutionEngine::new(ChainId("devnet".to_string()));
        let state = zeno_state::StateSnapshot::load(&store).expect("state");
        let err = engine
            .validate_transaction(&*scheme, &state, 0, &tx)
            .expect_err("must fail");
        assert!(matches!(err, zeno_types::TransactionError::InvalidNonce { .. }));
    }

    #[test]
    fn validates_and_commits_finalized_block_by_replay() {
        let source_store = MemoryStore::shared();
        let target_store = MemoryStore::shared();
        let scheme = default_scheme();
        let (proposer_pk, proposer_sk) = scheme.generate_keypair().expect("keypair");
        let proposer = zeno_types::Address(scheme.derive_address(&proposer_pk).expect("address"));
        let recipient = zeno_types::Address([9; 32]);
        source_store
            .put_account(&proposer, &zeno_types::Account { nonce: 0, balance: 100 })
            .expect("source proposer");
        target_store
            .put_account(&proposer, &zeno_types::Account { nonce: 0, balance: 100 })
            .expect("target proposer");

        let tx = sign_transaction(
            &*scheme,
            TransactionBody {
                chain_id: ChainId("devnet".to_string()),
                sender: proposer,
                recipient,
                amount: 10,
                nonce: 0,
                fee: 1,
                evm: None,
                memo: None,
                valid_until: None,
            },
            proposer_pk.clone(),
            &proposer_sk,
        )
        .expect("sign");

        let engine = ExecutionEngine::new(ChainId("devnet".to_string()));
        let (state_after, receipts) = engine
            .dry_run_transactions(&*scheme, &source_store, 1, &[tx.clone()], proposer)
            .expect("dry run");
        let header = engine
            .build_header(&source_store, proposer, 1, 0, 1, &[tx.clone()], &state_after, &receipts)
            .expect("header");
        let block = sign_block(
            &*scheme,
            BlockHeader { ..header },
            vec![tx],
            proposer_pk,
            &proposer_sk,
        )
        .expect("sign block");
        let executed = engine.execute_block(&*scheme, &source_store, block).expect("execute");
        let finalized = FinalizedBlock {
            block: executed.block,
            certificate: zeno_types::CommitCertificate {
                block_hash: Hash32::zero(),
                height: 1,
                round: 0,
                votes: Vec::new(),
            },
            receipts: executed.receipts,
            epoch_transition: executed.epoch_transition,
        };

        engine
            .validate_and_commit_finalized_block(&*scheme, &target_store, &finalized)
            .expect("replay commit");

        let latest = target_store.latest_block().expect("latest").expect("block");
        assert_eq!(latest.block.header.height, 1);
        assert_eq!(
            target_store
                .get_account(&recipient)
                .expect("recipient lookup")
                .expect("recipient"),
            zeno_types::Account { nonce: 0, balance: 10 }
        );
    }
}
