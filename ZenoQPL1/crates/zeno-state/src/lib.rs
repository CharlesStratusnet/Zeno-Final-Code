//! State access and commitment utilities.

use std::{collections::BTreeMap, sync::OnceLock};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeno_hash::{hash_bytes, merkle_root, sha3_hash, Hash32};
use zeno_storage::SharedStore;
use zeno_types::{
    Account, Address, Delegation, EconomicsParams, EpochTransition, Evidence, GovernanceProposal,
    GovernanceState, ParameterUpdate, SlashingEvent, StakingState, UnbondingDelegation, Validator,
    ValidatorStake, ValidatorStatus,
};

/// Errors raised while accessing state.
#[derive(Debug, Error)]
pub enum StateError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("state error: {0}")]
    State(String),
}

/// Snapshot of all account state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateSnapshot {
    /// Accounts keyed by address.
    pub accounts: BTreeMap<Address, Account>,
}

/// Staking state snapshot with deterministic economics helpers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StakingSnapshot {
    /// Backing staking state.
    pub state: StakingState,
}

/// Governance state snapshot and deterministic proposal activation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceSnapshot {
    /// Backing governance state.
    pub state: GovernanceState,
}

impl GovernanceSnapshot {
    /// Loads governance state or initializes it from active economics.
    pub fn load(store: &SharedStore, default_economics: &EconomicsParams) -> Result<Self, StateError> {
        let state = store
            .get_governance_state()
            .map_err(|err| StateError::Storage(err.to_string()))?
            .unwrap_or_else(|| GovernanceState::new(default_economics.clone()));
        Ok(Self { state })
    }

    /// Persists governance state.
    pub fn persist(&self, store: &SharedStore) -> Result<(), StateError> {
        store.put_governance_state(&self.state)
            .map_err(|err| StateError::Storage(err.to_string()))
    }

    /// Queues a deterministic parameter update for a future epoch boundary.
    pub fn queue_parameter_update(
        &mut self,
        activation_epoch: u64,
        update: ParameterUpdate,
        description: impl Into<String>,
    ) -> u64 {
        let proposal_id = self.state.next_proposal_id;
        self.state.next_proposal_id += 1;
        self.state.pending.push(GovernanceProposal {
            proposal_id,
            activation_epoch,
            update,
            description: description.into(),
        });
        proposal_id
    }

    /// Activates all proposals scheduled for the current epoch.
    pub fn activate_ready_updates(&mut self, epoch: u64) -> Vec<GovernanceProposal> {
        let mut applied = Vec::new();
        self.state.pending.retain(|proposal| {
            if proposal.activation_epoch > epoch {
                return true;
            }
            match &proposal.update {
                ParameterUpdate::Economics(economics) => {
                    self.state.economics = economics.clone();
                }
            }
            applied.push(proposal.clone());
            false
        });
        applied
    }
}

impl StakingSnapshot {
    /// Loads staking state from storage or initializes an empty snapshot.
    pub fn load(store: &SharedStore) -> Result<Self, StateError> {
        let state = store
            .get_staking_state()
            .map_err(|err| StateError::Storage(err.to_string()))?
            .unwrap_or_default();
        Ok(Self { state })
    }

    /// Persists staking state to storage.
    pub fn persist(&self, store: &SharedStore) -> Result<(), StateError> {
        store.put_staking_state(&self.state)
            .map_err(|err| StateError::Storage(err.to_string()))
    }

    /// Seeds validators from genesis descriptors if not already present.
    pub fn ensure_validators(&mut self, validators: &[Validator]) {
        for validator in validators {
            self.state
                .validators
                .entry(validator.address)
                .or_insert_with(|| ValidatorStake {
                    validator_address: validator.address,
                    self_bond: 0,
                    total_stake: 0,
                    commission_bps: 0,
                    status: ValidatorStatus::Active,
                    last_liveness_epoch: self.state.epoch,
                });
        }
    }

    /// Adds or increases a delegation and updates aggregate validator stake.
    pub fn delegate(
        &mut self,
        delegator: Address,
        validator_address: Address,
        amount: u128,
        is_self_bond: bool,
    ) -> Result<(), StateError> {
        let validator = self
            .state
            .validators
            .get_mut(&validator_address)
            .ok_or_else(|| StateError::State("unknown validator".to_string()))?;
        let key = (delegator, validator_address);
        let delegation = self.state.delegations.entry(key).or_insert(Delegation {
            delegator,
            validator_address,
            amount: 0,
        });
        delegation.amount = delegation.amount.saturating_add(amount);
        validator.total_stake = validator.total_stake.saturating_add(amount);
        if is_self_bond {
            validator.self_bond = validator.self_bond.saturating_add(amount);
        }
        Ok(())
    }

    /// Starts unbonding for a delegation. Funds are released after the configured delay.
    pub fn begin_unbonding(
        &mut self,
        delegator: Address,
        validator_address: Address,
        amount: u128,
        params: &EconomicsParams,
    ) -> Result<(), StateError> {
        let key = (delegator, validator_address);
        let delegation = self
            .state
            .delegations
            .get_mut(&key)
            .ok_or_else(|| StateError::State("delegation not found".to_string()))?;
        if delegation.amount < amount {
            return Err(StateError::State("insufficient delegated amount".to_string()));
        }
        delegation.amount -= amount;
        let validator = self
            .state
            .validators
            .get_mut(&validator_address)
            .ok_or_else(|| StateError::State("unknown validator".to_string()))?;
        validator.total_stake -= amount;
        if delegator == validator_address {
            validator.self_bond = validator.self_bond.saturating_sub(amount);
        }
        self.state.unbonding.push(UnbondingDelegation {
            delegator,
            validator_address,
            amount,
            release_epoch: self.state.epoch.saturating_add(params.unbonding_epochs),
        });
        Ok(())
    }

    /// Applies a slash to validator stake and records the event.
    pub fn slash(
        &mut self,
        validator_address: Address,
        slash_bps: u16,
        reason: impl Into<String>,
        jail: bool,
    ) -> Result<(), StateError> {
        let validator = self
            .state
            .validators
            .get_mut(&validator_address)
            .ok_or_else(|| StateError::State("unknown validator".to_string()))?;
        let slash_amount = validator
            .total_stake
            .saturating_mul(slash_bps as u128)
            / 10_000u128;
        validator.total_stake = validator.total_stake.saturating_sub(slash_amount);
        validator.self_bond = validator.self_bond.min(validator.total_stake);
        if jail {
            validator.status = ValidatorStatus::Jailed;
        }
        self.state.slashing_events.push(SlashingEvent {
            validator_address,
            epoch: self.state.epoch,
            slash_bps,
            reason: reason.into(),
        });
        Ok(())
    }

    /// Settles one epoch of rewards and treasury funding deterministically.
    pub fn settle_epoch_rewards(
        &mut self,
        total_fees: u128,
        reward_budget: u128,
        params: &EconomicsParams,
    ) -> BTreeMap<Address, u128> {
        let mut rewards = BTreeMap::new();
        let total_active_stake: u128 = self
            .state
            .validators
            .values()
            .filter(|validator| validator.status == ValidatorStatus::Active)
            .map(|validator| validator.total_stake)
            .sum();
        if total_active_stake == 0 {
            self.state.treasury_balance = self
                .state
                .treasury_balance
                .saturating_add(total_fees)
                .saturating_add(reward_budget);
            self.state.epoch = self.state.epoch.saturating_add(1);
            return rewards;
        }

        let distributable = total_fees.saturating_add(reward_budget);
        let treasury_cut = distributable.saturating_mul(params.treasury_bps as u128) / 10_000u128;
        self.state.treasury_balance = self.state.treasury_balance.saturating_add(treasury_cut);
        let validator_pool = distributable.saturating_sub(treasury_cut);

        for (address, validator) in &self.state.validators {
            if validator.status != ValidatorStatus::Active || validator.total_stake == 0 {
                continue;
            }
            let gross_reward = validator_pool.saturating_mul(validator.total_stake) / total_active_stake;
            let commission = gross_reward.saturating_mul(validator.commission_bps as u128) / 10_000u128;
            rewards.insert(*address, gross_reward);
            self.state.treasury_balance = self.state.treasury_balance.saturating_add(commission);
        }

        self.state.epoch = self.state.epoch.saturating_add(1);
        self.state
            .unbonding
            .retain(|entry| entry.release_epoch > self.state.epoch);
        rewards
    }

    /// Derives the active validator set for the next deterministic boundary.
    pub fn effective_validator_set(&self, params: &EconomicsParams) -> Vec<Address> {
        let mut validators = self
            .state
            .validators
            .values()
            .filter(|validator| {
                validator.status == ValidatorStatus::Active
                    && validator.self_bond >= params.minimum_self_bond
            })
            .cloned()
            .collect::<Vec<_>>();
        validators.sort_by(|left, right| {
            right
                .total_stake
                .cmp(&left.total_stake)
                .then_with(|| left.validator_address.cmp(&right.validator_address))
        });
        validators
            .into_iter()
            .map(|validator| validator.validator_address)
            .collect()
    }

    /// Applies slash-and-jail handling for consensus safety evidence.
    pub fn apply_evidence(
        &mut self,
        evidence: &[Evidence],
        params: &EconomicsParams,
    ) -> Result<(), StateError> {
        let mut slashed = BTreeMap::<Address, ()>::new();
        for item in evidence {
            if slashed.contains_key(&item.validator_address) {
                continue;
            }
            let is_equivocation = item.reason.contains("duplicate vote")
                || item.reason.contains("conflicting proposal");
            if is_equivocation {
                self.slash(
                    item.validator_address,
                    params.double_sign_slash_bps,
                    item.reason.clone(),
                    true,
                )?;
                slashed.insert(item.validator_address, ());
            }
        }
        Ok(())
    }

    /// Marks a validator as live in the current epoch.
    pub fn note_liveness(&mut self, validator_address: Address) -> Result<(), StateError> {
        let validator = self
            .state
            .validators
            .get_mut(&validator_address)
            .ok_or_else(|| StateError::State("unknown validator".to_string()))?;
        validator.last_liveness_epoch = self.state.epoch;
        Ok(())
    }

    /// Applies downtime slashing to validators that missed the current epoch.
    pub fn apply_downtime_slashing(&mut self, params: &EconomicsParams) -> Result<(), StateError> {
        let target_epoch = self.state.epoch.saturating_add(1);
        let stale = self
            .state
            .validators
            .values()
            .filter(|validator| {
                validator.status == ValidatorStatus::Active
                    && validator.last_liveness_epoch.saturating_add(1) < target_epoch
            })
            .map(|validator| validator.validator_address)
            .collect::<Vec<_>>();
        for address in stale {
            self.slash(address, params.downtime_slash_bps, "downtime", true)?;
        }
        Ok(())
    }

    /// Returns whether a validator is currently active under economics rules.
    pub fn is_validator_active(&self, validator_address: Address, params: &EconomicsParams) -> bool {
        self.state
            .validators
            .get(&validator_address)
            .is_some_and(|validator| {
                validator.status == ValidatorStatus::Active
                    && validator.self_bond >= params.minimum_self_bond
            })
    }

    /// Builds a finalized epoch transition object from current state.
    pub fn build_epoch_transition(
        &self,
        height: u64,
        economics: &EconomicsParams,
    ) -> EpochTransition {
        let validator_set = self.effective_validator_set(economics);
        EpochTransition {
            epoch: self.state.epoch,
            height,
            validator_set_root: validator_set_root(&validator_set),
            validator_set,
            economics: economics.clone(),
        }
    }
}

fn validator_set_root(validators: &[Address]) -> Hash32 {
    let leaves = validators
        .iter()
        .map(|address| {
            hash_bytes(
                zeno_codec::encode(&("zeno.validator_set.v1", address))
                    .expect("validator set leaf encoding must succeed"),
            )
        })
        .collect::<Vec<_>>();
    merkle_root(&leaves)
}

/// Sparse Merkle inclusion or non-inclusion proof for an account key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountProof {
    /// Proved address key.
    pub address: Address,
    /// Account value if present.
    pub account: Option<Account>,
    /// Sibling hashes from leaf to root.
    pub siblings: Vec<Hash32>,
}

impl StateSnapshot {
    /// Loads the full account map from storage.
    pub fn load(store: &SharedStore) -> Result<Self, StateError> {
        let accounts = store.accounts().map_err(|err| StateError::Storage(err.to_string()))?;
        Ok(Self { accounts })
    }

    /// Reads an account, defaulting to zeroed state.
    pub fn account(&self, address: &Address) -> Account {
        self.accounts.get(address).cloned().unwrap_or_default()
    }

    /// Writes an account.
    pub fn put_account(&mut self, address: Address, account: Account) {
        self.accounts.insert(address, account);
    }

    /// Commits the snapshot to storage.
    pub fn persist(&self, store: &SharedStore) -> Result<(), StateError> {
        for (address, account) in &self.accounts {
            store
                .put_account(address, account)
                .map_err(|err| StateError::Storage(err.to_string()))?;
        }
        Ok(())
    }

    /// Returns the deterministic state root.
    pub fn state_root(&self) -> Hash32 {
        SparseMerkleState::from_accounts(&self.accounts).root()
    }

    /// Returns a proof-capable sparse Merkle proof for an account key.
    pub fn account_proof(&self, address: Address) -> AccountProof {
        SparseMerkleState::from_accounts(&self.accounts).prove(address)
    }
}

/// Sparse Merkle state commitment for account data.
#[derive(Debug, Clone, Default)]
pub struct SparseMerkleState {
    accounts: BTreeMap<Address, Account>,
}

impl SparseMerkleState {
    /// Builds the sparse tree view from account state.
    pub fn from_accounts(accounts: &BTreeMap<Address, Account>) -> Self {
        Self {
            accounts: accounts.clone(),
        }
    }

    /// Returns the current sparse Merkle root.
    pub fn root(&self) -> Hash32 {
        let entries: Vec<([u8; 32], Hash32)> = self
            .accounts
            .iter()
            .map(|(address, account)| (path_key(*address), leaf_hash(*address, account)))
            .collect();
        subtree_root(&entries, 0)
    }

    /// Builds an inclusion or non-inclusion proof for one address.
    pub fn prove(&self, address: Address) -> AccountProof {
        let entries: Vec<([u8; 32], Hash32)> = self
            .accounts
            .iter()
            .map(|(entry_address, account)| (path_key(*entry_address), leaf_hash(*entry_address, account)))
            .collect();
        let mut siblings = Vec::with_capacity(SPARSE_DEPTH);
        collect_proof(&entries, path_key(address), 0, &mut siblings);
        AccountProof {
            address,
            account: self.accounts.get(&address).cloned(),
            siblings,
        }
    }
}

impl AccountProof {
    /// Verifies this proof against a sparse Merkle root.
    pub fn verify(&self, expected_root: Hash32) -> bool {
        let mut current = match &self.account {
            Some(account) => leaf_hash(self.address, account),
            None => empty_hashes()[SPARSE_DEPTH],
        };
        let path = path_key(self.address);
        for (depth, sibling) in self.siblings.iter().rev().enumerate() {
            current = if bit_at(&path, SPARSE_DEPTH - 1 - depth) {
                node_hash(*sibling, current)
            } else {
                node_hash(current, *sibling)
            };
        }
        current == expected_root
    }
}

fn leaf_hash(address: Address, account: &Account) -> Hash32 {
    hash_bytes(
        zeno_codec::encode(&("zeno.smt.leaf.v1", address, account))
            .expect("state leaf encoding must succeed"),
    )
}

fn node_hash(left: Hash32, right: Hash32) -> Hash32 {
    let mut bytes = Vec::with_capacity(16 + 64);
    bytes.extend_from_slice(b"zeno.smt.node.v1");
    bytes.extend_from_slice(left.as_bytes());
    bytes.extend_from_slice(right.as_bytes());
    hash_bytes(bytes)
}

fn empty_hashes() -> [Hash32; SPARSE_DEPTH + 1] {
    static EMPTY_HASHES: OnceLock<[Hash32; SPARSE_DEPTH + 1]> = OnceLock::new();
    *EMPTY_HASHES.get_or_init(|| {
        let mut hashes = [Hash32::zero(); SPARSE_DEPTH + 1];
        hashes[SPARSE_DEPTH] = hash_bytes(b"zeno.smt.empty.leaf.v1");
        for depth in (0..SPARSE_DEPTH).rev() {
            hashes[depth] = node_hash(hashes[depth + 1], hashes[depth + 1]);
        }
        hashes
    })
}

fn subtree_root(entries: &[([u8; 32], Hash32)], depth: usize) -> Hash32 {
    if entries.is_empty() {
        return empty_hashes()[depth];
    }
    if depth == SPARSE_DEPTH {
        return entries[0].1;
    }
    let mut left = Vec::new();
    let mut right = Vec::new();
    for (key, value) in entries {
        if bit_at(key, depth) {
            right.push((*key, *value));
        } else {
            left.push((*key, *value));
        }
    }
    node_hash(subtree_root(&left, depth + 1), subtree_root(&right, depth + 1))
}

fn collect_proof(
    entries: &[([u8; 32], Hash32)],
    target_key: [u8; 32],
    depth: usize,
    siblings: &mut Vec<Hash32>,
) {
    if depth == SPARSE_DEPTH {
        return;
    }
    let mut left = Vec::new();
    let mut right = Vec::new();
    for (key, value) in entries {
        if bit_at(key, depth) {
            right.push((*key, *value));
        } else {
            left.push((*key, *value));
        }
    }
    if bit_at(&target_key, depth) {
        siblings.push(subtree_root(&left, depth + 1));
        collect_proof(&right, target_key, depth + 1, siblings);
    } else {
        siblings.push(subtree_root(&right, depth + 1));
        collect_proof(&left, target_key, depth + 1, siblings);
    }
}

fn bit_at(key: &[u8; 32], depth: usize) -> bool {
    let byte = depth / 8;
    let bit = 7 - (depth % 8);
    ((key[byte] >> bit) & 1) == 1
}

fn path_key(address: Address) -> [u8; 32] {
    sha3_hash(address.0).0
}

#[cfg(test)]
mod tests {
    use super::{GovernanceSnapshot, StakingSnapshot, StateSnapshot};
    use zeno_storage::MemoryStore;
    use zeno_types::{
        Account, Address, EconomicsParams, Evidence, ParameterUpdate, Validator, ValidatorStatus,
    };
    use zeno_hash::Hash32;

    #[test]
    fn inclusion_proof_verifies() {
        let mut snapshot = StateSnapshot::default();
        snapshot.put_account(
            Address([1; 32]),
            Account {
                nonce: 7,
                balance: 99,
            },
        );
        snapshot.put_account(
            Address([2; 32]),
            Account {
                nonce: 3,
                balance: 5,
            },
        );
        let root = snapshot.state_root();
        let proof = snapshot.account_proof(Address([1; 32]));
        assert!(proof.verify(root));
    }

    #[test]
    fn non_inclusion_proof_verifies() {
        let mut snapshot = StateSnapshot::default();
        snapshot.put_account(
            Address([2; 32]),
            Account {
                nonce: 3,
                balance: 5,
            },
        );
        let root = snapshot.state_root();
        let proof = snapshot.account_proof(Address([9; 32]));
        assert!(proof.verify(root));
    }

    #[test]
    fn staking_rewards_and_validator_set_are_deterministic() {
        let validator_a = Validator {
            validator_id: "a".to_string(),
            voting_power: 1,
            p2p_address: "p2p-a".to_string(),
            rpc_address: "rpc-a".to_string(),
            public_key: vec![1],
            address: Address([1; 32]),
        };
        let validator_b = Validator {
            validator_id: "b".to_string(),
            voting_power: 1,
            p2p_address: "p2p-b".to_string(),
            rpc_address: "rpc-b".to_string(),
            public_key: vec![2],
            address: Address([2; 32]),
        };
        let params = EconomicsParams {
            minimum_self_bond: 100,
            epoch_length: 10,
            unbonding_epochs: 2,
            treasury_bps: 1_000,
            downtime_slash_bps: 100,
            double_sign_slash_bps: 500,
        };
        let mut staking = StakingSnapshot::default();
        staking.ensure_validators(&[validator_a.clone(), validator_b.clone()]);
        staking
            .delegate(validator_a.address, validator_a.address, 200, true)
            .expect("self bond");
        staking
            .delegate(Address([9; 32]), validator_a.address, 300, false)
            .expect("delegation");
        staking
            .delegate(validator_b.address, validator_b.address, 100, true)
            .expect("self bond");
        let rewards = staking.settle_epoch_rewards(1_000, 0, &params);
        assert!(rewards.get(&validator_a.address).copied().unwrap_or_default() > rewards.get(&validator_b.address).copied().unwrap_or_default());
        assert_eq!(
            staking.effective_validator_set(&params),
            vec![validator_a.address, validator_b.address]
        );
        staking
            .slash(validator_b.address, params.double_sign_slash_bps, "double sign", true)
            .expect("slash");
        assert_eq!(
            staking.state.validators.get(&validator_b.address).expect("validator").status,
            ValidatorStatus::Jailed
        );
    }

    #[test]
    fn evidence_applies_double_sign_slash_and_jail() {
        let validator = Validator {
            validator_id: "a".to_string(),
            voting_power: 1,
            p2p_address: "p2p-a".to_string(),
            rpc_address: "rpc-a".to_string(),
            public_key: vec![1],
            address: Address([1; 32]),
        };
        let params = EconomicsParams {
            minimum_self_bond: 100,
            epoch_length: 10,
            unbonding_epochs: 2,
            treasury_bps: 1_000,
            downtime_slash_bps: 100,
            double_sign_slash_bps: 500,
        };
        let mut staking = StakingSnapshot::default();
        staking.ensure_validators(&[validator.clone()]);
        staking
            .delegate(validator.address, validator.address, 1_000, true)
            .expect("self bond");
        staking
            .apply_evidence(
                &[Evidence {
                    validator_address: validator.address,
                    height: 7,
                    round: 2,
                    reason: "duplicate vote".to_string(),
                }],
                &params,
            )
            .expect("apply evidence");
        let validator_state = staking.state.validators.get(&validator.address).expect("validator");
        assert_eq!(validator_state.status, ValidatorStatus::Jailed);
        assert!(validator_state.total_stake < 1_000);
    }

    #[test]
    fn governance_updates_activate_at_epoch_boundary() {
        let store = MemoryStore::shared();
        let initial = EconomicsParams {
            minimum_self_bond: 100,
            epoch_length: 10,
            unbonding_epochs: 2,
            treasury_bps: 1_000,
            downtime_slash_bps: 100,
            double_sign_slash_bps: 500,
        };
        let mut governance = GovernanceSnapshot::load(&store, &initial).expect("load governance");
        let updated = EconomicsParams {
            treasury_bps: 2_000,
            ..initial.clone()
        };
        governance.queue_parameter_update(
            3,
            ParameterUpdate::Economics(updated.clone()),
            "raise treasury share",
        );
        let applied_before = governance.activate_ready_updates(2);
        assert!(applied_before.is_empty());
        assert_eq!(governance.state.economics.treasury_bps, 1_000);
        let applied_after = governance.activate_ready_updates(3);
        assert_eq!(applied_after.len(), 1);
        assert_eq!(governance.state.economics, updated);
    }

    #[test]
    fn downtime_slash_applies_to_stale_validators() {
        let validator = Validator {
            validator_id: "a".to_string(),
            voting_power: 1,
            p2p_address: "p2p-a".to_string(),
            rpc_address: "rpc-a".to_string(),
            public_key: vec![1],
            address: Address([1; 32]),
        };
        let params = EconomicsParams {
            minimum_self_bond: 100,
            epoch_length: 10,
            unbonding_epochs: 2,
            treasury_bps: 1_000,
            downtime_slash_bps: 100,
            double_sign_slash_bps: 500,
        };
        let mut staking = StakingSnapshot::default();
        staking.ensure_validators(&[validator.clone()]);
        staking
            .delegate(validator.address, validator.address, 1_000, true)
            .expect("self bond");
        staking.state.epoch = 2;
        staking
            .apply_downtime_slashing(&params)
            .expect("downtime slash");
        let validator_state = staking.state.validators.get(&validator.address).expect("validator");
        assert_eq!(validator_state.status, ValidatorStatus::Jailed);
        assert!(validator_state.total_stake < 1_000);
    }

    #[test]
    fn epoch_transition_contains_validator_set_root() {
        let validator_a = Validator {
            validator_id: "a".to_string(),
            voting_power: 1,
            p2p_address: "p2p-a".to_string(),
            rpc_address: "rpc-a".to_string(),
            public_key: vec![1],
            address: Address([1; 32]),
        };
        let validator_b = Validator {
            validator_id: "b".to_string(),
            voting_power: 1,
            p2p_address: "p2p-b".to_string(),
            rpc_address: "rpc-b".to_string(),
            public_key: vec![2],
            address: Address([2; 32]),
        };
        let params = EconomicsParams {
            minimum_self_bond: 100,
            epoch_length: 10,
            unbonding_epochs: 2,
            treasury_bps: 1_000,
            downtime_slash_bps: 100,
            double_sign_slash_bps: 500,
        };
        let mut staking = StakingSnapshot::default();
        staking.ensure_validators(&[validator_a.clone(), validator_b.clone()]);
        staking
            .delegate(validator_a.address, validator_a.address, 200, true)
            .expect("self bond");
        staking
            .delegate(validator_b.address, validator_b.address, 150, true)
            .expect("self bond");
        let transition = staking.build_epoch_transition(10, &params);
        assert_eq!(transition.validator_set, vec![validator_a.address, validator_b.address]);
        assert_ne!(transition.validator_set_root, Hash32::zero());
    }
}
const SPARSE_DEPTH: usize = 64;
