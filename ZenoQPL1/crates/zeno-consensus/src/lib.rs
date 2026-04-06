//! Deterministic validator consensus engine.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::time::{interval, MissedTickBehavior};
use tracing::{info, warn};
use zeno_crypto::{PublicKeyBytes, SecretKeyBytes, SignatureScheme};
use zeno_execution::ExecutionEngine;
use zeno_mempool::Mempool;
use zeno_network::NetworkHandle;
use zeno_primitives::{sender_from_public_key, sign_block, sign_vote, verify_block, verify_transaction, verify_vote};
use zeno_state::{StakingSnapshot, StateSnapshot};
use zeno_storage::SharedStore;
use zeno_types::{
    Address, Block, ChainId, CommitCertificate, ConsensusParams, ConsensusSnapshot,
    ConsensusWalEntry, EconomicsParams, Evidence, FinalizedBlock, Genesis, NetworkMessage,
    Proposal, Validator, Vote, VoteStep,
};

/// Validator signing material.
#[derive(Debug, Clone)]
pub struct LocalValidator {
    /// Validator descriptor.
    pub validator: Validator,
    /// Secret key bytes.
    pub secret_key: SecretKeyBytes,
}

/// Consensus engine.
pub struct ConsensusEngine {
    chain_id: ChainId,
    validators: Vec<Validator>,
    scheme: Arc<dyn SignatureScheme>,
    execution: ExecutionEngine,
    mempool: Arc<Mempool>,
    store: SharedStore,
    network: NetworkHandle,
    params: ConsensusParams,
    economics: EconomicsParams,
    local_validator: Option<LocalValidator>,
    state: Arc<RwLock<RoundState>>,
}

/// Sentinel hash representing a nil vote (no block).
pub const NIL_HASH: zeno_hash::Hash32 = zeno_hash::Hash32::zero();

/// Maximum round timeout (60 seconds).
const MAX_ROUND_TIMEOUT_MS: u64 = 60_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RoundState {
    height: u64,
    round: u32,
    proposal: Option<Block>,
    prevotes: BTreeMap<zeno_hash::Hash32, BTreeSet<Address>>,
    precommits: BTreeMap<zeno_hash::Hash32, BTreeSet<Address>>,
    votes: Vec<Vote>,
    evidence: Vec<Evidence>,
    /// Tracks which (validator, height, round) combos have already been recorded
    /// to prevent duplicate evidence slashing.
    processed_evidence: BTreeSet<(Address, u64, u32)>,
    prevoted: bool,
    precommitted: bool,
    /// Round at which this node locked on a block (Tendermint locking).
    locked_round: Option<u32>,
    /// Block locked on.
    locked_block: Option<Block>,
    /// Highest round at which a polka (2/3+ prevotes) was observed.
    valid_round: Option<u32>,
    /// Block that received the polka.
    valid_block: Option<Block>,
}

impl Default for RoundState {
    fn default() -> Self {
        Self {
            height: 1,
            round: 0,
            proposal: None,
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
            votes: Vec::new(),
            evidence: Vec::new(),
            processed_evidence: BTreeSet::new(),
            prevoted: false,
            precommitted: false,
            locked_round: None,
            locked_block: None,
            valid_round: None,
            valid_block: None,
        }
    }
}

impl ConsensusEngine {
    /// Creates a new consensus engine.
    pub fn new(
        genesis: &Genesis,
        scheme: Arc<dyn SignatureScheme>,
        execution: ExecutionEngine,
        mempool: Arc<Mempool>,
        store: SharedStore,
        network: NetworkHandle,
        local_validator: Option<LocalValidator>,
    ) -> Result<Self> {
        let recovered = recover_snapshot(
            store
            .get_consensus_snapshot()
            .context("load consensus snapshot")?
            .unwrap_or_else(|| {
                let height = store
                    .latest_block()
                    .ok()
                    .flatten()
                    .map(|block| block.block.header.height + 1)
                    .unwrap_or(1);
                ConsensusSnapshot { height, round: 0 }
            }),
            &store.load_consensus_wal().context("load consensus wal")?,
        );
        let state = RoundState {
            height: recovered.snapshot.height,
            round: recovered.snapshot.round,
            locked_round: recovered.locked_round,
            locked_block: recovered.locked_block,
            valid_round: recovered.valid_round,
            valid_block: recovered.valid_block,
            ..RoundState::default()
        };
        Ok(Self {
            chain_id: genesis.chain_id.clone(),
            validators: genesis.validators.clone(),
            scheme,
            execution,
            mempool,
            store,
            network,
            params: genesis.consensus.clone(),
            economics: genesis.economics.clone(),
            local_validator,
            state: Arc::new(RwLock::new(state)),
        })
    }

    fn quorum(&self) -> usize {
        let count = self.active_validators().len();
        (count * 2 / 3) + 1
    }

    /// Calculates the round timeout with exponential backoff.
    fn round_timeout(&self, round: u32) -> Duration {
        let base = self.params.proposal_timeout_ms + self.params.vote_timeout_ms;
        let shift = round.min(5) as u64;
        let backoff = base.saturating_mul(1u64.checked_shl(shift as u32).unwrap_or(32));
        Duration::from_millis(backoff.min(MAX_ROUND_TIMEOUT_MS))
    }

    fn proposer_for(&self, height: u64, round: u32) -> Validator {
        let validators = self.active_validators();
        let index = ((height as usize) + (round as usize)) % validators.len();
        validators[index].clone()
    }

    fn current_snapshot(&self) -> ConsensusSnapshot {
        let guard = self.state.read();
        ConsensusSnapshot {
            height: guard.height,
            round: guard.round,
        }
    }

    fn append_wal(&self, entry: ConsensusWalEntry) -> Result<()> {
        self.store.append_consensus_wal(&entry)?;
        Ok(())
    }

    fn persist_snapshot(&self) -> Result<()> {
        let snapshot = self.current_snapshot();
        self.store.put_consensus_snapshot(&snapshot)?;
        self.append_wal(ConsensusWalEntry::SnapshotPersisted {
            height: snapshot.height,
            round: snapshot.round,
        })
    }

    async fn maybe_propose(&self) -> Result<()> {
        let Some(local) = &self.local_validator else {
            return Ok(());
        };
        if !self.local_validator_active()? {
            return Ok(());
        }

        let snapshot = self.current_snapshot();
        let proposer = self.proposer_for(snapshot.height, snapshot.round);
        if proposer.address != local.validator.address {
            return Ok(());
        }

        if self.state.read().proposal.is_some() {
            return Ok(());
        }

        // Slashing protection: never sign a proposal at a height we've already signed.
        let mut protection = self.store
            .get_slashing_protection(&local.validator.address)?
            .unwrap_or_default();
        if snapshot.height <= protection.last_signed_proposal_height {
            warn!(height = snapshot.height, "slashing protection: skipping proposal at already-signed height");
            return Ok(());
        }
        protection.last_signed_proposal_height = snapshot.height;
        self.store.put_slashing_protection(&local.validator.address, &protection)?;

        // Evict expired transactions before selecting.
        self.mempool.evict_expired(snapshot.height);

        let transactions = self
            .mempool
            .select_for_block_prioritized(self.params.max_transactions_per_block, snapshot.height);
        let (state_after, receipts) = self.execution.dry_run_transactions(
            &*self.scheme,
            &self.store,
            snapshot.height,
            &transactions,
            proposer.address,
        )?;
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let header = self.execution.build_header(
            &self.store,
            proposer.address,
            snapshot.height,
            snapshot.round,
            timestamp_ms,
            &transactions,
            &state_after,
            &receipts,
        )?;
        let block = sign_block(
            &*self.scheme,
            header,
            transactions,
            PublicKeyBytes(local.validator.public_key.clone()),
            &local.secret_key,
        )?;
        // Block size limit enforcement.
        let block_bytes = zeno_codec::encode(&block).map_err(|e| anyhow!("encode block: {e}"))?;
        if block_bytes.len() > self.params.max_block_bytes {
            warn!(
                size = block_bytes.len(),
                max = self.params.max_block_bytes,
                "proposed block exceeds size limit, dropping transactions"
            );
            return Ok(());
        }
        self.note_validator_liveness(local.validator.address)?;
        self.append_wal(ConsensusWalEntry::ProposalAccepted {
            height: snapshot.height,
            round: snapshot.round,
            block_hash: block.hash(),
        })?;
        self.state.write().proposal = Some(block.clone());
        let proposal = Proposal {
            height: snapshot.height,
            round: snapshot.round,
            block,
            validator_address: proposer.address,
        };
        self.append_wal(ConsensusWalEntry::ProposalBroadcast {
            height: proposal.height,
            round: proposal.round,
            block_hash: proposal.block.hash(),
        })?;
        self.network
            .broadcast(NetworkMessage::Proposal(proposal.clone()))
            .await?;
        // After proposing, immediately prevote for our own proposal and
        // drive the vote chain. Without this, a single-validator network
        // would wait for the proposal to arrive over the network, which
        // never happens when there are no peers.
        if let Some(vote) = self.emit_prevote().await? {
            self.handle_vote_actions(vote).await?;
        }
        Ok(())
    }

    async fn on_proposal(&self, proposal: Proposal) -> Result<()> {
        self.validate_incoming_proposal(&proposal)?;
        {
            let mut guard = self.state.write();
            if proposal.height != guard.height || proposal.round != guard.round {
                return Ok(());
            }
            if let Some(existing) = &guard.proposal {
                if existing.hash() != proposal.block.hash() {
                    let key = (proposal.validator_address, proposal.height, proposal.round);
                    if !guard.processed_evidence.contains(&key) {
                        let evidence = Evidence {
                            validator_address: proposal.validator_address,
                            height: proposal.height,
                            round: proposal.round,
                            reason: "conflicting proposal".to_string(),
                        };
                        self.append_wal(ConsensusWalEntry::EvidenceRecorded {
                            height: evidence.height,
                            round: evidence.round,
                            validator_address: evidence.validator_address,
                            reason: evidence.reason.clone(),
                        })?;
                        guard.processed_evidence.insert(key);
                        guard.evidence.push(evidence);
                    }
                }
                return Ok(());
            }
            self.append_wal(ConsensusWalEntry::ProposalAccepted {
                height: proposal.height,
                round: proposal.round,
                block_hash: proposal.block.hash(),
            })?;
            guard.proposal = Some(proposal.block.clone());
        }
        if let Some(vote) = self.emit_prevote().await? {
            self.handle_vote_actions(vote).await?;
        }
        Ok(())
    }

    async fn emit_prevote(&self) -> Result<Option<Vote>> {
        let Some(local) = &self.local_validator else {
            return Ok(None);
        };
        if !self.local_validator_active()? {
            return Ok(None);
        }
        let (height, round, vote_hash, already) = {
            let guard = self.state.read();
            if guard.prevoted {
                return Ok(None);
            }
            let proposal_hash = guard.proposal.as_ref().map(|block| block.hash());
            // Tendermint locking rule:
            // 1. If locked and proposal matches locked block → prevote for it.
            // 2. If locked and proposal doesn't match → prevote nil (unless polka for proposal at valid_round >= locked_round).
            // 3. If not locked → prevote for proposal (or nil if no proposal).
            let vote_hash = match (&guard.locked_block, &guard.proposal) {
                (Some(locked), Some(proposal)) if locked.hash() == proposal.hash() => {
                    proposal.hash()
                }
                (Some(_locked), Some(proposal)) => {
                    // Locked on a different block. Check if we've seen a polka for the proposal
                    // at a valid_round >= locked_round.
                    if guard.valid_block.as_ref().is_some_and(|vb| vb.hash() == proposal.hash())
                        && guard.valid_round >= guard.locked_round
                    {
                        proposal.hash()
                    } else {
                        NIL_HASH
                    }
                }
                (None, Some(proposal)) => proposal.hash(),
                (_, None) => NIL_HASH, // No proposal → prevote nil.
            };
            (guard.height, guard.round, vote_hash, guard.prevoted)
        };
        if already {
            return Ok(None);
        }
        let vote = sign_vote(
            &*self.scheme,
            Vote {
                height,
                round,
                step: VoteStep::Prevote,
                block_hash: vote_hash,
                validator_address: local.validator.address,
                public_key: local.validator.public_key.clone(),
                signature: Vec::new(),
            },
            &local.secret_key,
        )?;
        self.note_validator_liveness(local.validator.address)?;
        self.append_wal(ConsensusWalEntry::VoteBroadcast {
            height,
            round,
            step: VoteStep::Prevote,
            block_hash: vote_hash,
            validator_address: local.validator.address,
        })?;
        self.state.write().prevoted = true;
        self.network.broadcast(NetworkMessage::Vote(vote.clone())).await?;
        Ok(Some(vote))
    }

    async fn emit_precommit(&self, block_hash: zeno_hash::Hash32) -> Result<Option<Vote>> {
        let Some(local) = &self.local_validator else {
            return Ok(None);
        };
        if !self.local_validator_active()? {
            return Ok(None);
        }
        let (height, round, already) = {
            let guard = self.state.read();
            (guard.height, guard.round, guard.precommitted)
        };
        if already {
            return Ok(None);
        }
        let vote = sign_vote(
            &*self.scheme,
            Vote {
                height,
                round,
                step: VoteStep::Precommit,
                block_hash,
                validator_address: local.validator.address,
                public_key: local.validator.public_key.clone(),
                signature: Vec::new(),
            },
            &local.secret_key,
        )?;
        self.note_validator_liveness(local.validator.address)?;
        self.append_wal(ConsensusWalEntry::VoteBroadcast {
            height,
            round,
            step: VoteStep::Precommit,
            block_hash,
            validator_address: local.validator.address,
        })?;
        self.state.write().precommitted = true;
        self.network.broadcast(NetworkMessage::Vote(vote.clone())).await?;
        Ok(Some(vote))
    }

    fn record_vote(&self, vote: Vote) -> Result<(Option<zeno_hash::Hash32>, Option<zeno_hash::Hash32>)> {
        verify_vote(&*self.scheme, &vote)?;
        self.note_validator_liveness(vote.validator_address)?;
        let mut should_precommit = None;
        let mut should_finalize = None;
        {
            let mut guard = self.state.write();
            if vote.height != guard.height || vote.round != guard.round {
                return Ok((None, None));
            }
            if guard
                .votes
                .iter()
                .any(|existing| {
                    existing.height == vote.height
                        && existing.round == vote.round
                        && existing.step == vote.step
                        && existing.validator_address == vote.validator_address
                        && existing.block_hash != vote.block_hash
                })
            {
                let key = (vote.validator_address, vote.height, vote.round);
                if !guard.processed_evidence.contains(&key) {
                    guard.processed_evidence.insert(key);
                    guard.evidence.push(Evidence {
                        validator_address: vote.validator_address,
                        height: vote.height,
                        round: vote.round,
                        reason: "duplicate vote".to_string(),
                    });
                }
                self.append_wal(ConsensusWalEntry::EvidenceRecorded {
                    height: vote.height,
                    round: vote.round,
                    validator_address: vote.validator_address,
                    reason: "duplicate vote".to_string(),
                })?;
                return Ok((None, None));
            }
            self.append_wal(ConsensusWalEntry::VoteRecorded {
                height: vote.height,
                round: vote.round,
                step: vote.step,
                block_hash: vote.block_hash,
                validator_address: vote.validator_address,
            })?;
            guard.votes.push(vote.clone());
            match vote.step {
                VoteStep::Prevote => {
                    guard.prevotes.entry(vote.block_hash).or_default().insert(vote.validator_address);
                }
                VoteStep::Precommit => {
                    guard.precommits.entry(vote.block_hash).or_default().insert(vote.validator_address);
                }
            };
            let count = match vote.step {
                VoteStep::Prevote => guard.prevotes.get(&vote.block_hash).map(|s| s.len()).unwrap_or(0),
                VoteStep::Precommit => guard.precommits.get(&vote.block_hash).map(|s| s.len()).unwrap_or(0),
            };
            if vote.step == VoteStep::Prevote && count >= self.quorum() {
                should_precommit = Some(vote.block_hash);
                // Polka detected — update locking state and persist to WAL.
                if vote.block_hash != NIL_HASH {
                    // Verify the proposal matches the voted block before locking.
                    let proposal_matches = guard
                        .proposal
                        .as_ref()
                        .is_some_and(|p| p.hash() == vote.block_hash);
                    if proposal_matches {
                        let block = guard.proposal.clone().expect("proposal verified above");
                        // Record polka (valid_round/valid_block) independently from lock.
                        guard.valid_round = Some(vote.round);
                        guard.valid_block = Some(block.clone());
                        self.append_wal(ConsensusWalEntry::PolkaObserved {
                            height: vote.height,
                            valid_round: vote.round,
                            block_hash: vote.block_hash,
                            block: block.clone(),
                        })?;
                        // Lock on the block.
                        guard.locked_round = Some(vote.round);
                        guard.locked_block = Some(block.clone());
                        self.append_wal(ConsensusWalEntry::Locked {
                            height: vote.height,
                            locked_round: vote.round,
                            block_hash: vote.block_hash,
                            block,
                        })?;
                    }
                }
            }
            if vote.step == VoteStep::Precommit && count >= self.quorum() {
                if vote.block_hash != NIL_HASH {
                    should_finalize = Some(vote.block_hash);
                }
            }
        }
        Ok((should_precommit, should_finalize))
    }

    async fn handle_vote_actions(&self, vote: Vote) -> Result<()> {
        let (should_precommit, mut should_finalize) = self.record_vote(vote)?;
        if let Some(block_hash) = should_precommit {
            if let Some(precommit_vote) = self.emit_precommit(block_hash).await? {
                let (_, local_finalize) = self.record_vote(precommit_vote)?;
                should_finalize = should_finalize.or(local_finalize);
            }
        }
        if let Some(block_hash) = should_finalize {
            self.finalize(block_hash).await?;
        }
        Ok(())
    }

    async fn on_vote(&self, vote: Vote) -> Result<()> {
        self.handle_vote_actions(vote).await
    }

    async fn finalize(&self, block_hash: zeno_hash::Hash32) -> Result<()> {
        let (block, votes, height, round) = {
            let guard = self.state.read();
            let block = guard
                .proposal
                .clone()
                .ok_or_else(|| anyhow!("missing proposal for finalize"))?;
            if block.hash() != block_hash {
                return Ok(());
            }
            let votes = guard
                .votes
                .iter()
                .filter(|vote| vote.step == VoteStep::Precommit && vote.block_hash == block_hash)
                .cloned()
                .collect::<Vec<_>>();
            (block, votes, guard.height, guard.round)
        };
        let certificate = CommitCertificate {
            block_hash,
            height,
            round,
            votes: votes.clone(),
        };
        self.validate_commit_certificate(&block, &certificate)?;

        let executed = self.execution.execute_block(&*self.scheme, &self.store, block.clone())?;
        // Build FinalizedBlock only after we have both execution result AND certificate.
        let finalized = FinalizedBlock {
            block: executed.block,
            certificate,
            receipts: executed.receipts,
            epoch_transition: executed.epoch_transition,
        };
        self.append_wal(ConsensusWalEntry::CommitFinalized {
            height,
            round,
            block_hash,
        })?;
        self.execution
            .commit_finalized_block(&self.store, &finalized, &executed.state)
            .context("commit finalized block")?;
        self.apply_pending_evidence()?;
        self.mempool.remove_committed(&finalized.block.transactions);
        self.network
            .broadcast(NetworkMessage::Commit(finalized))
            .await?;
        info!(height, round, hash = %block_hash, "finalized block");
        // WAL compaction — remove entries from more than 10 heights ago.
        if height > 10 {
            let compacted = self.store.compact_consensus_wal(height.saturating_sub(10))?;
            if compacted > 0 {
                info!(compacted, "compacted consensus WAL");
            }
        }
        // State pruning — remove old blocks if pruning is configured.
        if height > 1000 {
            let pruned = self.store.prune_blocks_below(height.saturating_sub(1000))?;
            if pruned > 0 {
                info!(pruned, "pruned old blocks");
            }
        }
        self.advance_height(height + 1).await?;
        Ok(())
    }

    async fn on_commit(&self, finalized: FinalizedBlock) -> Result<()> {
        self.import_external_finalized_block(finalized).await
    }

    /// Imports an externally finalized block through the durable consensus path.
    pub async fn import_external_finalized_block(&self, finalized: FinalizedBlock) -> Result<()> {
        let current = self.state.read().height;
        if finalized.certificate.height < current {
            return Ok(());
        }
        self.validate_commit_certificate(&finalized.block, &finalized.certificate)?;
        self.append_wal(ConsensusWalEntry::CommitFinalized {
            height: finalized.certificate.height,
            round: finalized.certificate.round,
            block_hash: finalized.certificate.block_hash,
        })?;
        self.execution
            .validate_and_commit_finalized_block(&*self.scheme, &self.store, &finalized)
            .context("validate external finalized block")?;
        self.mempool.remove_committed(&finalized.block.transactions);
        self.advance_height(finalized.block.header.height + 1).await
    }

    async fn advance_height(&self, next_height: u64) -> Result<()> {
        {
            let mut guard = self.state.write();
            guard.height = next_height;
            guard.round = 0;
            guard.proposal = None;
            guard.prevotes.clear();
            guard.precommits.clear();
            guard.votes.clear();
            guard.prevoted = false;
            guard.precommitted = false;
            // Clear locks on height advance.
            guard.locked_round = None;
            guard.locked_block = None;
            guard.valid_round = None;
            guard.valid_block = None;
        }
        self.persist_snapshot()?;
        self.append_wal(ConsensusWalEntry::HeightAdvanced { next_height })?;
        Ok(())
    }

    async fn advance_round(&self) -> Result<()> {
        {
            let mut guard = self.state.write();
            guard.round += 1;
            guard.proposal = None;
            guard.prevotes.clear();
            guard.precommits.clear();
            guard.votes.clear();
            guard.prevoted = false;
            guard.precommitted = false;
            // Preserve locked_round, locked_block, valid_round, valid_block across rounds.
        }
        let snapshot = self.current_snapshot();
        self.persist_snapshot()?;
        self.append_wal(ConsensusWalEntry::RoundAdvanced {
            height: snapshot.height,
            next_round: snapshot.round,
        })?;
        Ok(())
    }

    /// Starts the consensus task.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        self.persist_snapshot()?;
        self.maybe_propose().await?;

        let mut inbound = self.network.subscribe();
        let current_round = self.state.read().round;
        let mut round_deadline = tokio::time::Instant::now() + self.round_timeout(current_round);

        loop {
            tokio::select! {
                event = inbound.recv() => match event {
                    Ok(event) => match event.message {
                        NetworkMessage::Proposal(proposal) => {
                            if let Err(err) = self.on_proposal(proposal).await {
                                warn!(error = %err, "proposal rejected");
                            }
                        }
                        NetworkMessage::Vote(vote) => {
                            if let Err(err) = self.on_vote(vote).await {
                                warn!(error = %err, "vote rejected");
                            }
                        }
                        NetworkMessage::Commit(finalized) => {
                            if let Err(err) = self.on_commit(finalized).await {
                                warn!(error = %err, "commit rejected");
                            }
                            // Reset timeout after commit (new height).
                            let round = self.state.read().round;
                            round_deadline = tokio::time::Instant::now() + self.round_timeout(round);
                        }
                        NetworkMessage::Transaction(_)
                        | NetworkMessage::Status(_)
                        | NetworkMessage::Handshake(_)
                        | NetworkMessage::SyncRequest { .. }
                        | NetworkMessage::SyncResponse { .. }
                        | NetworkMessage::Ping { .. }
                        | NetworkMessage::Pong { .. } => {}
                    },
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(err) => return Err(anyhow!(err)),
                },
                _ = tokio::time::sleep_until(round_deadline) => {
                    // Emit nil prevote if we haven't voted yet (timeout without proposal).
                    if let Some(vote) = self.emit_prevote().await? {
                        self.handle_vote_actions(vote).await?;
                    }
                    self.advance_round().await?;
                    let round = self.state.read().round;
                    round_deadline = tokio::time::Instant::now() + self.round_timeout(round);
                    self.maybe_propose().await?;
                }
            }
        }
    }

    fn validate_incoming_proposal(&self, proposal: &Proposal) -> Result<()> {
        let expected = self.proposer_for(proposal.height, proposal.round);
        validate_incoming_proposal(
            &*self.scheme,
            &expected,
            proposal,
            &self.chain_id,
            &self.store,
            &self.execution,
            self.params.max_transactions_per_block,
        )
    }

    fn validate_commit_certificate(&self, block: &Block, certificate: &CommitCertificate) -> Result<()> {
        if certificate.block_hash != block.hash() {
            return Err(anyhow!("certificate block hash mismatch"));
        }
        if certificate.height != block.header.height {
            return Err(anyhow!("certificate height mismatch"));
        }
        if certificate.round != block.header.round {
            return Err(anyhow!("certificate round mismatch"));
        }
        let mut unique = BTreeSet::new();
        for vote in &certificate.votes {
            verify_vote(&*self.scheme, vote)?;
            if vote.height != certificate.height || vote.round != certificate.round {
                return Err(anyhow!("certificate vote height/round mismatch"));
            }
            if vote.step != VoteStep::Precommit {
                return Err(anyhow!("certificate must contain only precommit votes"));
            }
            if vote.block_hash != certificate.block_hash {
                return Err(anyhow!("certificate vote block hash mismatch"));
            }
            unique.insert(vote.validator_address);
        }
        if unique.len() < self.quorum() {
            return Err(anyhow!("certificate quorum not reached"));
        }
        Ok(())
    }

    fn active_validators(&self) -> Vec<Validator> {
        let Ok(mut staking) = StakingSnapshot::load(&self.store) else {
            return self.validators.clone();
        };
        staking.ensure_validators(&self.validators);
        let ordered_addresses = staking.effective_validator_set(&self.economics);
        if ordered_addresses.is_empty() {
            return self.validators.clone();
        }
        let validators_by_address = self
            .validators
            .iter()
            .cloned()
            .map(|validator| (validator.address, validator))
            .collect::<BTreeMap<_, _>>();
        ordered_addresses
            .into_iter()
            .filter_map(|address| validators_by_address.get(&address).cloned())
            .collect()
    }

    fn local_validator_active(&self) -> Result<bool> {
        let Some(local) = &self.local_validator else {
            return Ok(false);
        };
        let mut staking = StakingSnapshot::load(&self.store)?;
        staking.ensure_validators(&self.validators);
        Ok(staking.is_validator_active(local.validator.address, &self.economics))
    }

    fn note_validator_liveness(&self, validator_address: Address) -> Result<()> {
        let mut staking = StakingSnapshot::load(&self.store)?;
        staking.ensure_validators(&self.validators);
        staking.note_liveness(validator_address)?;
        staking.persist(&self.store)?;
        Ok(())
    }

    fn apply_pending_evidence(&self) -> Result<()> {
        let evidence = {
            let mut guard = self.state.write();
            let evidence = guard.evidence.clone();
            guard.evidence.clear();
            evidence
        };
        if evidence.is_empty() {
            return Ok(());
        }
        let mut staking = StakingSnapshot::load(&self.store)?;
        staking.ensure_validators(&self.validators);
        staking.apply_evidence(&evidence, &self.economics)?;
        staking.persist(&self.store)?;
        Ok(())
    }
}

struct RecoveredState {
    snapshot: ConsensusSnapshot,
    locked_round: Option<u32>,
    locked_block: Option<Block>,
    valid_round: Option<u32>,
    valid_block: Option<Block>,
}

fn recover_snapshot(snapshot: ConsensusSnapshot, wal: &[ConsensusWalEntry]) -> RecoveredState {
    let mut recovered = snapshot;
    let mut locked_round: Option<u32> = None;
    let mut locked_block: Option<Block> = None;
    let mut valid_round: Option<u32> = None;
    let mut valid_block: Option<Block> = None;
    for entry in wal {
        match entry {
            ConsensusWalEntry::SnapshotPersisted { height, round } => {
                if (*height, *round) >= (recovered.height, recovered.round) {
                    recovered.height = *height;
                    recovered.round = *round;
                }
            }
            ConsensusWalEntry::HeightAdvanced { next_height } => {
                if *next_height > recovered.height {
                    recovered.height = *next_height;
                    recovered.round = 0;
                    locked_round = None;
                    locked_block = None;
                    valid_round = None;
                    valid_block = None;
                }
            }
            ConsensusWalEntry::RoundAdvanced { height, next_round } => {
                if *height == recovered.height && *next_round > recovered.round {
                    recovered.round = *next_round;
                }
            }
            ConsensusWalEntry::CommitFinalized { height, .. } => {
                let next_height = height.saturating_add(1);
                if next_height > recovered.height {
                    recovered.height = next_height;
                    recovered.round = 0;
                    locked_round = None;
                    locked_block = None;
                    valid_round = None;
                    valid_block = None;
                }
            }
            ConsensusWalEntry::Locked { height, locked_round: lr, block, .. } => {
                if *height == recovered.height {
                    locked_round = Some(*lr);
                    locked_block = Some(block.clone());
                }
            }
            ConsensusWalEntry::PolkaObserved { height, valid_round: vr, block, .. } => {
                if *height == recovered.height {
                    valid_round = Some(*vr);
                    valid_block = Some(block.clone());
                }
            }
            ConsensusWalEntry::ProposalAccepted { .. }
            | ConsensusWalEntry::ProposalBroadcast { .. }
            | ConsensusWalEntry::VoteRecorded { .. }
            | ConsensusWalEntry::VoteBroadcast { .. }
            | ConsensusWalEntry::EvidenceRecorded { .. } => {}
        }
    }
    RecoveredState {
        snapshot: recovered,
        locked_round,
        locked_block,
        valid_round,
        valid_block,
    }
}

fn validate_incoming_proposal(
    scheme: &dyn SignatureScheme,
    expected: &Validator,
    proposal: &Proposal,
    chain_id: &ChainId,
    store: &SharedStore,
    execution: &ExecutionEngine,
    max_transactions_per_block: usize,
) -> Result<()> {
    if expected.address != proposal.validator_address {
        return Err(anyhow!("proposal from unexpected proposer"));
    }
    if proposal.block.header.proposer != expected.address {
        return Err(anyhow!("proposal block header proposer mismatch"));
    }
    if proposal.block.proposer_public_key != expected.public_key {
        return Err(anyhow!("proposal public key does not match validator set"));
    }
    if proposal.block.header.chain_id != *chain_id {
        return Err(anyhow!("proposal chain id mismatch"));
    }
    if proposal.block.header.height != proposal.height {
        return Err(anyhow!("proposal height/header mismatch"));
    }
    if proposal.block.header.round != proposal.round {
        return Err(anyhow!("proposal round/header mismatch"));
    }
    if proposal.block.transactions.len() > max_transactions_per_block {
        return Err(anyhow!("proposal exceeds transaction limit"));
    }
    let expected_parent = store
        .latest_block()?
        .map(|entry| entry.block.hash())
        .unwrap_or_default();
    if proposal.block.header.parent_hash != expected_parent {
        return Err(anyhow!("proposal parent hash mismatch"));
    }
    verify_block(scheme, &proposal.block).context("invalid proposal block signature")?;
    let mut state = StateSnapshot::load(store)?;
    for tx in &proposal.block.transactions {
        execution
            .validate_transaction(scheme, &state, proposal.height, tx)
            .map_err(|err| anyhow!("proposal contains invalid transaction: {err}"))?;
        let mut sender = state.account(&tx.body.sender);
        sender.balance = sender
            .balance
            .checked_sub(tx.body.amount.saturating_add(tx.body.fee))
            .ok_or_else(|| anyhow!("proposal sender underflow"))?;
        sender.nonce += 1;
        state.put_account(tx.body.sender, sender);
        if tx.body.evm.is_none() {
            let mut recipient = state.account(&tx.body.recipient);
            recipient.balance = recipient.balance.saturating_add(tx.body.amount);
            state.put_account(tx.body.recipient, recipient);
        }
        let derived = sender_from_public_key(scheme, &tx.public_key)
            .map_err(|err| anyhow!("proposal sender derivation failed: {err}"))?;
        if derived != tx.body.sender {
            return Err(anyhow!("proposal transaction sender mismatch"));
        }
        let body_bytes = zeno_primitives::canonical_transaction_bytes(&tx.body)?;
        verify_transaction(scheme, chain_id, tx, proposal.height)
            .map_err(|err| anyhow!("proposal transaction signature invalid: {err}"))?;
        if body_bytes.is_empty() {
            return Err(anyhow!("proposal transaction canonical bytes unexpectedly empty"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zeno_execution::ExecutionEngine;
    use zeno_crypto::{default_scheme, PublicKeyBytes, SignatureScheme};
    use zeno_primitives::sign_block;
    use zeno_storage::MemoryStore;
    use zeno_types::{
        Account, BlockHeader, ChainId, ConsensusParams, ConsensusSnapshot, CryptoParams, Genesis,
        EconomicsParams, NetworkMetadata, Proposal, Validator,
    };

    use super::{recover_snapshot, validate_incoming_proposal};

    fn validator_fixture() -> (Arc<dyn SignatureScheme>, Validator, zeno_crypto::SecretKeyBytes) {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let address = zeno_types::Address(scheme.derive_address(&pk).expect("address"));
        let validator = Validator {
            validator_id: "validator-0".to_string(),
            voting_power: 1,
            p2p_address: "127.0.0.1:7000".to_string(),
            rpc_address: "127.0.0.1:8000".to_string(),
            public_key: pk.0,
            address,
        };
        (scheme, validator, sk)
    }

    fn genesis_fixture(validator: &Validator) -> Genesis {
        let mut accounts = std::collections::BTreeMap::new();
        accounts.insert(
            validator.address,
            Account {
                nonce: 0,
                balance: 1_000_000,
            },
        );
        Genesis {
            chain_id: ChainId("zeno-testnet".to_string()),
            metadata: NetworkMetadata {
                network_name: "test".to_string(),
                ticker: "TST".to_string(),
                rpc_urls: vec!["http://127.0.0.1:8000".to_string()],
                block_explorer_url: "http://127.0.0.1:8000/explorer".to_string(),
                metamask_compatible: false,
                metamask_snap_compatible: true,
                smart_contracts_supported: true,
                evm_chain_id: Some(424242),
                compatibility_notice: "test".to_string(),
                metamask_snap_id: None,
            },
            accounts,
            validators: vec![validator.clone()],
            consensus: ConsensusParams {
                proposal_timeout_ms: 1000,
                vote_timeout_ms: 1000,
                max_transactions_per_block: 16,
            },
            crypto: CryptoParams {
                ml_dsa_parameter: "ML-DSA-65 compatible (Dilithium3 family)".to_string(),
            },
            economics: EconomicsParams {
                minimum_self_bond: 100,
                epoch_length: 10,
                unbonding_epochs: 2,
                treasury_bps: 1_000,
                downtime_slash_bps: 100,
                double_sign_slash_bps: 500,
            },
        }
    }

    #[test]
    fn rejects_proposal_with_malformed_signature() {
        let (scheme, validator, secret_key) = validator_fixture();
        let genesis = genesis_fixture(&validator);
        let header = BlockHeader {
            height: 1,
            round: 0,
            chain_id: genesis.chain_id.clone(),
            parent_hash: zeno_hash::Hash32::zero(),
            tx_root: zeno_hash::Hash32::zero(),
            state_root: zeno_hash::Hash32::zero(),
            receipt_root: zeno_hash::Hash32::zero(),
            proposer: validator.address,
            timestamp_ms: 1,
        };
        let mut block = sign_block(
            &*scheme,
            header,
            Vec::new(),
            PublicKeyBytes(validator.public_key.clone()),
            &secret_key,
        )
        .expect("signed block");
        block.proposer_signature = vec![0u8; 64];
        let proposal = Proposal {
            height: 1,
            round: 0,
            block,
            validator_address: validator.address,
        };
        let store = MemoryStore::shared();
        let execution = ExecutionEngine::new(genesis.chain_id.clone());

        let err = validate_incoming_proposal(
            &*scheme,
            &validator,
            &proposal,
            &genesis.chain_id,
            &store,
            &execution,
            genesis.consensus.max_transactions_per_block,
        )
        .expect_err("must fail");
        assert!(err.to_string().contains("invalid proposal block signature"));
    }

    #[test]
    fn rejects_proposal_with_wrong_validator_public_key() {
        let (scheme, validator, secret_key) = validator_fixture();
        let (_, other_validator, _) = validator_fixture();
        let genesis = genesis_fixture(&validator);
        let header = BlockHeader {
            height: 1,
            round: 0,
            chain_id: genesis.chain_id.clone(),
            parent_hash: zeno_hash::Hash32::zero(),
            tx_root: zeno_hash::Hash32::zero(),
            state_root: zeno_hash::Hash32::zero(),
            receipt_root: zeno_hash::Hash32::zero(),
            proposer: validator.address,
            timestamp_ms: 1,
        };
        let mut block = sign_block(
            &*scheme,
            header,
            Vec::new(),
            PublicKeyBytes(validator.public_key.clone()),
            &secret_key,
        )
        .expect("signed block");
        block.proposer_public_key = other_validator.public_key.clone();
        let proposal = Proposal {
            height: 1,
            round: 0,
            block,
            validator_address: validator.address,
        };
        let store = MemoryStore::shared();
        let execution = ExecutionEngine::new(genesis.chain_id.clone());

        let err = validate_incoming_proposal(
            &*scheme,
            &validator,
            &proposal,
            &genesis.chain_id,
            &store,
            &execution,
            genesis.consensus.max_transactions_per_block,
        )
        .expect_err("must fail");
        assert!(err
            .to_string()
            .contains("proposal public key does not match validator set"));
    }

    #[test]
    fn wal_recovery_advances_snapshot() {
        let recovered = recover_snapshot(
            ConsensusSnapshot { height: 3, round: 0 },
            &[
                zeno_types::ConsensusWalEntry::RoundAdvanced {
                    height: 3,
                    next_round: 2,
                },
                zeno_types::ConsensusWalEntry::CommitFinalized {
                    height: 3,
                    round: 2,
                    block_hash: zeno_hash::Hash32::zero(),
                },
            ],
        );
        assert_eq!(recovered.snapshot.height, 4);
        assert_eq!(recovered.snapshot.round, 0);
        assert!(recovered.locked_round.is_none());
    }

    #[test]
    fn round_state_preserves_locks_across_rounds() {
        let mut state = super::RoundState::default();
        let block = zeno_types::Block {
            header: BlockHeader {
                height: 1,
                round: 0,
                chain_id: ChainId("test".to_string()),
                parent_hash: zeno_hash::Hash32::zero(),
                tx_root: zeno_hash::Hash32::zero(),
                state_root: zeno_hash::Hash32::zero(),
                receipt_root: zeno_hash::Hash32::zero(),
                proposer: zeno_types::Address([1; 32]),
                timestamp_ms: 1,
            },
            transactions: Vec::new(),
            proposer_public_key: Vec::new(),
            proposer_signature: Vec::new(),
        };
        state.locked_round = Some(0);
        state.locked_block = Some(block.clone());
        state.valid_round = Some(0);
        state.valid_block = Some(block.clone());
        // Simulate round advance — clear per-round state but keep locks.
        state.round += 1;
        state.proposal = None;
        state.prevotes.clear();
        state.precommits.clear();
        state.votes.clear();
        state.prevoted = false;
        state.precommitted = false;
        // Locks must survive.
        assert_eq!(state.locked_round, Some(0));
        assert!(state.locked_block.is_some());
        assert_eq!(state.valid_round, Some(0));
        assert!(state.valid_block.is_some());
    }

    #[test]
    fn nil_hash_is_zero() {
        assert_eq!(super::NIL_HASH, zeno_hash::Hash32::zero());
    }

    #[test]
    fn round_state_clears_locks_on_height_advance() {
        let mut state = super::RoundState::default();
        state.locked_round = Some(2);
        state.locked_block = Some(zeno_types::Block {
            header: BlockHeader {
                height: 1,
                round: 2,
                chain_id: ChainId("test".to_string()),
                parent_hash: zeno_hash::Hash32::zero(),
                tx_root: zeno_hash::Hash32::zero(),
                state_root: zeno_hash::Hash32::zero(),
                receipt_root: zeno_hash::Hash32::zero(),
                proposer: zeno_types::Address([1; 32]),
                timestamp_ms: 1,
            },
            transactions: Vec::new(),
            proposer_public_key: Vec::new(),
            proposer_signature: Vec::new(),
        });
        // Simulate height advance.
        state.height += 1;
        state.round = 0;
        state.locked_round = None;
        state.locked_block = None;
        state.valid_round = None;
        state.valid_block = None;
        assert!(state.locked_round.is_none());
        assert!(state.locked_block.is_none());
    }
}
