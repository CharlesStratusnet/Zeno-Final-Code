//! Shared domain types for the chain.

use std::collections::BTreeMap;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeno_hash::Hash32;

/// Account address type.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct Address(pub [u8; 32]);

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Chain identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainId(pub String);

/// Basic account record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Account {
    /// Account nonce.
    pub nonce: u64,
    /// Account liquid balance.
    pub balance: u128,
}

/// Validator lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ValidatorStatus {
    /// Validator can participate in consensus.
    #[default]
    Active,
    /// Validator is jailed and cannot participate until restored.
    Jailed,
    /// Validator is inactive for validator set selection.
    Inactive,
}

/// Validator staking state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ValidatorStake {
    /// Validator operator address.
    pub validator_address: Address,
    /// Self-bonded amount.
    pub self_bond: u128,
    /// Delegated amount including self-bond.
    pub total_stake: u128,
    /// Commission rate in basis points.
    pub commission_bps: u16,
    /// Current lifecycle status.
    pub status: ValidatorStatus,
    /// Last epoch in which the validator met liveness requirements.
    pub last_liveness_epoch: u64,
}

/// Delegation from a delegator to a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Delegation {
    /// Delegator address.
    pub delegator: Address,
    /// Validator address.
    pub validator_address: Address,
    /// Bonded amount.
    pub amount: u128,
}

/// Pending unbonding request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UnbondingDelegation {
    /// Delegator address.
    pub delegator: Address,
    /// Validator address.
    pub validator_address: Address,
    /// Amount scheduled for release.
    pub amount: u128,
    /// Epoch at which funds become withdrawable.
    pub release_epoch: u64,
}

/// Slashing incident persisted for audit and settlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SlashingEvent {
    /// Validator address.
    pub validator_address: Address,
    /// Epoch in which the slash was recorded.
    pub epoch: u64,
    /// Basis points of stake removed.
    pub slash_bps: u16,
    /// Human-readable reason.
    pub reason: String,
}

/// Staking and rewards parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicsParams {
    /// Minimum self-bond required for active validators.
    pub minimum_self_bond: u128,
    /// Epoch length in blocks.
    pub epoch_length: u64,
    /// Unbonding duration in epochs.
    pub unbonding_epochs: u64,
    /// Treasury share of distributed rewards in basis points.
    pub treasury_bps: u16,
    /// Downtime slash amount in basis points.
    pub downtime_slash_bps: u16,
    /// Double-sign slash amount in basis points.
    pub double_sign_slash_bps: u16,
}

/// Supported governance parameter updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParameterUpdate {
    /// Replace economics parameters.
    Economics(EconomicsParams),
}

/// Pending governance proposal for deterministic activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceProposal {
    /// Monotonic proposal identifier.
    pub proposal_id: u64,
    /// Epoch at which the change activates.
    pub activation_epoch: u64,
    /// Requested update.
    pub update: ParameterUpdate,
    /// Free-form reason or title.
    pub description: String,
}

/// Governance state snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceState {
    /// Currently active economics parameters.
    pub economics: EconomicsParams,
    /// Pending deterministic proposals.
    pub pending: Vec<GovernanceProposal>,
    /// Last allocated proposal id.
    pub next_proposal_id: u64,
}

impl GovernanceState {
    /// Creates governance state from the active economics config.
    pub fn new(economics: EconomicsParams) -> Self {
        Self {
            economics,
            pending: Vec::new(),
            next_proposal_id: 1,
        }
    }
}

/// Finalized epoch transition record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochTransition {
    /// Epoch after applying the transition.
    pub epoch: u64,
    /// Finalized block height that activated this transition.
    pub height: u64,
    /// Effective validator set in deterministic order.
    pub validator_set: Vec<Address>,
    /// Commitment over the validator set ordering.
    pub validator_set_root: Hash32,
    /// Active economics parameters after the transition.
    pub economics: EconomicsParams,
}

/// Aggregate staking state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StakingState {
    /// Current epoch index.
    pub epoch: u64,
    /// Validator staking records.
    pub validators: BTreeMap<Address, ValidatorStake>,
    /// Delegations keyed by delegator/validator pair.
    pub delegations: BTreeMap<(Address, Address), Delegation>,
    /// Pending unbondings.
    pub unbonding: Vec<UnbondingDelegation>,
    /// Treasury balance tracked by the protocol.
    pub treasury_balance: u128,
    /// Slashing log.
    pub slashing_events: Vec<SlashingEvent>,
}

/// 20-byte EVM address.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct EvmAddress(pub [u8; 20]);

impl core::fmt::Display for EvmAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

/// EVM transaction payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmTransaction {
    /// Action kind.
    pub kind: EvmTransactionKind,
    /// Call/create value.
    pub value: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Gas price.
    pub gas_price: u128,
}

/// Supported EVM transaction kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvmTransactionKind {
    /// Contract deployment.
    Create {
        /// Creation bytecode.
        bytecode: Vec<u8>,
    },
    /// Contract call.
    Call {
        /// Contract address.
        contract: EvmAddress,
        /// ABI-encoded calldata.
        input: Vec<u8>,
    },
}

/// Transaction body without signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionBody {
    /// Chain identifier for replay protection.
    pub chain_id: ChainId,
    /// Sender account.
    pub sender: Address,
    /// Recipient account.
    pub recipient: Address,
    /// Transfer amount.
    pub amount: u128,
    /// Sender nonce.
    pub nonce: u64,
    /// Fee paid to the block proposer.
    pub fee: u128,
    /// Optional EVM execution payload.
    pub evm: Option<EvmTransaction>,
    /// Optional memo.
    pub memo: Option<String>,
    /// Optional validity bound in block height.
    pub valid_until: Option<u64>,
}

/// Signed transaction envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Canonical body.
    pub body: TransactionBody,
    /// Sender public key used for verification.
    pub public_key: Vec<u8>,
    /// ML-DSA signature over the canonical body.
    pub signature: Vec<u8>,
}

impl Transaction {
    /// Transaction identifier.
    pub fn id(&self) -> Hash32 {
        zeno_hash::hash_bytes(zeno_codec::encode(self).expect("transaction encoding must succeed"))
    }
}

/// Execution receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Transaction hash.
    pub tx_hash: Hash32,
    /// Block height.
    pub height: u64,
    /// Sender charged fee.
    pub fee_charged: u128,
    /// Outcome.
    pub outcome: ExecutionOutcome,
    /// Optional EVM execution result.
    pub evm: Option<EvmCallResult>,
}

/// Transaction execution outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionOutcome {
    /// Transfer succeeded.
    Success,
    /// Transfer failed.
    Rejected(String),
}

/// Result of an EVM transaction or eth_call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmCallResult {
    /// Created contract address when applicable.
    pub contract_address: Option<EvmAddress>,
    /// Return/output bytes.
    pub output: Vec<u8>,
    /// Gas used.
    pub gas_used: u64,
    /// Log entries.
    pub logs: Vec<EvmLog>,
}

/// Simplified EVM log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmLog {
    /// Emitting contract.
    pub address: EvmAddress,
    /// Topics.
    pub topics: Vec<Hash32>,
    /// Data bytes.
    pub data: Vec<u8>,
}

/// Stored EVM account state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EvmAccountState {
    /// EVM nonce.
    pub nonce: u64,
    /// EVM balance.
    pub balance: u128,
    /// Runtime bytecode.
    pub code: Vec<u8>,
    /// Storage trie flattened as slot/value pairs.
    pub storage: BTreeMap<Hash32, Hash32>,
}

/// Read-only eth_call request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmCallRequest {
    /// Optional sender.
    pub from: Option<[u8; 20]>,
    /// Target contract.
    pub to: EvmAddress,
    /// Input calldata.
    pub data: Vec<u8>,
    /// Optional gas limit.
    pub gas_limit: Option<u64>,
    /// Optional value.
    pub value: Option<u128>,
}

/// Validator descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    /// Stable validator identifier.
    pub validator_id: String,
    /// Voting power.
    pub voting_power: u64,
    /// Network address.
    pub p2p_address: String,
    /// RPC address.
    pub rpc_address: String,
    /// Validator public key.
    pub public_key: Vec<u8>,
    /// Derived validator address.
    pub address: Address,
}

/// Genesis configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Human-facing network metadata.
    pub metadata: NetworkMetadata,
    /// Initial accounts.
    #[serde(with = "genesis_accounts_serde")]
    pub accounts: BTreeMap<Address, Account>,
    /// Validator set.
    pub validators: Vec<Validator>,
    /// Consensus parameters.
    pub consensus: ConsensusParams,
    /// Cryptography configuration.
    pub crypto: CryptoParams,
    /// Economics configuration.
    pub economics: EconomicsParams,
}

/// Cryptography parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoParams {
    /// Selected ML-DSA parameter family.
    pub ml_dsa_parameter: String,
}

/// Consensus parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusParams {
    /// Proposal timeout in milliseconds.
    pub proposal_timeout_ms: u64,
    /// Vote timeout in milliseconds.
    pub vote_timeout_ms: u64,
    /// Maximum transactions per block.
    pub max_transactions_per_block: usize,
}

/// Human-facing network metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkMetadata {
    /// Network display name.
    pub network_name: String,
    /// Native asset ticker.
    pub ticker: String,
    /// Canonical RPC endpoints for the network.
    pub rpc_urls: Vec<String>,
    /// Canonical explorer URL.
    pub block_explorer_url: String,
    /// Whether the network is Ethereum JSON-RPC compatible.
    pub metamask_compatible: bool,
    /// Whether a MetaMask Snap flow is supported.
    pub metamask_snap_compatible: bool,
    /// Whether the execution layer supports smart contracts.
    pub smart_contracts_supported: bool,
    /// Optional EVM chain id. This is `None` for the current chain.
    pub evm_chain_id: Option<u64>,
    /// Free-form note about wallet/tooling compatibility.
    pub compatibility_notice: String,
    /// Optional MetaMask Snap identifier.
    pub metamask_snap_id: Option<String>,
}

mod genesis_accounts_serde {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::{Account, Address};

    pub fn serialize<S>(accounts: &BTreeMap<Address, Account>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let as_strings: BTreeMap<String, &Account> = accounts
            .iter()
            .map(|(address, account)| (hex::encode(address.0), account))
            .collect();
        as_strings.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<Address, Account>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let as_strings = BTreeMap::<String, Account>::deserialize(deserializer)?;
        as_strings
            .into_iter()
            .map(|(address, account)| {
                let bytes = hex::decode(&address).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("address must decode to 32 bytes"));
                }
                let mut raw = [0u8; 32];
                raw.copy_from_slice(&bytes);
                Ok((Address(raw), account))
            })
            .collect()
    }
}

/// Block header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Height.
    pub height: u64,
    /// Round.
    pub round: u32,
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Previous block hash.
    pub parent_hash: Hash32,
    /// Transaction root.
    pub tx_root: Hash32,
    /// State root.
    pub state_root: Hash32,
    /// Receipt root.
    pub receipt_root: Hash32,
    /// Proposer address.
    pub proposer: Address,
    /// Milliseconds since unix epoch.
    pub timestamp_ms: u64,
}

/// Signed block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Header.
    pub header: BlockHeader,
    /// Transactions.
    pub transactions: Vec<Transaction>,
    /// Proposer public key.
    pub proposer_public_key: Vec<u8>,
    /// Proposer signature.
    pub proposer_signature: Vec<u8>,
}

impl Block {
    /// Block hash.
    pub fn hash(&self) -> Hash32 {
        zeno_hash::hash_bytes(zeno_codec::encode(self).expect("block encoding must succeed"))
    }
}

/// Proposal message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// Height.
    pub height: u64,
    /// Round.
    pub round: u32,
    /// Proposed block.
    pub block: Block,
    /// Proposal signer.
    pub validator_address: Address,
}

/// Consensus phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteStep {
    /// Prevote.
    Prevote,
    /// Precommit.
    Precommit,
}

/// Vote message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    /// Height.
    pub height: u64,
    /// Round.
    pub round: u32,
    /// Step.
    pub step: VoteStep,
    /// Block hash voted for.
    pub block_hash: Hash32,
    /// Voter address.
    pub validator_address: Address,
    /// Voter public key.
    pub public_key: Vec<u8>,
    /// Signature.
    pub signature: Vec<u8>,
}

/// Evidence placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Duplicate vote offender.
    pub validator_address: Address,
    /// Height.
    pub height: u64,
    /// Round.
    pub round: u32,
    /// Free-form reason.
    pub reason: String,
}

/// Finalization certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitCertificate {
    /// Block hash.
    pub block_hash: Hash32,
    /// Height.
    pub height: u64,
    /// Round.
    pub round: u32,
    /// Collected precommit votes.
    pub votes: Vec<Vote>,
}

/// Block sync request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncRequest {
    /// Request headers beginning at a specific height.
    Headers {
        /// Starting height.
        start_height: u64,
        /// Maximum number of headers requested.
        limit: u64,
    },
    /// Request a finalized block by height.
    BlockByHeight {
        /// Block height.
        height: u64,
    },
    /// Request a finalized block by hash.
    BlockByHash {
        /// Block hash.
        hash: Hash32,
    },
}

/// Block sync response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncResponse {
    /// Returned block headers.
    Headers {
        /// Returned headers.
        headers: Vec<BlockHeader>,
    },
    /// Returned finalized block if available.
    Block {
        /// Requested block.
        block: Option<FinalizedBlock>,
    },
    /// Request could not be served.
    NotFound,
}

/// Network envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Peer handshake.
    Handshake(Handshake),
    /// Transaction gossip.
    Transaction(Transaction),
    /// Proposal gossip.
    Proposal(Proposal),
    /// Vote gossip.
    Vote(Vote),
    /// Finalized block propagation.
    Commit(FinalizedBlock),
    /// Peer status exchange.
    Status(ChainStatus),
    /// Sync request/response channel.
    SyncRequest {
        /// Correlates request and response.
        request_id: u64,
        /// Request payload.
        request: SyncRequest,
    },
    /// Sync request/response channel.
    SyncResponse {
        /// Correlates request and response.
        request_id: u64,
        /// Response payload.
        response: SyncResponse,
    },
    /// Liveness probe.
    Ping {
        /// Opaque nonce.
        nonce: u64,
    },
    /// Liveness response.
    Pong {
        /// Opaque nonce.
        nonce: u64,
    },
}

/// Handshake payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handshake {
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Node identifier.
    pub node_id: String,
    /// Best finalized height.
    pub best_height: u64,
}

/// Status payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStatus {
    /// Human-facing network metadata.
    pub metadata: NetworkMetadata,
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Latest finalized height.
    pub latest_height: u64,
    /// Latest finalized block hash.
    pub latest_hash: Hash32,
    /// Node identity.
    pub node_id: String,
    /// Current peers.
    pub peers: Vec<String>,
}

/// Consensus persistence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ConsensusSnapshot {
    /// Height.
    pub height: u64,
    /// Round.
    pub round: u32,
}

/// Durable consensus write-ahead log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusWalEntry {
    /// Local node persisted the latest round snapshot.
    SnapshotPersisted {
        /// Height.
        height: u64,
        /// Round.
        round: u32,
    },
    /// A proposal was accepted into local round state.
    ProposalAccepted {
        /// Height.
        height: u64,
        /// Round.
        round: u32,
        /// Proposed block hash.
        block_hash: Hash32,
    },
    /// A proposal was broadcast by the local node.
    ProposalBroadcast {
        /// Height.
        height: u64,
        /// Round.
        round: u32,
        /// Proposed block hash.
        block_hash: Hash32,
    },
    /// A vote was recorded after validation.
    VoteRecorded {
        /// Height.
        height: u64,
        /// Round.
        round: u32,
        /// Step.
        step: VoteStep,
        /// Block hash.
        block_hash: Hash32,
        /// Validator address.
        validator_address: Address,
    },
    /// A vote was broadcast by the local node.
    VoteBroadcast {
        /// Height.
        height: u64,
        /// Round.
        round: u32,
        /// Step.
        step: VoteStep,
        /// Block hash.
        block_hash: Hash32,
        /// Validator address.
        validator_address: Address,
    },
    /// A block was finalized from a validated certificate.
    CommitFinalized {
        /// Height.
        height: u64,
        /// Round.
        round: u32,
        /// Block hash.
        block_hash: Hash32,
    },
    /// The consensus engine advanced height.
    HeightAdvanced {
        /// Height after the transition.
        next_height: u64,
    },
    /// The consensus engine advanced round.
    RoundAdvanced {
        /// Height.
        height: u64,
        /// Round after the transition.
        next_round: u32,
    },
    /// Evidence was recorded locally.
    EvidenceRecorded {
        /// Height.
        height: u64,
        /// Round.
        round: u32,
        /// Validator address.
        validator_address: Address,
        /// Description of the safety fault.
        reason: String,
    },
    /// Validator locked on a block after observing a polka.
    Locked {
        /// Height.
        height: u64,
        /// Round at which the lock was acquired.
        locked_round: u32,
        /// Hash of the locked block.
        block_hash: Hash32,
        /// The locked block (serialized for recovery).
        block: Block,
    },
}

/// Stored block bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedBlock {
    /// Block.
    pub block: Block,
    /// Commit certificate.
    pub certificate: CommitCertificate,
    /// Receipts.
    pub receipts: Vec<Receipt>,
    /// Optional epoch transition finalized with this block.
    pub epoch_transition: Option<EpochTransition>,
}

/// RPC response status for a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Not seen by the node.
    Unknown,
    /// Present in mempool.
    Pending,
    /// Finalized with receipt.
    Finalized(Receipt),
}

/// Signed payload identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node identifier.
    pub node_id: String,
    /// Validator address if configured.
    pub validator_address: Option<Address>,
    /// P2P listen address.
    pub p2p_listen: String,
    /// RPC listen address.
    pub rpc_listen: String,
}

/// Generic JSON-RPC request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Protocol version.
    pub jsonrpc: String,
    /// Request id — can be a number, string, or null per JSON-RPC spec.
    pub id: serde_json::Value,
    /// Method name.
    pub method: String,
    /// Parameters.
    pub params: serde_json::Value,
}

/// Generic JSON-RPC response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcResponse<T> {
    /// Protocol version.
    pub jsonrpc: String,
    /// Request id — echoed from the request.
    pub id: serde_json::Value,
    /// Result.
    pub result: Option<T>,
    /// Error.
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code.
    pub code: i64,
    /// Error message.
    pub message: String,
}

/// Transaction admission error.
#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("amount must be non-zero")]
    ZeroAmount,
    #[error("fee must be non-zero")]
    ZeroFee,
    #[error("memo too large")]
    MemoTooLarge,
    #[error("transaction expired at height {0}")]
    Expired(u64),
    #[error("wrong chain id")]
    WrongChainId,
    #[error("insufficient balance")]
    InsufficientBalance,
    #[error("invalid nonce expected {expected} got {actual}")]
    InvalidNonce { expected: u64, actual: u64 },
    #[error("sender does not match public key")]
    SenderMismatch,
    #[error("signature invalid")]
    InvalidSignature,
    #[error("transaction too large ({0} bytes)")]
    TransactionTooLarge(usize),
    #[error("gas limit exceeded (max {max}, got {actual})")]
    GasLimitExceeded {
        /// Maximum allowed gas.
        max: u64,
        /// Requested gas.
        actual: u64,
    },
}

/// Log filter for eth_getLogs queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EvmLogFilter {
    /// Starting block height.
    pub from_block: Option<u64>,
    /// Ending block height.
    pub to_block: Option<u64>,
    /// Filter by emitting contract address.
    pub address: Option<EvmAddress>,
    /// Filter by topic slots (positional).
    pub topics: Vec<Option<Hash32>>,
}

/// Convenience byte payload wrapper.
pub type CanonicalBytes = Bytes;
