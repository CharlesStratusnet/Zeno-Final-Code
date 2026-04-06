# Target Architecture

Zeno is being migrated from a compact prototype into a high-assurance, post-quantum secure, fast-finality, EVM-compatible Layer 1. The target system is split into explicit operating planes so execution correctness, consensus safety, networking resilience, and operator controls can evolve independently without collapsing back into a monolithic node runtime.

## Design Goals

- deterministic execution and state transitions
- proof-capable state commitments
- hardened BFT consensus with crash recovery
- strong validator economics and evidence-driven slashing
- production networking, sync, and anti-abuse controls
- institutional-grade observability and operations
- cryptographic agility beyond a single signature algorithm
- EVM compatibility without weakening protocol safety

## Plane Model

### Execution Plane

The execution plane is responsible for:

- transaction admission and deterministic validation
- state transition and fee accounting
- EVM execution and receipt generation
- state root generation and proof serving
- separation between speculative execution and finalized execution
- deterministic, auditable serialization and replay

The current codebase already contains the first-generation building blocks:

- [`zeno-execution`](/Users/charliecohen/ZenoQPL1/crates/zeno-execution/src/lib.rs)
- [`zeno-evm`](/Users/charliecohen/ZenoQPL1/crates/zeno-evm/src/lib.rs)
- [`zeno-state`](/Users/charliecohen/ZenoQPL1/crates/zeno-state/src/lib.rs)
- [`zeno-storage`](/Users/charliecohen/ZenoQPL1/crates/zeno-storage/src/lib.rs)

Target upgrades:

- move from account snapshot commitment to proof-capable commitments
- maintain isolated speculative views for proposal construction
- add deterministic gas, refund, and fee rules
- add staking, treasury, and reward accounting into the state machine
- expose proofs for light clients and sync

### Consensus Plane

The consensus plane is responsible for:

- deterministic proposer schedule
- proposal validation and acceptance rules
- vote validation, replay protection, and aggregation
- quorum certificate construction
- fast-path finality under synchrony
- safe fallback under asynchrony
- validator set updates at deterministic boundaries
- epoch transitions, evidence handling, and slashing hooks
- durable WAL-backed crash recovery

The current engine in [`zeno-consensus`](/Users/charliecohen/ZenoQPL1/crates/zeno-consensus/src/lib.rs) is a simplified BFT path. It is useful as a prototype but not sufficient for a production-grade chain.

Target upgrades:

- lock and unlock rules with durable local lock state
- strict proposal structure validation before vote handling
- proof-driven commit logic instead of message-driven commit logic
- consensus WAL persisted before every externally visible action
- deterministic round and timeout transitions
- evidence of double-signing and conflicting proposals
- finality proofs suitable for light client verification

### Network Plane

The network plane is responsible for:

- mempool propagation and block propagation
- peer identity, authentication, and discovery
- peer scoring, anti-eclipse controls, and ban logic
- request/response sync protocols
- header sync, body sync, state sync, and snapshot sync
- bandwidth shaping, deduplication, and resumable transfer
- transport evaluation for QUIC or equivalent modern protocols
- transaction ordering and anti-spam controls

The current implementation in [`zeno-network`](/Users/charliecohen/ZenoQPL1/crates/zeno-network/src/lib.rs) is a small TCP gossip layer. It should be treated as a functional bootstrap, not the target architecture.

Target upgrades:

- split gossip from sync protocols
- introduce authenticated peer identities
- add per-peer quotas, scoring, and backoff
- support full, fast, snapshot, checkpoint, and light sync modes
- add encrypted mempool and block builder isolation

### Operations Plane

The operations plane is responsible for:

- metrics, tracing, health status, and structured diagnostics
- snapshots, backups, restore verification, and archival workflows
- validator key management and remote signer integration
- HSM/KMS compatibility and key rotation
- upgrade orchestration and rollback control
- release compatibility and safety policy enforcement

This plane is largely absent in the prototype and must be built deliberately rather than bolted onto the runtime later.

Target upgrades:

- explicit ops APIs instead of ad hoc node-local logic
- backup-safe storage snapshots
- validator key isolation from wallet keys
- remote signer and policy-driven signing approvals
- upgrade state compatibility checks

## Cross-Cutting Security Requirements

- cryptographic agility with explicit algorithm identifiers and versioning
- hybrid signature policy support
- anti-downgrade rules for signing and handshake negotiation
- domain separation for every signed transcript
- deterministic serialization audits and compatibility tests
- replay protection across consensus, networking, and wallet flows
- strict validation before state mutation
- persistent safety state before network broadcast or voting

## Commitment Strategy

The current state root is a Merkle root over all accounts in memory. That is deterministic, but it is not proof-capable enough for institutional-grade light clients or sync.

Recommended path: Sparse Merkle Tree.

Reasoning:

- simpler and lower-risk than a Verkle deployment in the near term
- supports efficient membership and non-membership proofs
- fits account/state proof serving and snapshot verification well
- allows later evolution toward richer authenticated data structures

Target commitment split:

- account tree for native chain state
- validator/economics tree for staking state
- receipt and transaction inclusion proofs
- EVM storage commitment strategy aligned with execution requirements

## Delivery Principle

The migration must be incremental. Every phase should preserve deterministic replay, add tests before expanding behavior, and avoid mixing speculative behavior with finalized state transitions.
