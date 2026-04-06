# Rebuild Roadmap

This roadmap turns the target architecture into a delivery sequence that can be implemented safely.

## Phase 1: Runtime Separation

- split the node into execution, consensus, network, and operations planes
- stop coupling runtime startup directly to protocol logic
- define explicit ownership boundaries and APIs between planes
- preserve current semantics while improving structure

## Phase 2: Deterministic Execution Hardening

- separate speculative execution from finalized execution
- introduce proof-capable state commitments using a Sparse Merkle Tree
- add deterministic fee accounting for native transfers and EVM paths
- make receipts, state roots, and execution metadata audit-friendly
- add execution replay and cross-version compatibility tests

## Phase 3: Consensus Redesign

- add consensus WAL and crash recovery
- persist every local safety step before acting on it
- introduce deterministic proposer schedule and round transitions
- enforce strict proposal validity and vote replay protection
- implement quorum certificate handling and proof-driven commit
- add epoch boundaries, validator set updates, and evidence plumbing
- support fast-path under synchrony and safe fallback under asynchrony

## Phase 4: Validator Economics

- implement staking, delegation, commission, self-bond, and jail state
- introduce unbonding windows and deterministic epoch accounting
- add reward, fee, and treasury distribution
- add slashing for equivocation and downtime
- wire evidence outcomes into economics state transitions

## Phase 5: Networking and Sync

- separate gossip, sync, and control protocols
- implement authenticated peer identities and peer discovery
- add peer scoring, anti-eclipse protections, and rate limits
- add full sync, fast sync, snapshot sync, checkpoint sync, and light mode
- implement resumable transfer and proof-serving paths
- evaluate QUIC or equivalent modern transport

## Phase 6: Cryptographic Agility

- version signing algorithms explicitly
- support hybrid signature modes and downgrade resistance
- introduce validator key rotation and revocation
- separate wallet keys from validator signing keys
- support remote signers and HSM/KMS-backed flows
- benchmark signature size and verification cost at validator scale

## Phase 7: Operations Plane

- add metrics and tracing surfaces per plane
- add snapshot, restore, and backup workflows
- add upgrade orchestration and compatibility checks
- define institutional runbooks and failure-mode drills

## Required Safety Harnesses

- deterministic state machine tests per consensus stage
- Byzantine and partial synchrony simulation harness
- equivocation and conflicting proposal tests
- crash recovery tests with WAL replay
- state commitment proof tests
- serialization audit fixtures
- sync corruption and adversarial peer tests

## Immediate Next Slice

The current repository now starts Phase 1:

- node runtime split into explicit planes
- architecture and migration path documented
- semantics preserved while the internals are prepared for deeper protocol work
