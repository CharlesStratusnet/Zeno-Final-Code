# Consensus

The chain uses a static-validator BFT design with deterministic finality.

## Flow

1. Proposer selection is deterministic by `(height + round) % validator_count`.
2. The proposer builds a block from the mempool and signs the block header with ML-DSA.
3. Validators verify the proposal and emit a prevote for the block hash.
4. When a node observes quorum prevotes, it emits a precommit.
5. When a node observes quorum precommits, it finalizes the block and persists the commit certificate.

## Properties

- Finality is deterministic once quorum precommits are observed.
- Votes are domain-separated from transactions and proposals.
- Duplicate vote detection is tracked as evidence for future slashing and accountability work.
- Consensus progress is persisted as a `(height, round)` snapshot so a node can restart from the latest finalized state.

## Current Limitations

- The current implementation favors correctness and auditability over pipelining or aggressive liveness optimizations.
- Timeout handling advances rounds, but locking and full Tendermint-style polka behavior are intentionally not yet implemented.
- Validator set changes and slashing economics are not implemented in this version.
