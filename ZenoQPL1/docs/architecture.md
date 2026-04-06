# Architecture

The workspace is split into crates so the protocol surface is explicit:

- `zeno-codec`: canonical bincode encoding
- `zeno-hash`: Blake3 hashing and Merkle roots
- `zeno-crypto`: ML-DSA signing abstraction and liboqs-backed implementation
- `zeno-types`: shared wire and storage types
- `zeno-primitives`: canonical signable bytes and protocol helpers
- `zeno-storage`: `ChainStore` with RocksDB and in-memory backends
- `zeno-state`: deterministic account snapshot and state root logic
- `zeno-execution`: transaction validation and block execution
- `zeno-evm`: embedded EVM execution, contract state storage, and ML-DSA verification precompile surface
- `zeno-mempool`: fee-ordered pending transaction pool
- `zeno-network`: TCP P2P transport with bounded frames and handshake checks
- `zeno-consensus`: validator BFT flow with proposal, prevote, and precommit
- `zeno-rpc`: JSON-RPC server
- `zeno-node`: runtime composition
- `zeno-wallet`: wallet key and signing helpers
- `zeno-cli`: operator and wallet CLI
- `zeno-genesis`: devnet and genesis generation
- `zeno-test-utils` and `integration-tests`: shared testing utilities and integration coverage
- `benchmarks`: Criterion benchmark harness

The execution model is account-based. Transactions carry `chain_id`, `nonce`, `fee`, optional memo, and optional `valid_until` height. All signable payloads use canonical binary serialization, and the signing domain is explicit so transaction, proposal, and consensus vote signatures cannot be replayed across contexts.

Persistence is abstracted behind `ChainStore`. The state root is a deterministic Merkle-style commitment over sorted account records. Finalized blocks store their header, transactions, receipts, and commit certificate.

The base chain remains account-based and ML-DSA authenticated. EVM execution is an embedded execution subsystem rather than the canonical account/authentication model. That means Solidity contracts can run, but user authorization still flows through post-quantum transaction signatures instead of Ethereum account signatures. The intended wallet architecture for contract interaction is a MetaMask Snap plus relayer/account-abstraction flow.
