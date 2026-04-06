# Zeno PQ Chain

Zeno PQ Chain is a production-intent Layer 1 blockchain monorepo in Rust with:

- account-based execution
- ML-DSA-based transaction, proposal, and vote signing
- deterministic state transitions
- validator BFT consensus with prevote and precommit phases
- TCP peer-to-peer networking with static-peer devnet support
- RocksDB-backed persistence with an in-memory backend for tests
- JSON-RPC
- CLI-based node and wallet tooling

The repository is modular by crate so cryptography, consensus, state transition, networking, RPC, and operations can be reviewed independently.

## Network Metadata

- Network name: `Zeno PQ Devnet`
- Chain ID: `zeno-devnet`
- Ticker: `ZPQ`
- Primary RPC URL: `http://127.0.0.1:8000`
- Additional RPC URLs: `http://127.0.0.1:8001`, `http://127.0.0.1:8002`, `http://127.0.0.1:8003`
- Block explorer URL: `http://127.0.0.1:8000/explorer`
- EVM chain ID: `424242`
- MetaMask Snap ID: `local:http://127.0.0.1:8081/zeno-pq-snap`

Solidity-compatible EVM execution is now present, and Ethereum-style read RPC methods are exposed for `eth_chainId`, `eth_blockNumber`, `eth_getCode`, and `eth_call`.

Standard MetaMask add-network compatibility is still not available because user authorization remains ML-DSA-based rather than Ethereum ECDSA. The intended wallet path is a MetaMask Snap plus relayer/account-abstraction flow. See [docs/metamask_snap.md](/Users/charliecohen/ZenoQPL1/docs/metamask_snap.md).

## Build

```bash
cargo check --workspace
cargo test --workspace
```

On macOS with Apple Command Line Tools, set:

```bash
export LIBCLANG_PATH=/Library/Developer/CommandLineTools/usr/lib
```

before building so `rocksdb` can load `libclang`.

## Devnet

1. Generate a fresh 4-validator network:

```bash
./scripts/devnet-init.sh
```

2. Launch the validators:

```bash
docker compose -f docker/docker-compose.devnet.yml up --build
```

3. Query node status:

```bash
cargo run --bin zeno-cli -- node status --rpc 127.0.0.1:8000
```

4. Inspect the faucet address generated during devnet init:

```bash
cargo run --bin zeno-cli -- wallet show-address --key ./devnet/faucet.json
```

5. Create a wallet:

```bash
cargo run --bin zeno-cli -- wallet generate --output ./devnet/user1.json
```

6. Check balance:

```bash
cargo run --bin zeno-cli -- wallet balance --rpc 127.0.0.1:8000 --address <hex-address>
```

7. Build and sign a transfer:

```bash
cargo run --bin zeno-cli -- wallet build-tx \
  --key ./devnet/faucet.json \
  --chain-id zeno-devnet \
  --recipient <recipient-hex-address> \
  --amount 1000 \
  --nonce 0 \
  --fee 1 \
  --valid-until 100 \
  --output ./devnet/tx.json
```

8. Submit the transaction:

```bash
cargo run --bin zeno-cli -- wallet submit-tx --rpc 127.0.0.1:8000 --tx ./devnet/tx.json
```

9. Query transaction status:

```bash
cargo run --bin zeno-cli -- wallet tx-status --rpc 127.0.0.1:8000 --hash <tx-hash>
```

10. Stop and restart the validators:

```bash
docker compose -f docker/docker-compose.devnet.yml down
docker compose -f docker/docker-compose.devnet.yml up --build
```

The validator data directories are persisted in named Docker volumes so finalized state survives container restarts.

## Documents

- `docs/architecture.md`
- `docs/consensus.md`
- `docs/crypto.md`
- `docs/state.md`
- `docs/networking.md`
- `docs/rpc.md`
- `docs/devnet.md`
- `docs/threat_model.md`
- `docs/limitations.md`
- `docs/target_architecture.md`
- `docs/rebuild_roadmap.md`
