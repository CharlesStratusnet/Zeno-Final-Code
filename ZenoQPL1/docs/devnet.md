# Devnet

The repository ships a 4-validator local devnet workflow.

## Fresh Clone Workflow

```bash
export LIBCLANG_PATH=/Library/Developer/CommandLineTools/usr/lib
cargo check --workspace
./scripts/devnet-init.sh
docker compose -f docker/docker-compose.devnet.yml up --build
```

Artifacts created in `./devnet`:

- `genesis.json`
- `faucet.json`
- `node-0/node.toml`
- `node-1/node.toml`
- `node-2/node.toml`
- `node-3/node.toml`
- validator key files for each node

Default network metadata:

- Network name: `Zeno PQ Devnet`
- Chain ID: `zeno-devnet`
- Ticker: `ZPQ`
- EVM chain ID: `424242`
- Explorer URL: `http://127.0.0.1:8000/explorer`
- MetaMask Snap ID: `local:http://127.0.0.1:8081/zeno-pq-snap`

## Operational Notes

- Docker named volumes preserve node data between restarts.
- `zeno-cli node status --rpc 127.0.0.1:8000` shows current finalized height and peers.
- Wallet operations are CLI-based and use ML-DSA keys only.
- Solidity-compatible execution is available through the embedded EVM path and CLI transaction builders.
- Standard MetaMask "Add network" support is intentionally unavailable; the compatibility path is the Snap flow documented in `docs/metamask_snap.md`.
