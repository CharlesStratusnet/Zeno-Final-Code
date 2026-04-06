# MetaMask Snap Integration

Zeno PQ Chain can expose Solidity-compatible EVM execution while keeping ML-DSA as the transaction authorization primitive. That means MetaMask integration must use a Snap-based flow instead of standard Ethereum account signing.

## Why a Snap Is Required

- Standard MetaMask custom-network support assumes Ethereum account signing.
- Zeno keeps ML-DSA for user authorization.
- The Snap acts as the PQ wallet and signs intents or relayer payloads.

## Current Scaffold

The repository includes a scaffold at `snaps/zeno-pq-snap/` with:

- `snap.manifest.json`
- `src/index.ts`
- placeholder RPC methods for compatibility inspection and ML-DSA signing

## Intended Flow

1. The user connects through a dapp aware of the Zeno Snap.
2. The Snap manages or imports an ML-DSA keypair.
3. The dapp produces a relayed/account-abstraction payload for the chain.
4. The Snap signs the payload with ML-DSA.
5. A relayer submits the signed payload to the chain.
6. The chain executes the EVM transaction after ML-DSA authorization is verified.

## Current Scope

This scaffold does not yet implement:

- production Snap bundling
- secure key import/export UX
- relayer transport
- full account-abstraction contracts
- automatic dapp injection helpers
