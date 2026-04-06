# Limitations

- This repository has not been audited.
- Post-quantum resistant does not mean permanently future-proof.
- ML-DSA introduces materially larger keys and signatures than classical schemes.
- Production deployment would still require security audit, formal review, adversarial testing, economic review, and operational hardening.
- The current consensus implementation is deliberately conservative and not optimized for throughput.
- Validator set changes, staking economics, slashing, and governance are not implemented.
- The current networking layer provides bounded decoding and handshake checks, but deeper peer scoring and anti-DoS policy remain future work.
- The chain now includes an embedded EVM execution path and exposes a limited Ethereum-style read RPC surface (`eth_chainId`, `eth_blockNumber`, `eth_getCode`, `eth_call`), but it does not yet expose a full Ethereum write RPC surface.
- Standard MetaMask custom-network compatibility is still not available because user transaction authorization remains ML-DSA based rather than Ethereum `secp256k1`/ECDSA based.
- The MetaMask integration path is currently a scaffolded Snap plus relayer/account-abstraction design, not a finished production wallet integration.
- The current EVM implementation is intentionally narrow: value transfer in EVM transactions is disabled, log indexing is incomplete, and the ML-DSA verifier is exposed as a reserved precompile surface rather than a fully wired contract-to-precompile path.
