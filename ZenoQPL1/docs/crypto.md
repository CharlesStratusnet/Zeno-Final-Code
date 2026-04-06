# Cryptography

All protocol signing uses ML-DSA through the `zeno-crypto` abstraction layer.

## Backend

- The implementation uses the `oqs` Rust crate backed by liboqs.
- The default parameter set is `MlDsa65`.
- The code does not silently fall back to ECDSA, Ed25519, secp256k1, RSA, or any other classical signature scheme.

## Domains

The chain uses explicit signing domains:

- `zeno.tx.v1`
- `zeno.block_proposal.v1`
- `zeno.consensus_vote.v1`

The signable bytes are `domain || 0xff || canonical_message`.

## Key Handling

- Secret keys are wrapped in a zeroizing container where practical.
- Public keys and signatures are length-checked strictly against the selected scheme metadata.
- Addresses are derived from a hash commitment over the public key under a dedicated derivation tag.

## Notes

The underlying library currently exposes both Dilithium-family and ML-DSA identifiers. This repository uses the ML-DSA family names and maps directly to the liboqs-supported algorithms.

Post-quantum resistant does not mean permanently future-proof. Security depends on the current standardization status of ML-DSA, the correctness of the implementation, and the continued strength of the underlying hardness assumptions.
