# Threat Model

This repository assumes:

- a static validator set known at genesis
- at most `f` Byzantine validators in a `3f + 1` set
- correct canonical serialization on every node
- correct behavior of the liboqs ML-DSA implementation and the `oqs` Rust bindings
- honest persistence and local filesystem integrity on validator hosts

Threats considered:

- malformed transactions and signatures
- replay across chains through explicit `chain_id`
- replay across protocol domains through explicit signing tags
- malformed network payloads and oversized frames
- duplicate votes by validators
- node restart and replay from persisted finalized state

Threats not yet fully mitigated:

- adaptive network partition attacks
- validator key exfiltration and HSM integration gaps
- economic attacks due to missing slashing and staking economics
- advanced mempool DoS hardening
- validator set rotation and governance abuse
