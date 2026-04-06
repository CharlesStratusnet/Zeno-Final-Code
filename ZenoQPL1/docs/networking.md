# Networking

The P2P layer uses TCP with length-delimited canonical binary messages.

## Message Types

- handshake
- transaction gossip
- proposal gossip
- vote gossip
- finalized block propagation
- chain status exchange

## Validation

- inbound frames are bounded by `max_frame_bytes`
- peers must present the same `chain_id`
- malformed payloads fail decode and are rejected
- peers are tracked explicitly so operators can inspect connectivity through RPC

## Devnet Model

The default devnet uses static peers from node configuration. Each validator advertises a stable container hostname in Docker Compose so the network can come up deterministically.
