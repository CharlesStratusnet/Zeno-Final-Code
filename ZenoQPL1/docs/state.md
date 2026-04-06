# State

State is an account map keyed by 32-byte addresses.

Each account stores:

- `nonce`
- `balance`

## Transaction Rules

- `amount > 0`
- `fee > 0`
- `chain_id` must match local chain configuration
- `memo` must respect the configured maximum size
- `valid_until` must not be expired
- sender address must match the ML-DSA public key
- signature must verify under the transaction domain
- nonce must match the current account nonce
- balance must cover `amount + fee`

## Execution

Execution is deterministic:

1. Verify the block proposal signature.
2. Re-execute transactions in block order.
3. Deduct amount and fee from the sender.
4. Increment sender nonce.
5. Credit the recipient amount.
6. Credit proposer fees after all transaction applications succeed.
7. Verify the transaction root, receipt root, and state root.

Receipts are stored per transaction hash and returned through RPC.
