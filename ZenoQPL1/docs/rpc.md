# RPC

The node exposes JSON-RPC over HTTP.

Supported methods:

- `get_balance`
- `get_nonce`
- `get_block_by_height`
- `get_block_by_hash`
- `get_latest_block`
- `get_tx_status`
- `submit_tx`
- `get_peers`
- `get_validator_set`
- `get_chain_status`
- `eth_chainId`
- `eth_blockNumber`
- `eth_getCode`
- `eth_call`

Requests use the shared `JsonRpcRequest` type with `jsonrpc`, `id`, `method`, and `params`.

`get_chain_status` now includes:

- network name
- ticker
- canonical RPC URLs
- block explorer URL
- explicit compatibility flags for MetaMask and smart contracts

Example:

```json
{
  "jsonrpc": "2.0",
  "id": "4ea54d4a-0f7f-43d7-9b53-2e647809ef50",
  "method": "get_balance",
  "params": "001122..."
}
```
