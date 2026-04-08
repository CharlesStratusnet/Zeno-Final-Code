//! JSON-RPC server with full Ethereum/MetaMask compatibility.

mod pages;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use parking_lot::Mutex;
use serde_json::json;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use zeno_types::{
    Address, ChainStatus, EvmAddress, EvmCallRequest, EvmCallResult, EvmLogFilter,
    FinalizedBlock, JsonRpcError, JsonRpcRequest, JsonRpcResponse, Receipt, Transaction,
    TransactionStatus, Validator,
};

/// Trait implemented by node state for RPC access.
#[async_trait]
pub trait RpcProvider: Send + Sync + 'static {
    // -- Zeno native methods --
    /// Returns account balance.
    async fn get_balance(&self, address: Address) -> Result<u128>;
    /// Returns account nonce.
    async fn get_nonce(&self, address: Address) -> Result<u64>;
    /// Returns block by height.
    async fn get_block_by_height(&self, height: u64) -> Result<Option<FinalizedBlock>>;
    /// Returns block by hash.
    async fn get_block_by_hash(&self, hash: zeno_hash::Hash32) -> Result<Option<FinalizedBlock>>;
    /// Returns the latest block.
    async fn get_latest_block(&self) -> Result<Option<FinalizedBlock>>;
    /// Returns transaction status.
    async fn get_tx_status(&self, hash: zeno_hash::Hash32) -> Result<TransactionStatus>;
    /// Submits a transaction.
    async fn submit_tx(&self, tx: Transaction) -> Result<zeno_hash::Hash32>;
    /// Returns peer list.
    async fn get_peers(&self) -> Result<Vec<String>>;
    /// Returns validators.
    async fn get_validator_set(&self) -> Result<Vec<Validator>>;
    /// Returns chain status.
    async fn get_chain_status(&self) -> Result<ChainStatus>;

    // -- Ethereum JSON-RPC methods for MetaMask --
    /// Returns the EVM chain id if configured.
    async fn eth_chain_id(&self) -> Result<Option<u64>>;
    /// Returns the latest block number.
    async fn eth_block_number(&self) -> Result<u64>;
    /// Returns runtime bytecode for an EVM address.
    async fn eth_get_code(&self, address: EvmAddress) -> Result<Vec<u8>>;
    /// Executes a read-only EVM call.
    async fn eth_call(&self, request: EvmCallRequest) -> Result<Vec<u8>>;
    /// Returns the EVM balance for an address.
    async fn eth_get_balance(&self, address: EvmAddress) -> Result<u128>;
    /// Returns the EVM transaction count for an address.
    async fn eth_get_transaction_count(&self, address: EvmAddress) -> Result<u64>;
    /// Returns the transaction receipt by hash.
    async fn eth_get_transaction_receipt(&self, hash: zeno_hash::Hash32) -> Result<Option<Receipt>>;
    /// Returns matching EVM logs.
    async fn eth_get_logs(&self, filter: EvmLogFilter) -> Result<Vec<zeno_types::EvmLog>>;
    /// Estimates gas for an EVM call.
    async fn eth_estimate_gas(&self, request: EvmCallRequest) -> Result<u64>;
    /// Returns the current gas price.
    async fn eth_gas_price(&self) -> Result<u128>;
    /// Sends a raw ECDSA-signed Ethereum transaction.
    async fn eth_send_raw_transaction(&self, raw_hex: String) -> Result<zeno_hash::Hash32>;
    // -- Dynamic validator set --
    /// Registers a new validator.
    async fn register_validator(&self, request: zeno_types::ValidatorJoinRequest) -> Result<()>;
    // -- Explorer, staking, faucet, governance methods --
    /// Returns recent blocks (up to `count` from the tip).
    async fn get_recent_blocks(&self, count: u64) -> Result<Vec<FinalizedBlock>>;
    /// Returns staking state.
    async fn get_staking_state(&self) -> Result<zeno_types::StakingState>;
    /// Returns governance state.
    async fn get_governance_state(&self) -> Result<zeno_types::GovernanceState>;
    /// Sends faucet tokens to an address.
    async fn faucet_send(&self, recipient: Address, amount: u128) -> Result<()>;
    // -- Zero-knowledge proof methods --
    /// Shields value into the private pool.
    async fn zk_shield(&self, request: zeno_zk::ShieldRequest) -> Result<u64>;
    /// Unshields value from the private pool.
    async fn zk_unshield(&self, request: zeno_zk::UnshieldRequest) -> Result<()>;
    /// Returns the shielded pool state (root, commitment count, nullifier count).
    async fn zk_pool_info(&self) -> Result<serde_json::Value>;
    /// Returns Prometheus metrics text.
    async fn metrics(&self) -> Result<String>;
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// Rate limiter for RPC requests.
pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
    max_rps: f64,
    burst: f64,
}

impl RateLimiter {
    /// Creates a new rate limiter.
    pub fn new(max_rps: u32, burst: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            max_rps: max_rps as f64,
            burst: burst as f64,
        }
    }

    /// Returns `true` if the request is allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock();
        let now = Instant::now();
        let bucket = buckets.entry(ip).or_insert(TokenBucket {
            tokens: self.burst,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.max_rps).min(self.burst);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
struct RpcState {
    provider: Arc<dyn RpcProvider>,
    rate_limiter: Arc<RateLimiter>,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Runs the JSON-RPC server.
pub async fn serve(listen: SocketAddr, provider: Arc<dyn RpcProvider>) -> Result<()> {
    let state = RpcState {
        provider,
        rate_limiter: Arc::new(RateLimiter::new(100, 200)),
    };
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(tower_http::cors::Any)
        .max_age(std::time::Duration::from_secs(86400));
    let app = Router::new()
        .route("/", get(handle_explorer).post(handle_rpc))
        .route("/explorer", get(handle_explorer))
        .route("/explorer/block/{height}", get(handle_block_page))
        .route("/explorer/tx/{hash}", get(handle_tx_page))
        .route("/explorer/address/{address}", get(handle_address_page))
        .route("/staking", get(handle_staking_page))
        .route("/governance", get(handle_governance_page))
        .route("/faucet", get(handle_faucet_page))
        .route("/health", get(handle_health))
        .route("/metrics", get(handle_metrics))
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_health(State(state): State<RpcState>) -> impl IntoResponse {
    let height = state
        .provider
        .get_latest_block()
        .await
        .ok()
        .flatten()
        .map(|block| block.block.header.height)
        .unwrap_or(0);
    Json(json!({ "status": "ok", "height": height }))
}

async fn handle_metrics(State(state): State<RpcState>) -> impl IntoResponse {
    match state.provider.metrics().await {
        Ok(body) => (
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            body,
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            String::new(),
        ),
    }
}

async fn handle_explorer(State(state): State<RpcState>) -> impl IntoResponse {
    let chain_id = state.provider.eth_chain_id().await.ok().flatten().unwrap_or(0);
    let status = state.provider.get_chain_status().await.ok();
    let peers = status.as_ref().map(|s| s.peers.len()).unwrap_or(0);
    let ticker = status.as_ref().map(|s| s.metadata.ticker.clone()).unwrap_or_else(|| "ZPQ".to_string());
    let blocks = state.provider.get_recent_blocks(20).await.unwrap_or_default();
    let height = blocks.first().map(|b| b.block.header.height).unwrap_or(0);
    let block_data: Vec<(u64, String, u64, usize, String)> = blocks
        .iter()
        .map(|b| {
            let h = &b.block.header;
            (h.height, b.block.hash().to_string(), h.timestamp_ms, b.block.transactions.len(), h.proposer.to_string())
        })
        .collect();
    Html(pages::explorer_page(height, chain_id, peers, &ticker, &block_data))
}

async fn handle_block_page(
    State(state): State<RpcState>,
    axum::extract::Path(height): axum::extract::Path<u64>,
) -> impl IntoResponse {
    match state.provider.get_block_by_height(height).await {
        Ok(Some(block)) => {
            let h = &block.block.header;
            let txs: Vec<(String, String, String, u128, u128)> = block.block.transactions.iter().map(|tx| {
                (tx.id().to_string(), tx.body.sender.to_string(), tx.body.recipient.to_string(), tx.body.amount, tx.body.fee)
            }).collect();
            Html(pages::block_page(
                h.height, &block.block.hash().to_string(), &h.parent_hash.to_string(),
                &h.state_root.to_string(), &h.tx_root.to_string(), &h.receipt_root.to_string(),
                &h.proposer.to_string(), h.timestamp_ms, block.block.transactions.len(), &txs,
            ))
        }
        _ => Html(pages::page("Not Found", "explorer", "<div class=\"hero\"><h1>Block Not Found</h1></div>")),
    }
}

async fn handle_tx_page(
    State(state): State<RpcState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> impl IntoResponse {
    let hash_str = hash.strip_prefix("0x").unwrap_or(&hash);
    let parsed = hex::decode(hash_str).ok().and_then(|b| {
        if b.len() == 32 { let mut h = [0u8;32]; h.copy_from_slice(&b); Some(zeno_hash::Hash32(h)) } else { None }
    });
    let Some(parsed) = parsed else {
        return Html(pages::page("Not Found", "explorer", "<div class=\"hero\"><h1>Invalid Hash</h1></div>"));
    };
    match state.provider.get_tx_status(parsed).await {
        Ok(TransactionStatus::Finalized(receipt)) => {
            let (from, to, amount, fee, nonce) = state.provider.get_block_by_height(receipt.height).await.ok().flatten()
                .and_then(|b| b.block.transactions.iter().find(|tx| tx.id() == parsed).map(|tx| {
                    (tx.body.sender.to_string(), tx.body.recipient.to_string(), tx.body.amount, tx.body.fee, tx.body.nonce)
                }))
                .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string(), 0, 0, 0));
            let status = match receipt.outcome { zeno_types::ExecutionOutcome::Success => "Success", _ => "Failed" };
            Html(pages::tx_page(&hash, receipt.height, &from, &to, amount, fee, nonce, status))
        }
        _ => Html(pages::page("Not Found", "explorer", "<div class=\"hero\"><h1>Transaction Not Found</h1></div>")),
    }
}

async fn handle_address_page(
    State(state): State<RpcState>,
    axum::extract::Path(address): axum::extract::Path<String>,
) -> impl IntoResponse {
    let addr_str = address.strip_prefix("0x").unwrap_or(&address);
    // Try as 20-byte EVM address first, then 32-byte native.
    let (balance, nonce) = if addr_str.len() == 40 {
        if let Ok(addr) = parse_hex_address(&json!(format!("0x{addr_str}"))) {
            let b = state.provider.eth_get_balance(addr).await.unwrap_or(0);
            let n = state.provider.eth_get_transaction_count(addr).await.unwrap_or(0);
            (b, n)
        } else { (0, 0) }
    } else if addr_str.len() == 64 {
        if let Ok(bytes) = hex::decode(addr_str) {
            let mut a = [0u8;32]; a.copy_from_slice(&bytes);
            let b = state.provider.get_balance(Address(a)).await.unwrap_or(0);
            let n = state.provider.get_nonce(Address(a)).await.unwrap_or(0);
            (b, n)
        } else { (0, 0) }
    } else { (0, 0) };
    Html(pages::address_page(&address, balance, nonce))
}

async fn handle_staking_page(State(state): State<RpcState>) -> impl IntoResponse {
    let staking = state.provider.get_staking_state().await.unwrap_or_default();
    let validators: Vec<(String, u128, u128, u16, String)> = staking.validators.values().map(|v| {
        let status = match v.status {
            zeno_types::ValidatorStatus::Active => "Active",
            zeno_types::ValidatorStatus::Jailed => "Jailed",
            zeno_types::ValidatorStatus::Inactive => "Inactive",
        };
        (v.validator_address.to_string(), v.self_bond, v.total_stake, v.commission_bps, status.to_string())
    }).collect();
    Html(pages::staking_page(staking.epoch, staking.treasury_balance, &validators))
}

async fn handle_governance_page(State(state): State<RpcState>) -> impl IntoResponse {
    let gov = state.provider.get_governance_state().await;
    match gov {
        Ok(g) => {
            let pending: Vec<(u64, u64, String)> = g.pending.iter().map(|p| (p.proposal_id, p.activation_epoch, p.description.clone())).collect();
            Html(pages::governance_page(g.next_proposal_id, g.economics.treasury_bps, g.economics.epoch_length, g.economics.minimum_self_bond, &pending))
        }
        Err(_) => Html(pages::page("Governance", "governance", "<div class=\"hero\"><h1>Governance Unavailable</h1></div>")),
    }
}

async fn handle_faucet_page(State(_state): State<RpcState>) -> impl IntoResponse {
    Html(pages::faucet_page())
}

async fn handle_rpc(
    State(state): State<RpcState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Rate limit by X-Forwarded-For or fallback to 127.0.0.1.
    let ip: IpAddr = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    if !state.rate_limiter.check(ip) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"jsonrpc":"2.0","id":null,"error":{"code":-32005,"message":"rate limit exceeded"}})));
    }

    // Try parsing as a JSON value first to detect batch vs single.
    let raw: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::OK, Json(json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":format!("parse error: {e}")}}))),
    };

    if let serde_json::Value::Array(batch) = raw {
        // Batch request — process each and return array of responses.
        let mut responses = Vec::with_capacity(batch.len());
        for item in batch {
            let resp = process_single_request(Arc::clone(&state.provider), item).await;
            responses.push(resp);
        }
        (StatusCode::OK, Json(json!(responses)))
    } else {
        // Single request.
        let resp = process_single_request(Arc::clone(&state.provider), raw).await;
        (StatusCode::OK, Json(resp))
    }
}

async fn process_single_request(
    provider: Arc<dyn RpcProvider>,
    raw: serde_json::Value,
) -> serde_json::Value {
    let request: JsonRpcRequest = match serde_json::from_value(raw) {
        Ok(r) => r,
        Err(e) => return json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":format!("invalid request: {e}")}}),
    };
    let id = request.id.clone();
    match dispatch(provider, request).await {
        Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
        Err(err) => json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":err.to_string()}}),
    }
}

// ---------------------------------------------------------------------------
// Ethereum-format param helpers
// ---------------------------------------------------------------------------

/// Parses a 0x-prefixed hex address from a JSON value.
fn parse_hex_address(val: &serde_json::Value) -> Result<EvmAddress> {
    let s = val.as_str().ok_or_else(|| anyhow!("expected hex address string"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| anyhow!("invalid hex address: {e}"))?;
    if bytes.len() != 20 {
        return Err(anyhow!("address must be 20 bytes, got {}", bytes.len()));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(EvmAddress(addr))
}

/// Parses a 0x-prefixed hex hash from a JSON value.
fn parse_hex_hash(val: &serde_json::Value) -> Result<zeno_hash::Hash32> {
    let s = val.as_str().ok_or_else(|| anyhow!("expected hex hash string"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| anyhow!("invalid hex hash: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("hash must be 32 bytes, got {}", bytes.len()));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(zeno_hash::Hash32(hash))
}

/// Parses a block number from "latest", "earliest", "pending", or hex number.
fn parse_block_number(val: &serde_json::Value, latest: u64) -> u64 {
    match val.as_str() {
        Some("latest") | Some("pending") | None => latest,
        Some("earliest") => 0,
        Some(s) => {
            let s = s.strip_prefix("0x").unwrap_or(s);
            u64::from_str_radix(s, 16).unwrap_or(latest)
        }
    }
}

/// Extracts element at index from a JSON array, or returns the value itself.
fn param_at(params: &serde_json::Value, index: usize) -> Option<&serde_json::Value> {
    match params {
        serde_json::Value::Array(arr) => arr.get(index),
        other if index == 0 => Some(other),
        _ => None,
    }
}

/// Formats a Zeno FinalizedBlock as an Ethereum-compatible block JSON object.
fn format_eth_block(block: &FinalizedBlock, full_txs: bool) -> serde_json::Value {
    let h = &block.block.header;
    let block_hash = format!("0x{}", block.block.hash());
    let txs: serde_json::Value = if full_txs {
        json!(block.block.transactions.iter().enumerate().map(|(i, tx)| {
            json!({
                "hash": format!("0x{}", tx.id()),
                "blockHash": &block_hash,
                "blockNumber": format!("0x{:x}", h.height),
                "transactionIndex": format!("0x{:x}", i),
                "from": format!("0x{}", hex::encode(&tx.body.sender.0[12..32])),
                "to": format!("0x{}", hex::encode(&tx.body.recipient.0[12..32])),
                "value": format!("0x{:x}", tx.body.amount),
                "gas": "0x5208",
                "gasPrice": "0x0",
                "input": "0x",
                "nonce": format!("0x{:x}", tx.body.nonce),
            })
        }).collect::<Vec<_>>())
    } else {
        json!(block.block.transactions.iter().map(|tx| format!("0x{}", tx.id())).collect::<Vec<_>>())
    };
    json!({
        "number": format!("0x{:x}", h.height),
        "hash": block_hash,
        "parentHash": format!("0x{}", h.parent_hash),
        "nonce": "0x0000000000000000",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "transactionsRoot": format!("0x{}", h.tx_root),
        "stateRoot": format!("0x{}", h.state_root),
        "receiptsRoot": format!("0x{}", h.receipt_root),
        "miner": format!("0x{}", hex::encode(&h.proposer.0[12..32])),
        "difficulty": "0x0",
        "totalDifficulty": "0x0",
        "extraData": "0x",
        "size": "0x100",
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x0",
        "timestamp": format!("0x{:x}", h.timestamp_ms / 1000),
        "transactions": txs,
        "uncles": [],
        "baseFeePerGas": "0x0",
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    })
}

/// Formats a receipt as an Ethereum-compatible receipt JSON object.
fn format_eth_receipt(receipt: &Receipt, block: Option<&FinalizedBlock>) -> serde_json::Value {
    let block_hash = block.map(|b| format!("0x{}", b.block.hash())).unwrap_or_else(|| "0x".repeat(33));
    let block_number = block.map(|b| b.block.header.height).unwrap_or(0);
    let success = matches!(receipt.outcome, zeno_types::ExecutionOutcome::Success);
    let contract_addr = receipt
        .evm
        .as_ref()
        .and_then(|e| e.contract_address.as_ref())
        .map(|a| json!(format!("0x{}", hex::encode(a.0))))
        .unwrap_or(json!(null));
    let logs: Vec<serde_json::Value> = receipt
        .evm
        .as_ref()
        .map(|e| {
            e.logs
                .iter()
                .enumerate()
                .map(|(i, log)| {
                    json!({
                        "address": format!("0x{}", hex::encode(log.address.0)),
                        "topics": log.topics.iter().map(|t| format!("0x{t}")).collect::<Vec<_>>(),
                        "data": format!("0x{}", hex::encode(&log.data)),
                        "blockNumber": format!("0x{block_number:x}"),
                        "blockHash": &block_hash,
                        "transactionHash": format!("0x{}", receipt.tx_hash),
                        "transactionIndex": "0x0",
                        "logIndex": format!("0x{i:x}"),
                        "removed": false,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "transactionHash": format!("0x{}", receipt.tx_hash),
        "blockHash": block_hash,
        "blockNumber": format!("0x{block_number:x}"),
        "transactionIndex": "0x0",
        "from": "0x0000000000000000000000000000000000000000",
        "to": null,
        "contractAddress": contract_addr,
        "cumulativeGasUsed": format!("0x{:x}", receipt.evm.as_ref().map(|e| e.gas_used).unwrap_or(21000)),
        "gasUsed": format!("0x{:x}", receipt.evm.as_ref().map(|e| e.gas_used).unwrap_or(21000)),
        "effectiveGasPrice": "0x0",
        "logs": logs,
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "status": if success { "0x1" } else { "0x0" },
        "type": "0x0",
    })
}

/// Parses an eth_call request from MetaMask-format params.
fn parse_eth_call_request(params: &serde_json::Value) -> Result<EvmCallRequest> {
    let obj = param_at(params, 0).ok_or_else(|| anyhow!("missing call object"))?;
    let to = obj.get("to")
        .and_then(|v| v.as_str())
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s).unwrap_or_default();
            let mut addr = [0u8; 20];
            if bytes.len() == 20 { addr.copy_from_slice(&bytes); }
            addr
        })
        .unwrap_or([0u8; 20]);
    let from = obj.get("from")
        .and_then(|v| v.as_str())
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s).unwrap_or_default();
            let mut addr = [0u8; 20];
            if bytes.len() == 20 { addr.copy_from_slice(&bytes); }
            addr
        });
    let data = obj.get("data")
        .or_else(|| obj.get("input"))
        .and_then(|v| v.as_str())
        .map(|s| hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap_or_default())
        .unwrap_or_default();
    let value = obj.get("value")
        .and_then(|v| v.as_str())
        .and_then(|s| u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok());
    let gas = obj.get("gas")
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok());
    Ok(EvmCallRequest {
        from,
        to: EvmAddress(to),
        data,
        gas_limit: gas,
        value,
    })
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

async fn dispatch(provider: Arc<dyn RpcProvider>, request: JsonRpcRequest) -> Result<serde_json::Value> {
    let latest_height = provider.eth_block_number().await.unwrap_or(0);
    let params = &request.params;

    match request.method.as_str() {
        // -- Zeno native methods --
        "get_balance" => {
            let address: Address = serde_json::from_value(params.clone())?;
            Ok(json!(provider.get_balance(address).await?))
        }
        "get_nonce" => {
            let address: Address = serde_json::from_value(params.clone())?;
            Ok(json!(provider.get_nonce(address).await?))
        }
        "get_block_by_height" => {
            let height: u64 = serde_json::from_value(params.clone())?;
            Ok(json!(provider.get_block_by_height(height).await?))
        }
        "get_block_by_hash" => {
            let hash: zeno_hash::Hash32 = serde_json::from_value(params.clone())?;
            Ok(json!(provider.get_block_by_hash(hash).await?))
        }
        "get_latest_block" => Ok(json!(provider.get_latest_block().await?)),
        "get_tx_status" => {
            let hash: zeno_hash::Hash32 = serde_json::from_value(params.clone())?;
            Ok(json!(provider.get_tx_status(hash).await?))
        }
        "submit_tx" => {
            let tx: Transaction = serde_json::from_value(params.clone())?;
            Ok(json!(provider.submit_tx(tx).await?))
        }
        "get_peers" => Ok(json!(provider.get_peers().await?)),
        "get_validator_set" => Ok(json!(provider.get_validator_set().await?)),
        "get_chain_status" => Ok(json!(provider.get_chain_status().await?)),

        // -- Ethereum JSON-RPC methods (MetaMask compatible) --
        "eth_chainId" => {
            let id = provider.eth_chain_id().await?.unwrap_or(0);
            Ok(json!(format!("0x{id:x}")))
        }
        "net_version" => {
            let id = provider.eth_chain_id().await?.unwrap_or(0);
            Ok(json!(id.to_string()))
        }
        "web3_clientVersion" => {
            Ok(json!("ZenoPQ/0.1.0"))
        }
        "eth_accounts" => {
            Ok(json!([]))
        }
        "eth_syncing" => {
            Ok(json!(false))
        }
        "eth_mining" => {
            Ok(json!(false))
        }
        "eth_hashrate" => {
            Ok(json!("0x0"))
        }
        "eth_protocolVersion" => {
            Ok(json!("0x41"))
        }
        "eth_blockNumber" => {
            Ok(json!(format!("0x{:x}", provider.eth_block_number().await?)))
        }
        "eth_getBalance" => {
            let addr = param_at(params, 0).ok_or_else(|| anyhow!("missing address"))?;
            let address = parse_hex_address(addr)?;
            let balance = provider.eth_get_balance(address).await?;
            Ok(json!(format!("0x{balance:x}")))
        }
        "eth_getTransactionCount" => {
            let addr = param_at(params, 0).ok_or_else(|| anyhow!("missing address"))?;
            let address = parse_hex_address(addr)?;
            let nonce = provider.eth_get_transaction_count(address).await?;
            Ok(json!(format!("0x{nonce:x}")))
        }
        "eth_getCode" => {
            let addr = param_at(params, 0).ok_or_else(|| anyhow!("missing address"))?;
            let address = parse_hex_address(addr)?;
            let code = provider.eth_get_code(address).await?;
            Ok(json!(format!("0x{}", hex::encode(code))))
        }
        "eth_getStorageAt" => {
            // Return zero for now (storage queries not indexed by slot)
            Ok(json!("0x0000000000000000000000000000000000000000000000000000000000000000"))
        }
        "eth_getBlockByNumber" => {
            let latest_tag = json!("latest");
            let block_param = param_at(params, 0).unwrap_or(&latest_tag);
            let full_txs = param_at(params, 1).and_then(|v| v.as_bool()).unwrap_or(false);
            let height = parse_block_number(block_param, latest_height);
            match provider.get_block_by_height(height).await? {
                Some(block) => Ok(format_eth_block(&block, full_txs)),
                None if height == 0 => {
                    // Return a synthetic genesis block
                    Ok(json!({
                        "number": "0x0",
                        "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "nonce": "0x0000000000000000",
                        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                        "logsBloom": format!("0x{}", "0".repeat(512)),
                        "transactionsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "receiptsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "miner": "0x0000000000000000000000000000000000000000",
                        "difficulty": "0x0",
                        "totalDifficulty": "0x0",
                        "extraData": "0x",
                        "size": "0x100",
                        "gasLimit": "0x1c9c380",
                        "gasUsed": "0x0",
                        "timestamp": "0x0",
                        "transactions": [],
                        "uncles": [],
                        "baseFeePerGas": "0x0",
                        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    }))
                }
                None => Ok(json!(null)),
            }
        }
        "eth_getBlockByHash" => {
            let hash_param = param_at(params, 0).ok_or_else(|| anyhow!("missing hash"))?;
            let full_txs = param_at(params, 1).and_then(|v| v.as_bool()).unwrap_or(false);
            let hash = parse_hex_hash(hash_param)?;
            match provider.get_block_by_hash(hash).await? {
                Some(block) => Ok(format_eth_block(&block, full_txs)),
                None => Ok(json!(null)),
            }
        }
        "eth_getTransactionByHash" => {
            let hash_param = param_at(params, 0).ok_or_else(|| anyhow!("missing hash"))?;
            let hash = parse_hex_hash(hash_param)?;
            match provider.get_tx_status(hash).await? {
                TransactionStatus::Finalized(receipt) => {
                    let block = provider.get_block_by_height(receipt.height).await?;
                    Ok(json!({
                        "hash": format!("0x{hash}"),
                        "blockHash": block.as_ref().map(|b| format!("0x{}", b.block.hash())),
                        "blockNumber": format!("0x{:x}", receipt.height),
                        "transactionIndex": "0x0",
                        "from": "0x0000000000000000000000000000000000000000",
                        "to": null,
                        "value": "0x0",
                        "gas": "0x5208",
                        "gasPrice": "0x0",
                        "input": "0x",
                        "nonce": "0x0",
                    }))
                }
                _ => Ok(json!(null)),
            }
        }
        "eth_getTransactionReceipt" => {
            let hash_param = param_at(params, 0).ok_or_else(|| anyhow!("missing hash"))?;
            let hash = parse_hex_hash(hash_param)?;
            match provider.eth_get_transaction_receipt(hash).await? {
                Some(receipt) => {
                    let block = provider.get_block_by_height(receipt.height).await?;
                    Ok(format_eth_receipt(&receipt, block.as_ref()))
                }
                None => Ok(json!(null)),
            }
        }
        "eth_call" => {
            let call_req = parse_eth_call_request(params)?;
            let output = provider.eth_call(call_req).await?;
            Ok(json!(format!("0x{}", hex::encode(output))))
        }
        "eth_estimateGas" => {
            let call_req = parse_eth_call_request(params)?;
            let gas = provider.eth_estimate_gas(call_req).await?;
            Ok(json!(format!("0x{gas:x}")))
        }
        "eth_gasPrice" => {
            let price = provider.eth_gas_price().await?;
            Ok(json!(format!("0x{price:x}")))
        }
        "eth_maxPriorityFeePerGas" => {
            Ok(json!("0x0"))
        }
        "eth_feeHistory" => {
            // Minimal fee history for MetaMask
            Ok(json!({
                "baseFeePerGas": ["0x0", "0x0"],
                "gasUsedRatio": [0.0],
                "oldestBlock": format!("0x{latest_height:x}"),
                "reward": [["0x0"]]
            }))
        }
        "eth_getLogs" => {
            let filter_obj = param_at(params, 0).cloned().unwrap_or(json!({}));
            let from_block = filter_obj.get("fromBlock")
                .map(|v| parse_block_number(v, latest_height));
            let to_block = filter_obj.get("toBlock")
                .map(|v| parse_block_number(v, latest_height));
            let address = filter_obj.get("address")
                .and_then(|v| parse_hex_address(v).ok());
            let filter = EvmLogFilter {
                from_block,
                to_block,
                address,
                topics: Vec::new(),
            };
            let logs = provider.eth_get_logs(filter).await?;
            Ok(json!(logs.iter().map(|log| json!({
                "address": format!("0x{}", hex::encode(log.address.0)),
                "topics": log.topics.iter().map(|t| format!("0x{t}")).collect::<Vec<_>>(),
                "data": format!("0x{}", hex::encode(&log.data)),
            })).collect::<Vec<_>>()))
        }
        "eth_sendRawTransaction" => {
            let raw = param_at(params, 0)
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing raw transaction hex"))?
                .to_string();
            let hash = provider.eth_send_raw_transaction(raw).await?;
            Ok(json!(format!("0x{hash}")))
        }

        "register_validator" => {
            let request: zeno_types::ValidatorJoinRequest = serde_json::from_value(params.clone())?;
            provider.register_validator(request).await?;
            Ok(json!({"status": "ok"}))
        }
        "get_recent_blocks" => {
            let count = param_at(params, 0).and_then(|v| v.as_u64()).unwrap_or(10);
            let blocks = provider.get_recent_blocks(count).await?;
            Ok(json!(blocks))
        }
        "get_staking_state" => {
            Ok(json!(provider.get_staking_state().await?))
        }
        "get_governance_state" => {
            Ok(json!(provider.get_governance_state().await?))
        }
        "faucet_send" => {
            let addr_str = param_at(params, 0).and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing address"))?;
            let addr_hex = addr_str.strip_prefix("0x").unwrap_or(addr_str);
            // Support both 20-byte and 32-byte addresses.
            let address = if addr_hex.len() == 40 {
                let bytes = hex::decode(addr_hex)?;
                let mut addr = [0u8; 32];
                addr[12..32].copy_from_slice(&bytes);
                Address(addr)
            } else if addr_hex.len() == 64 {
                let bytes = hex::decode(addr_hex)?;
                let mut addr = [0u8; 32];
                addr.copy_from_slice(&bytes);
                Address(addr)
            } else {
                return Err(anyhow!("invalid address length"));
            };
            let amount: u128 = param_at(params, 1)
                .and_then(|v| v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64().map(|n| n as u128)))
                .unwrap_or(1_000_000_000_000_000_000);
            provider.faucet_send(address, amount).await?;
            Ok(json!({"status": "ok", "amount": amount}))
        }

        "zk_shield" => {
            let request: zeno_zk::ShieldRequest = serde_json::from_value(params.clone())?;
            let index = provider.zk_shield(request).await?;
            Ok(json!({"index": index}))
        }
        "zk_unshield" => {
            let request: zeno_zk::UnshieldRequest = serde_json::from_value(params.clone())?;
            provider.zk_unshield(request).await?;
            Ok(json!({"status": "ok"}))
        }
        "zk_pool_info" => {
            Ok(provider.zk_pool_info().await?)
        }

        other => Err(anyhow!("unknown method: {other}")),
    }
}
