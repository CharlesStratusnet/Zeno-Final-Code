use std::{
    collections::VecDeque,
    fs,
    net::SocketAddr,
    path::Path,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::time::{interval, Duration, MissedTickBehavior};
use tracing::info;
use zeno_config::NodeConfig;
use zeno_crypto::default_scheme;
use zeno_genesis::load_genesis;
use zeno_mempool::Mempool;
use zeno_rpc::RpcProvider;
use zeno_state::{GovernanceSnapshot, StakingSnapshot};
use zeno_storage::{MemoryStore, RocksStore, SharedStore};
use zeno_types::{
    Address, BlockHeader, ChainStatus, EvmAddress, EvmCallRequest, EvmCallResult, EvmLogFilter,
    FinalizedBlock, Genesis, NetworkMessage, Receipt, SyncRequest, SyncResponse, Transaction,
    TransactionStatus, Validator,
};

use crate::{
    consensus_plane::{ConsensusPlane, SharedConsensusPlane},
    execution_plane::{ExecutionPlane, SharedExecutionPlane},
    network_plane::{NetworkPlane, SharedNetworkPlane},
    operations_plane::OperationsPlane,
};

#[derive(Debug, Default)]
struct SyncState {
    active_peer: Option<String>,
    target_height: u64,
    pending_headers: Option<PendingHeadersRequest>,
    pending_block: Option<PendingBlockRequest>,
    queued_heights: VecDeque<u64>,
}

#[derive(Debug, Clone)]
struct PendingHeadersRequest {
    request_id: u64,
    start_height: u64,
    limit: u64,
}

#[derive(Debug, Clone)]
struct PendingBlockRequest {
    request_id: u64,
    height: u64,
}

/// Shared node runtime.
pub struct Node {
    /// Loaded config.
    pub config: NodeConfig,
    /// Loaded genesis.
    pub genesis: Genesis,
    /// Shared store.
    pub store: SharedStore,
    /// Shared mempool.
    pub mempool: Arc<Mempool>,
    /// Network plane.
    pub network_plane: SharedNetworkPlane,
    /// Execution plane.
    pub execution_plane: SharedExecutionPlane,
    /// Operations plane.
    pub operations_plane: OperationsPlane,
    /// Signature scheme.
    pub scheme: Arc<dyn zeno_crypto::SignatureScheme>,
    request_ids: AtomicU64,
    sync_state: Mutex<SyncState>,
}

impl Node {
    /// Creates and initializes a node from disk configuration.
    pub async fn from_paths(config_path: impl AsRef<Path>, genesis_path: impl AsRef<Path>) -> Result<Self> {
        let config = NodeConfig::load(config_path)?;
        let genesis = load_genesis(genesis_path)?;
        Self::new(config, genesis).await
    }

    /// Creates and initializes a node.
    pub async fn new(config: NodeConfig, genesis: Genesis) -> Result<Self> {
        let store = RocksStore::open(&config.storage.data_dir)?;
        bootstrap_genesis(&store, &genesis)?;
        let network_plane = Arc::new(NetworkPlane::start(&config, &store).await?);
        let execution_plane = Arc::new(ExecutionPlane::new(config.chain_id.clone(), &genesis));

        Ok(Self {
            config,
            genesis,
            store,
            mempool: Arc::new(Mempool::new()),
            network_plane,
            execution_plane,
            operations_plane: OperationsPlane::new(),
            scheme: default_scheme(),
            request_ids: AtomicU64::new(1),
            sync_state: Mutex::new(SyncState::default()),
        })
    }

    /// Starts consensus and RPC services.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let consensus_plane = Arc::new(ConsensusPlane::new(
            &self.config,
            &self.genesis,
            Arc::clone(&self.scheme),
            Arc::clone(&self.execution_plane),
            Arc::clone(&self.mempool),
            Arc::clone(&self.store),
            self.network_plane.handle(),
        )?);
        self.run_services(consensus_plane).await
    }

    async fn run_services(self: Arc<Self>, consensus_plane: SharedConsensusPlane) -> Result<()> {
        let rpc_provider: Arc<dyn RpcProvider> = self.clone();
        let rpc_addr = SocketAddr::from_str(&self.config.rpc.listen)
            .with_context(|| format!("invalid rpc address {}", self.config.rpc.listen))?;
        let gossip_task = {
            let this = self.clone();
            let consensus = consensus_plane.engine();
            tokio::spawn(async move {
                let mut inbound = this.network_plane.handle().subscribe();
                loop {
                    match inbound.recv().await {
                        Ok(event) => {
                            match event.message {
                                NetworkMessage::Transaction(tx) => {
                                    let _ = this.mempool.insert(tx);
                                }
                                NetworkMessage::SyncRequest { request_id, request } => {
                                    let response = this.build_sync_response(request)?;
                                    this.network_plane
                                        .handle()
                                        .send_to(event.peer, NetworkMessage::SyncResponse {
                                            request_id,
                                            response,
                                        })
                                        .await?;
                                }
                                NetworkMessage::Ping { nonce } => {
                                    this.network_plane
                                        .handle()
                                        .send_to(event.peer, NetworkMessage::Pong { nonce })
                                        .await?;
                                }
                                NetworkMessage::SyncResponse { request_id, response } => {
                                    this.handle_sync_response(&consensus, event.peer, request_id, response).await?;
                                }
                                NetworkMessage::Handshake(_)
                                | NetworkMessage::Proposal(_)
                                | NetworkMessage::Vote(_)
                                | NetworkMessage::Commit(_)
                                | NetworkMessage::Status(_)
                                | NetworkMessage::Pong { .. } => {}
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(err) => return Err(anyhow!(err)),
                    }
                }
            })
        };
        let status_task = {
            let this = self.clone();
            tokio::spawn(async move {
                let result: Result<()> = async {
                    let mut ticker = interval(Duration::from_secs(5));
                    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
                    loop {
                        ticker.tick().await;
                        let status = this.current_chain_status()?;
                        this.network_plane
                            .handle()
                            .broadcast(NetworkMessage::Status(status))
                            .await?;
                    }
                }
                .await;
                result
            })
        };
        let sync_task = {
            let this = self.clone();
            let consensus = consensus_plane.engine();
            tokio::spawn(async move {
                let result: Result<()> = async {
                    let mut ticker = interval(Duration::from_secs(3));
                    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
                    loop {
                        ticker.tick().await;
                        this.sync_with_best_peer(&consensus).await?;
                    }
                }
                .await;
                result
            })
        };

        let consensus_task = {
            let consensus = consensus_plane.engine();
            tokio::spawn(async move { consensus.run().await })
        };
        let rpc_task = tokio::spawn(async move { zeno_rpc::serve(rpc_addr, rpc_provider).await });

        info!(node_id = %self.config.node_id, "node services started");
        let (gossip_result, status_result, sync_result, consensus_result, rpc_result) =
            tokio::try_join!(gossip_task, status_task, sync_task, consensus_task, rpc_task)
                .map_err(|err| anyhow!(err))?;
        gossip_result?;
        status_result?;
        sync_result?;
        consensus_result?;
        rpc_result?;
        Ok(())
    }

    fn build_sync_response(&self, request: SyncRequest) -> Result<SyncResponse> {
        match request {
            SyncRequest::Headers { start_height, limit } => {
                let limit = limit.clamp(1, 256);
                let mut headers = Vec::new();
                for height in start_height..start_height.saturating_add(limit) {
                    let Some(block) = self.store.get_block_by_height(height)? else {
                        break;
                    };
                    headers.push(block.block.header);
                }
                Ok(SyncResponse::Headers { headers })
            }
            SyncRequest::BlockByHeight { height } => Ok(SyncResponse::Block {
                block: self.store.get_block_by_height(height)?,
            }),
            SyncRequest::BlockByHash { hash } => Ok(SyncResponse::Block {
                block: self.store.get_block_by_hash(&hash)?,
            }),
        }
    }

    fn current_chain_status(&self) -> Result<ChainStatus> {
        let latest = self.store.latest_block()?;
        Ok(ChainStatus {
            metadata: self.genesis.metadata.clone(),
            chain_id: self.config.chain_id.clone(),
            latest_height: latest.as_ref().map(|block| block.block.header.height).unwrap_or(0),
            latest_hash: latest.map(|block| block.block.hash()).unwrap_or_default(),
            node_id: self.config.node_id.clone(),
            peers: self.network_plane.peers(),
        })
    }

    async fn handle_sync_response(
        &self,
        consensus: &Arc<zeno_consensus::ConsensusEngine>,
        peer: String,
        request_id: u64,
        response: SyncResponse,
    ) -> Result<()> {
        match response {
            SyncResponse::Headers { headers } => {
                let local_height = self.latest_height()?;
                {
                    let mut sync = self.sync_state.lock().expect("sync lock");
                    if sync.active_peer.as_deref() != Some(peer.as_str()) {
                        return Ok(());
                    }
                    let Some(pending) = sync.pending_headers.take() else {
                        return Ok(());
                    };
                    if pending.request_id != request_id {
                        sync.pending_headers = Some(pending);
                        return Ok(());
                    }
                    let heights = self.validate_header_batch(local_height, &headers, &pending)?;
                    sync.queued_heights.extend(heights);
                }
                self.continue_sync(peer).await?;
            }
            SyncResponse::Block { block } => {
                let expected_height = {
                    let mut sync = self.sync_state.lock().expect("sync lock");
                    if sync.active_peer.as_deref() != Some(peer.as_str()) {
                        return Ok(());
                    }
                    let Some(pending) = sync.pending_block.take() else {
                        return Ok(());
                    };
                    if pending.request_id != request_id {
                        sync.pending_block = Some(pending);
                        return Ok(());
                    }
                    pending.height
                };
                if let Some(block) = block {
                    if block.block.header.height != expected_height {
                        return Ok(());
                    }
                    consensus.import_external_finalized_block(block).await?;
                }
                self.continue_sync(peer).await?;
            }
            SyncResponse::NotFound => {}
        }
        Ok(())
    }

    async fn sync_with_best_peer(&self, _consensus: &Arc<zeno_consensus::ConsensusEngine>) -> Result<()> {
        let local_height = self.latest_height()?;
        let Some((peer, state)) = self
            .network_plane
            .peer_states()
            .into_iter()
            .filter(|(_, state)| state.best_height > local_height)
            .max_by_key(|(_, state)| (state.best_height, state.score))
        else {
            return Ok(());
        };
        {
            let mut sync = self.sync_state.lock().expect("sync lock");
            if sync.active_peer.as_deref() != Some(peer.as_str()) {
                *sync = SyncState {
                    active_peer: Some(peer.clone()),
                    target_height: state.best_height,
                    pending_headers: None,
                    pending_block: None,
                    queued_heights: VecDeque::new(),
                };
            } else {
                sync.target_height = sync.target_height.max(state.best_height);
            }
        }
        self.continue_sync(peer).await
    }

    fn latest_height(&self) -> Result<u64> {
        Ok(self
            .store
            .latest_block()?
            .map(|block| block.block.header.height)
            .unwrap_or(0))
    }

    fn next_request_id(&self) -> u64 {
        self.request_ids.fetch_add(1, Ordering::Relaxed)
    }

    async fn continue_sync(&self, peer: String) -> Result<()> {
        enum NextAction {
            Headers {
                request_id: u64,
                start_height: u64,
                limit: u64,
            },
            Block {
                request_id: u64,
                height: u64,
            },
        }

        let local_height = self.latest_height()?;
        let next = {
            let mut sync = self.sync_state.lock().expect("sync lock");
            if sync.active_peer.as_deref() != Some(peer.as_str()) {
                return Ok(());
            }
            if sync.pending_headers.is_some() || sync.pending_block.is_some() {
                return Ok(());
            }
            if let Some(height) = sync.queued_heights.pop_front() {
                let request_id = self.next_request_id();
                sync.pending_block = Some(PendingBlockRequest { request_id, height });
                Some(NextAction::Block { request_id, height })
            } else if sync.target_height > local_height {
                let request_id = self.next_request_id();
                let start_height = local_height.saturating_add(1);
                let limit = (sync.target_height - local_height).min(32);
                sync.pending_headers = Some(PendingHeadersRequest {
                    request_id,
                    start_height,
                    limit,
                });
                Some(NextAction::Headers {
                    request_id,
                    start_height,
                    limit,
                })
            } else {
                None
            }
        };

        match next {
            Some(NextAction::Headers {
                request_id,
                start_height,
                limit,
            }) => {
                self.network_plane
                    .handle()
                    .request_sync_from(
                        peer,
                        request_id,
                        SyncRequest::Headers { start_height, limit },
                    )
                    .await
            }
            Some(NextAction::Block { request_id, height }) => {
                self.network_plane
                    .handle()
                    .request_sync_from(peer, request_id, SyncRequest::BlockByHeight { height })
                    .await
            }
            None => Ok(()),
        }
    }

    fn validate_header_batch(
        &self,
        local_height: u64,
        headers: &[BlockHeader],
        pending: &PendingHeadersRequest,
    ) -> Result<Vec<u64>> {
        if headers.is_empty() {
            return Ok(Vec::new());
        }
        if headers.len() > pending.limit as usize {
            return Err(anyhow!("sync header response exceeds requested limit"));
        }

        let latest_hash = self
            .store
            .latest_block()?
            .map(|block| block.block.hash())
            .unwrap_or_default();
        let mut expected_height = pending.start_height.max(local_height.saturating_add(1));
        let mut heights = Vec::with_capacity(headers.len());

        let mut prev_hash = latest_hash;
        for (index, header) in headers.iter().enumerate() {
            if header.chain_id != self.config.chain_id {
                return Err(anyhow!("sync header chain id mismatch"));
            }
            if header.height != expected_height {
                return Err(anyhow!("sync header range is not contiguous"));
            }
            if index == 0 && header.parent_hash != latest_hash {
                return Err(anyhow!("sync first header parent hash mismatch"));
            }
            if index > 0 && header.parent_hash != prev_hash {
                return Err(anyhow!("sync header parent hash chain broken at height {}", header.height));
            }
            // Verify timestamp is not in the far future (10 minute tolerance).
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            if header.timestamp_ms > now_ms.saturating_add(600_000) {
                return Err(anyhow!("sync header timestamp too far in future"));
            }
            prev_hash = zeno_hash::hash_bytes(
                zeno_codec::encode(header).map_err(|e| anyhow!("header encode: {e}"))?,
            );
            heights.push(header.height);
            expected_height = expected_height.saturating_add(1);
        }
        Ok(heights)
    }

}

#[async_trait]
impl RpcProvider for Node {
    async fn get_balance(&self, address: Address) -> Result<u128> {
        Ok(self.store.get_account(&address)?.unwrap_or_default().balance)
    }

    async fn get_nonce(&self, address: Address) -> Result<u64> {
        Ok(self.store.get_account(&address)?.unwrap_or_default().nonce)
    }

    async fn get_block_by_height(&self, height: u64) -> Result<Option<FinalizedBlock>> {
        self.store.get_block_by_height(height).map_err(Into::into)
    }

    async fn get_block_by_hash(&self, hash: zeno_hash::Hash32) -> Result<Option<FinalizedBlock>> {
        self.store.get_block_by_hash(&hash).map_err(Into::into)
    }

    async fn get_latest_block(&self) -> Result<Option<FinalizedBlock>> {
        self.store.latest_block().map_err(Into::into)
    }

    async fn get_tx_status(&self, hash: zeno_hash::Hash32) -> Result<TransactionStatus> {
        if let Some(receipt) = self.store.get_receipt(&hash)? {
            return Ok(TransactionStatus::Finalized(receipt));
        }
        if self.mempool.contains(&hash) {
            return Ok(TransactionStatus::Pending);
        }
        Ok(TransactionStatus::Unknown)
    }

    async fn submit_tx(&self, tx: Transaction) -> Result<zeno_hash::Hash32> {
        self.execution_plane
            .validate_transaction(&*self.scheme, &self.store, &tx)?;
        let hash = tx.id();
        self.mempool.insert(tx.clone())?;
        self.network_plane
            .handle()
            .broadcast(zeno_types::NetworkMessage::Transaction(tx))
            .await?;
        Ok(hash)
    }

    async fn get_peers(&self) -> Result<Vec<String>> {
        Ok(self.network_plane.peers())
    }

    async fn get_validator_set(&self) -> Result<Vec<Validator>> {
        Ok(self.genesis.validators.clone())
    }

    async fn get_chain_status(&self) -> Result<ChainStatus> {
        self.current_chain_status()
    }

    async fn eth_chain_id(&self) -> Result<Option<u64>> {
        Ok(self.execution_plane.evm_chain_id())
    }

    async fn eth_block_number(&self) -> Result<u64> {
        Ok(self
            .store
            .latest_block()?
            .map(|block| block.block.header.height)
            .unwrap_or(0))
    }

    async fn eth_get_code(&self, address: EvmAddress) -> Result<Vec<u8>> {
        self.execution_plane.eth_get_code(&self.store, address)
    }

    async fn eth_call(&self, request: EvmCallRequest) -> Result<Vec<u8>> {
        self.execution_plane.eth_call(&self.store, request)
    }

    async fn eth_get_balance(&self, address: EvmAddress) -> Result<u128> {
        // Check EVM account first.
        let evm_balance = self
            .store
            .get_evm_account(&address)?
            .map(|account| account.balance)
            .unwrap_or(0);
        // Also check the native account at the zero-padded 32-byte address.
        // This bridges native ZPQ transfers to MetaMask visibility.
        let mut native_addr = [0u8; 32];
        native_addr[12..32].copy_from_slice(&address.0);
        let native_balance = self
            .store
            .get_account(&Address(native_addr))?
            .map(|account| account.balance)
            .unwrap_or(0);
        Ok(evm_balance.saturating_add(native_balance))
    }

    async fn eth_get_transaction_count(&self, address: EvmAddress) -> Result<u64> {
        Ok(self
            .store
            .get_evm_account(&address)?
            .map(|account| account.nonce)
            .unwrap_or(0))
    }

    async fn eth_get_transaction_receipt(&self, hash: zeno_hash::Hash32) -> Result<Option<Receipt>> {
        Ok(self.store.get_receipt(&hash)?)
    }

    async fn eth_get_logs(&self, filter: EvmLogFilter) -> Result<Vec<zeno_types::EvmLog>> {
        let from = filter.from_block.unwrap_or(0);
        let to = filter.to_block.unwrap_or_else(|| {
            self.store
                .latest_block()
                .ok()
                .flatten()
                .map(|block| block.block.header.height)
                .unwrap_or(0)
        });
        let raw_logs = self.store.get_evm_logs_range(from, to)?;
        let filtered = raw_logs
            .into_iter()
            .map(|(_, log)| log)
            .filter(|log| {
                if let Some(ref addr) = filter.address {
                    if log.address != *addr {
                        return false;
                    }
                }
                for (index, topic_filter) in filter.topics.iter().enumerate() {
                    if let Some(required_topic) = topic_filter {
                        if log.topics.get(index) != Some(required_topic) {
                            return false;
                        }
                    }
                }
                true
            })
            .collect();
        Ok(filtered)
    }

    async fn eth_estimate_gas(&self, request: EvmCallRequest) -> Result<u64> {
        let result = self.execution_plane.eth_call(&self.store, request)?;
        // Return the output length as a rough gas estimate; actual metering is in EVM
        Ok(result.len() as u64 + 21_000)
    }

    async fn eth_gas_price(&self) -> Result<u128> {
        Ok(0)
    }

    async fn eth_send_raw_transaction(&self, raw_hex: String) -> Result<zeno_hash::Hash32> {
        let (tx_hash, _result) = self.execution_plane.execute_raw_eth_tx(&self.store, &raw_hex)?;
        Ok(zeno_hash::Hash32(tx_hash))
    }

    async fn get_recent_blocks(&self, count: u64) -> Result<Vec<FinalizedBlock>> {
        let latest_height = self
            .store
            .latest_block()?
            .map(|b| b.block.header.height)
            .unwrap_or(0);
        let mut blocks = Vec::new();
        let start = latest_height.saturating_sub(count.saturating_sub(1));
        for h in (start..=latest_height).rev() {
            if let Some(block) = self.store.get_block_by_height(h)? {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    async fn get_staking_state(&self) -> Result<zeno_types::StakingState> {
        Ok(self
            .store
            .get_staking_state()?
            .unwrap_or_default())
    }

    async fn get_governance_state(&self) -> Result<zeno_types::GovernanceState> {
        self.store
            .get_governance_state()?
            .ok_or_else(|| anyhow!("governance state not initialized"))
    }

    async fn faucet_send(&self, recipient: Address, amount: u128) -> Result<()> {
        // Rate limit: max 10,000,000 ZPQ per request.
        const MAX_FAUCET_AMOUNT: u128 = 10_000_000;
        if amount > MAX_FAUCET_AMOUNT {
            return Err(anyhow!("faucet maximum is {MAX_FAUCET_AMOUNT} ZPQ per request"));
        }
        if amount == 0 {
            return Err(anyhow!("amount must be greater than 0"));
        }
        // Check faucet balance.
        let faucet_path = std::path::Path::new("./devnet/faucet.json");
        if faucet_path.exists() {
            let faucet_key = load_wallet_key(faucet_path)?;
            let faucet_account = self
                .store
                .get_account(&faucet_key.address)?
                .unwrap_or_default();
            if faucet_account.balance < amount {
                return Err(anyhow!("faucet is empty"));
            }
            // Deduct from faucet.
            let mut updated_faucet = faucet_account;
            updated_faucet.balance = updated_faucet.balance.saturating_sub(amount);
            self.store.put_account(&faucet_key.address, &updated_faucet)?;
        }
        // Credit recipient.
        let mut account = self
            .store
            .get_account(&recipient)?
            .unwrap_or_default();
        account.balance = account.balance.saturating_add(amount);
        self.store.put_account(&recipient, &account)?;
        Ok(())
    }

    async fn metrics(&self) -> Result<String> {
        Ok(crate::operations_plane::encode_metrics())
    }
}

fn bootstrap_genesis(store: &SharedStore, genesis: &Genesis) -> Result<()> {
    if store.get_genesis()?.is_none() {
        store.put_genesis(genesis)?;
        for (address, account) in &genesis.accounts {
            store.put_account(address, account)?;
        }
    }
    let governance = GovernanceSnapshot::load(store, &genesis.economics)?;
    governance.persist(store)?;
    let mut staking = StakingSnapshot::load(store)?;
    staking.ensure_validators(&genesis.validators);
    for validator in &genesis.validators {
        let account = genesis
            .accounts
            .get(&validator.address)
            .ok_or_else(|| anyhow!(
                "validator {} has no genesis account — cannot bootstrap",
                validator.address
            ))?;
        if account.balance < genesis.economics.minimum_self_bond {
            return Err(anyhow!(
                "validator {} balance {} is below minimum self-bond {}",
                validator.address,
                account.balance,
                genesis.economics.minimum_self_bond
            ));
        }
        let self_bond = genesis.economics.minimum_self_bond;
        staking
            .delegate(validator.address, validator.address, self_bond, true)
            .map_err(|e| anyhow!("bootstrap delegation failed: {e}"))?;
    }
    staking.persist(store)?;
    Ok(())
}

/// Loads a key file from JSON.
pub fn load_wallet_key(path: impl AsRef<Path>) -> Result<zeno_wallet::WalletKeyFile> {
    let bytes = fs::read(path.as_ref())
        .with_context(|| format!("unable to read {}", path.as_ref().display()))?;
    serde_json::from_slice(&bytes).map_err(Into::into)
}

/// Creates an in-memory node for tests.
pub async fn in_memory_node(config: NodeConfig, genesis: Genesis) -> Result<Node> {
    let store = MemoryStore::shared();
    bootstrap_genesis(&store, &genesis)?;
    let network_plane = Arc::new(NetworkPlane::start(&config, &store).await?);
    let execution_plane = Arc::new(ExecutionPlane::new(config.chain_id.clone(), &genesis));

    Ok(Node {
        config,
        genesis,
        store,
        mempool: Arc::new(Mempool::new()),
        network_plane,
        execution_plane,
        operations_plane: OperationsPlane::new(),
        scheme: default_scheme(),
        request_ids: AtomicU64::new(1),
        sync_state: Mutex::new(SyncState::default()),
    })
}
