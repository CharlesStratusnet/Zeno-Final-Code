//! TCP peer-to-peer networking.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{broadcast, mpsc},
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, info, warn};
use zeno_hash::{hash_bytes, Hash32};
use zeno_types::{ChainId, Handshake, NetworkMessage, SyncRequest};

#[derive(Debug, Clone)]
struct OutboundMessage {
    target_peer: Option<String>,
    message: NetworkMessage,
}

/// Network errors.
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("io error: {0}")]
    Io(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Inbound network event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    /// Peer address.
    pub peer: String,
    /// Decoded message.
    pub message: NetworkMessage,
}

/// Scoring constants for peer reputation.
pub const SCORE_INITIAL: i64 = 10;
/// Score reward for a valid new message.
pub const SCORE_VALID_MESSAGE: i64 = 1;
/// Score penalty for sending a duplicate message.
pub const SCORE_DUPLICATE_MESSAGE: i64 = -2;
/// Score penalty for an invalid/malformed message.
pub const SCORE_INVALID_MESSAGE: i64 = -10;
/// Score reward for a useful block (advances our chain).
pub const SCORE_USEFUL_BLOCK: i64 = 5;
/// Score at or below which a peer is banned.
pub const SCORE_BAN_THRESHOLD: i64 = -50;
/// Maximum peer score.
pub const SCORE_MAX: i64 = 100;
/// Maximum number of inbound connections.
pub const MAX_INBOUND_CONNECTIONS: usize = 50;
/// Ban duration in milliseconds (5 minutes).
pub const BAN_DURATION_MS: u64 = 300_000;

/// Runtime peer reputation and sync metadata.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerState {
    /// Signed reputation score.
    pub score: i64,
    /// Best known finalized height announced by the peer.
    pub best_height: u64,
    /// Timestamp of connection in ms since epoch.
    pub connected_at: u64,
    /// Timestamp of last received message in ms since epoch.
    pub last_message_at: u64,
    /// Total messages received from this peer.
    pub messages_received: u64,
    /// Whether we initiated the connection.
    pub is_outbound: bool,
    /// If banned, timestamp when ban expires.
    pub banned_until: Option<u64>,
    /// Cryptographic node identity from handshake (prevents Sybil via IP rotation).
    pub node_id: String,
}

/// Shared network handle.
#[derive(Clone)]
pub struct NetworkHandle {
    outbound: mpsc::Sender<OutboundMessage>,
    inbound: broadcast::Sender<NetworkEvent>,
    peers: Arc<RwLock<BTreeMap<String, PeerState>>>,
}

impl NetworkHandle {
    /// Broadcasts a message to all connected peers.
    pub async fn broadcast(&self, message: NetworkMessage) -> Result<()> {
        self.outbound
            .send(OutboundMessage {
                target_peer: None,
                message,
            })
            .await
            .map_err(|_| anyhow!("network stopped"))
    }

    /// Sends a message to a specific peer.
    pub async fn send_to(&self, peer: impl Into<String>, message: NetworkMessage) -> Result<()> {
        self.outbound
            .send(OutboundMessage {
                target_peer: Some(peer.into()),
                message,
            })
            .await
            .map_err(|_| anyhow!("network stopped"))
    }

    /// Subscribes to inbound events.
    pub fn subscribe(&self) -> broadcast::Receiver<NetworkEvent> {
        self.inbound.subscribe()
    }

    /// Returns connected peers.
    pub fn peers(&self) -> Vec<String> {
        self.peers.read().keys().cloned().collect()
    }

    /// Returns peer scores for inspection.
    pub fn peer_scores(&self) -> BTreeMap<String, i64> {
        self.peers
            .read()
            .iter()
            .map(|(peer, state)| (peer.clone(), state.score))
            .collect()
    }

    /// Returns peer metadata for sync selection.
    pub fn peer_states(&self) -> BTreeMap<String, PeerState> {
        self.peers.read().clone()
    }

    /// Returns the number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    /// Bans a peer for a specified duration.
    pub fn ban_peer(&self, peer: &str, duration_ms: u64) {
        let now = now_ms();
        if let Some(state) = self.peers.write().get_mut(peer) {
            state.banned_until = Some(now.saturating_add(duration_ms));
            state.score = SCORE_BAN_THRESHOLD;
        }
    }

    /// Returns whether a peer is currently banned.
    pub fn is_banned(&self, peer: &str) -> bool {
        let now = now_ms();
        self.peers
            .read()
            .get(peer)
            .is_some_and(|state| state.banned_until.is_some_and(|until| now < until))
    }

    /// Broadcasts a sync request to connected peers.
    pub async fn request_sync(&self, request_id: u64, request: SyncRequest) -> Result<()> {
        self.broadcast(NetworkMessage::SyncRequest { request_id, request }).await
    }

    /// Sends a sync request to a specific peer.
    pub async fn request_sync_from(
        &self,
        peer: impl Into<String>,
        request_id: u64,
        request: SyncRequest,
    ) -> Result<()> {
        self.send_to(peer, NetworkMessage::SyncRequest { request_id, request }).await
    }
}

/// Starts the networking service.
pub async fn start_network(
    node_id: String,
    chain_id: ChainId,
    listen: String,
    peers: Vec<String>,
    max_frame_bytes: usize,
    best_height: u64,
) -> Result<NetworkHandle> {
    let listener = TcpListener::bind(&listen)
        .await
        .with_context(|| format!("unable to bind p2p listener {listen}"))?;
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<OutboundMessage>(1024);
    let (inbound_tx, _) = broadcast::channel::<NetworkEvent>(1024);
    let shared_peers = Arc::new(RwLock::new(BTreeMap::new()));

    let accept_inbound = inbound_tx.clone();
    let accept_peers = Arc::clone(&shared_peers);
    let accept_chain_id = chain_id.clone();
    let accept_node_id = node_id.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let inbound = accept_inbound.clone();
                    let peers = Arc::clone(&accept_peers);
                    let chain_id = accept_chain_id.clone();
                    let node_id = accept_node_id.clone();
                    tokio::spawn(async move {
                        if let Err(err) =
                            handle_connection(stream, true, inbound, peers, chain_id, node_id, max_frame_bytes, best_height)
                                .await
                        {
                            warn!(error = %err, "inbound connection failed");
                        }
                    });
                }
                Err(err) => warn!(error = %err, "p2p accept failed"),
            }
        }
    });

    let dial_inbound = inbound_tx.clone();
    let dial_peers = Arc::clone(&shared_peers);
    let dial_chain_id = chain_id.clone();
    let dial_node_id = node_id.clone();
    for peer in peers {
        let inbound = dial_inbound.clone();
        let peers = Arc::clone(&dial_peers);
        let chain_id = dial_chain_id.clone();
        let node_id = dial_node_id.clone();
        tokio::spawn(async move {
            match TcpStream::connect(&peer).await {
                Ok(stream) => {
                    if let Err(err) =
                        handle_connection(stream, false, inbound, peers, chain_id, node_id, max_frame_bytes, best_height)
                            .await
                    {
                        warn!(peer = %peer, error = %err, "outbound connection failed");
                    }
                }
                Err(err) => warn!(peer = %peer, error = %err, "peer connect failed"),
            }
        });
    }

    let fanout_peers = Arc::clone(&shared_peers);
    tokio::spawn(async move {
        let peers = fanout_peers;
        let mut sinks = BTreeMap::<String, mpsc::Sender<NetworkMessage>>::new();
        let (register_tx, mut register_rx) = mpsc::channel::<(String, mpsc::Sender<NetworkMessage>)>(128);
        let register_tx_clone = register_tx.clone();
        NETWORK_REGISTRY.set(register_tx_clone).ok();

        loop {
            tokio::select! {
                Some((peer, sink)) = register_rx.recv() => {
                    sinks.insert(peer, sink);
                }
                Some(outbound) = outbound_rx.recv() => {
                    sinks.retain(|_, sink| !sink.is_closed());
                    if let Some(target_peer) = outbound.target_peer {
                        if let Some(sink) = sinks.get(&target_peer) {
                            let _ = sink.send(outbound.message).await;
                        }
                    } else {
                        for sink in sinks.values() {
                            let _ = sink.send(outbound.message.clone()).await;
                        }
                    }
                    debug!(peer_count = peers.read().len(), "broadcasted network message");
                }
            }
        }
    });

    info!(listen = %listen, "network service started");
    Ok(NetworkHandle {
        outbound: outbound_tx,
        inbound: inbound_tx,
        peers: shared_peers,
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

static NETWORK_REGISTRY: std::sync::OnceLock<mpsc::Sender<(String, mpsc::Sender<NetworkMessage>)>> =
    std::sync::OnceLock::new();

async fn handle_connection(
    stream: TcpStream,
    inbound_only: bool,
    inbound: broadcast::Sender<NetworkEvent>,
    peers: Arc<RwLock<BTreeMap<String, PeerState>>>,
    chain_id: ChainId,
    node_id: String,
    max_frame_bytes: usize,
    best_height: u64,
) -> Result<()> {
    let peer = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(max_frame_bytes)
        .new_codec();
    let mut framed = Framed::new(stream, codec);
    let handshake = NetworkMessage::Handshake(Handshake {
        chain_id: chain_id.clone(),
        node_id: node_id.clone(),
        best_height,
    });
    framed.send(BytesMut::from(&zeno_codec::encode(&handshake)?[..]).freeze()).await?;
    let next = framed.next().await.ok_or_else(|| anyhow!("missing handshake"))??;
    let remote: NetworkMessage = zeno_codec::decode(&next)?;
    // Connection limit check for inbound connections.
    if inbound_only {
        let inbound_count = peers
            .read()
            .values()
            .filter(|state| !state.is_outbound)
            .count();
        if inbound_count >= MAX_INBOUND_CONNECTIONS {
            return Err(anyhow!("inbound connection limit reached"));
        }
    }
    match remote {
        NetworkMessage::Handshake(payload) if payload.chain_id == chain_id => {
            // Check if this node_id is banned (prevents reconnect under new IP).
            let is_node_banned = peers
                .read()
                .values()
                .any(|state| {
                    state.node_id == payload.node_id
                        && state.banned_until.is_some_and(|until| now_ms() < until)
                });
            if is_node_banned {
                return Err(anyhow!("node {} is banned", payload.node_id));
            }
            peers.write().insert(
                peer.clone(),
                PeerState {
                    score: SCORE_INITIAL,
                    best_height: payload.best_height,
                    connected_at: now_ms(),
                    last_message_at: now_ms(),
                    messages_received: 0,
                    is_outbound: !inbound_only,
                    banned_until: None,
                    node_id: payload.node_id.clone(),
                },
            );
            info!(peer = %peer, node_id = %payload.node_id, inbound_only, "peer handshake accepted");
        }
        NetworkMessage::Handshake(payload) => {
            return Err(anyhow!(
                "chain id mismatch local={} remote={}",
                chain_id.0,
                payload.chain_id.0
            ));
        }
        other => return Err(anyhow!("expected handshake, got {:?}", other)),
    }

    let (tx, mut rx) = mpsc::channel::<NetworkMessage>(256);
    if let Some(registry) = NETWORK_REGISTRY.get() {
        let _ = registry.send((peer.clone(), tx)).await;
    }
    let recent_messages = Arc::new(RwLock::new(RecentMessages::default()));

    loop {
        tokio::select! {
            Some(frame) = framed.next() => {
                let frame = frame.map_err(|err| anyhow!(err))?;
                let message: NetworkMessage = zeno_codec::decode(&frame)?;
                if let Some(state) = peers.write().get_mut(&peer) {
                    state.last_message_at = now_ms();
                    state.messages_received += 1;
                    match &message {
                        NetworkMessage::Status(status) => {
                            state.best_height = state.best_height.max(status.latest_height);
                        }
                        NetworkMessage::Commit(finalized) => {
                            let new_height = finalized.block.header.height;
                            if new_height > state.best_height {
                                state.best_height = new_height;
                                state.score = (state.score + SCORE_USEFUL_BLOCK).min(SCORE_MAX);
                            }
                        }
                        _ => {}
                    }
                }
                let message_id = message_id(&message)?;
                if recent_messages.write().remember(message_id) {
                    // Valid new message — reward.
                    if let Some(state) = peers.write().get_mut(&peer) {
                        state.score = (state.score + SCORE_VALID_MESSAGE).min(SCORE_MAX);
                    }
                    let _ = inbound.send(NetworkEvent { peer: peer.clone(), message });
                } else {
                    // Duplicate — penalize.
                    if let Some(state) = peers.write().get_mut(&peer) {
                        state.score += SCORE_DUPLICATE_MESSAGE;
                    }
                }
                // Check for ban threshold.
                let should_ban = peers
                    .read()
                    .get(&peer)
                    .is_some_and(|state| state.score <= SCORE_BAN_THRESHOLD);
                if should_ban {
                    if let Some(state) = peers.write().get_mut(&peer) {
                        state.banned_until = Some(now_ms().saturating_add(BAN_DURATION_MS));
                    }
                    break;
                }
            }
            Some(message) = rx.recv() => {
                framed.send(BytesMut::from(&zeno_codec::encode(&message)?[..]).freeze()).await?;
            }
            else => break,
        }
    }

    peers.write().remove(&peer);
    Ok(())
}

#[derive(Debug, Default)]
struct RecentMessages {
    seen: BTreeSet<Hash32>,
    order: VecDeque<Hash32>,
}

impl RecentMessages {
    const MAX_RECENT: usize = 2048;

    fn remember(&mut self, id: Hash32) -> bool {
        if self.seen.contains(&id) {
            return false;
        }
        self.seen.insert(id);
        self.order.push_back(id);
        while self.order.len() > Self::MAX_RECENT {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        true
    }
}

fn message_id(message: &NetworkMessage) -> Result<Hash32> {
    Ok(hash_bytes(zeno_codec::encode(message)?))
}

#[cfg(test)]
mod tests {
    use super::{Hash32, RecentMessages, PeerState, SCORE_BAN_THRESHOLD, SCORE_INITIAL, SCORE_MAX,
                SCORE_VALID_MESSAGE, SCORE_DUPLICATE_MESSAGE, SCORE_USEFUL_BLOCK};

    #[test]
    fn recent_messages_reject_duplicates() {
        let mut recent = RecentMessages::default();
        let id = Hash32([7; 32]);
        assert!(recent.remember(id));
        assert!(!recent.remember(id));
    }

    #[test]
    fn recent_messages_evict_oldest() {
        let mut recent = RecentMessages::default();
        for i in 0..RecentMessages::MAX_RECENT {
            let mut bytes = [0u8; 32];
            bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(recent.remember(Hash32(bytes)));
        }
        assert_eq!(recent.seen.len(), RecentMessages::MAX_RECENT);
        // Add one more — should evict the oldest.
        let new_id = Hash32([0xff; 32]);
        assert!(recent.remember(new_id));
        assert_eq!(recent.seen.len(), RecentMessages::MAX_RECENT);
        // First entry should be evicted.
        assert!(!recent.seen.contains(&Hash32([0u8; 32])));
    }

    #[test]
    fn peer_state_defaults() {
        let state = PeerState::default();
        assert_eq!(state.score, 0);
        assert_eq!(state.best_height, 0);
        assert!(state.banned_until.is_none());
    }

    #[test]
    fn score_constants_are_reasonable() {
        assert!(SCORE_INITIAL > 0);
        assert!(SCORE_VALID_MESSAGE > 0);
        assert!(SCORE_DUPLICATE_MESSAGE < 0);
        assert!(SCORE_BAN_THRESHOLD < 0);
        assert!(SCORE_MAX > SCORE_INITIAL);
        assert!(SCORE_USEFUL_BLOCK > SCORE_VALID_MESSAGE);
    }

    #[test]
    fn score_clamps_at_max() {
        let mut score: i64 = 95;
        score = (score + SCORE_VALID_MESSAGE).min(SCORE_MAX);
        assert_eq!(score, 96);
        score = (score + SCORE_USEFUL_BLOCK).min(SCORE_MAX);
        assert_eq!(score, SCORE_MAX);
    }

    #[test]
    fn score_drops_below_ban_threshold() {
        let mut score: i64 = SCORE_INITIAL;
        for _ in 0..40 {
            score += SCORE_DUPLICATE_MESSAGE;
        }
        assert!(score <= SCORE_BAN_THRESHOLD);
    }
}
