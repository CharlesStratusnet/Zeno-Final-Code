use std::sync::Arc;

use anyhow::Result;
use zeno_config::NodeConfig;
use zeno_network::{start_network, NetworkHandle};
use zeno_storage::SharedStore;
use zeno_types::ChainId;

/// Network plane boundary for propagation and peer connectivity.
pub struct NetworkPlane {
    handle: NetworkHandle,
}

impl NetworkPlane {
    /// Starts the network plane using node configuration.
    pub async fn start(config: &NodeConfig, store: &SharedStore) -> Result<Self> {
        let latest_height = store
            .latest_block()?
            .map(|block| block.block.header.height)
            .unwrap_or(0);
        let handle = start_network(
            config.node_id.clone(),
            ChainId(config.chain_id.0.clone()),
            config.p2p.listen.clone(),
            config.p2p.peers.clone(),
            config.p2p.max_frame_bytes,
            latest_height,
        )
        .await?;
        Ok(Self { handle })
    }

    /// Returns the network handle used by other planes.
    pub fn handle(&self) -> NetworkHandle {
        self.handle.clone()
    }

    /// Returns connected peers.
    pub fn peers(&self) -> Vec<String> {
        self.handle.peers()
    }

    /// Returns current peer reputation scores.
    pub fn peer_scores(&self) -> std::collections::BTreeMap<String, i64> {
        self.handle.peer_scores()
    }

    /// Returns current peer sync metadata.
    pub fn peer_states(&self) -> std::collections::BTreeMap<String, zeno_network::PeerState> {
        self.handle.peer_states()
    }
}

pub type SharedNetworkPlane = Arc<NetworkPlane>;
