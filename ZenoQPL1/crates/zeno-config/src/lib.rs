//! Node configuration.

use std::{fs, path::Path, time::Duration};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use zeno_crypto::MlDsaParameter;
use zeno_types::{ChainId, ConsensusParams, CryptoParams, NetworkMetadata, NodeInfo};

/// Global node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node identity.
    pub node_id: String,
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Human-facing network metadata.
    pub metadata: NetworkMetadata,
    /// P2P configuration.
    pub p2p: P2pConfig,
    /// RPC configuration.
    pub rpc: RpcConfig,
    /// Storage configuration.
    pub storage: StorageConfig,
    /// Consensus settings.
    pub consensus: ConsensusConfig,
    /// Validator key material if this is a validator node.
    pub validator: Option<ValidatorConfig>,
    /// Crypto selection.
    pub crypto: CryptoConfig,
}

impl NodeConfig {
    /// Loads a TOML configuration file.
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .with_context(|| format!("unable to read config {}", path.display()))?;
        toml::from_str(&contents).with_context(|| format!("invalid config {}", path.display()))
    }

    /// Saves a TOML configuration file.
    pub fn save(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let path = path.as_ref();
        let contents = toml::to_string_pretty(self).context("unable to serialize config")?;
        fs::write(path, contents).with_context(|| format!("unable to write {}", path.display()))
    }

    /// Returns consensus parameters in shared type form.
    pub fn consensus_params(&self) -> ConsensusParams {
        ConsensusParams {
            proposal_timeout_ms: self.consensus.proposal_timeout.as_millis() as u64,
            vote_timeout_ms: self.consensus.vote_timeout.as_millis() as u64,
            max_transactions_per_block: self.consensus.max_transactions_per_block,
            max_block_bytes: 2_097_152,
            target_gas_per_block: 15_000_000,
            max_gas_per_block: 30_000_000,
        }
    }

    /// Returns crypto parameters in shared type form.
    pub fn crypto_params(&self) -> CryptoParams {
        CryptoParams {
            ml_dsa_parameter: self.crypto.ml_dsa_parameter.description().to_string(),
        }
    }

    /// Exports node metadata.
    pub fn node_info(&self) -> NodeInfo {
        NodeInfo {
            node_id: self.node_id.clone(),
            validator_address: self.validator.as_ref().map(|validator| validator.address),
            p2p_listen: self.p2p.listen.clone(),
            rpc_listen: self.rpc.listen.clone(),
        }
    }
}

/// Networking configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    /// Listening address.
    pub listen: String,
    /// Static peers.
    pub peers: Vec<String>,
    /// Maximum inbound frame size.
    pub max_frame_bytes: usize,
}

/// RPC configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// Listening address.
    pub listen: String,
}

/// Storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Data directory.
    pub data_dir: String,
}

/// Consensus configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Proposal timeout.
    #[serde(with = "humantime_serde")]
    pub proposal_timeout: Duration,
    /// Vote timeout.
    #[serde(with = "humantime_serde")]
    pub vote_timeout: Duration,
    /// Maximum transactions per block.
    pub max_transactions_per_block: usize,
}

/// Validator configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// Validator address.
    pub address: zeno_types::Address,
    /// Public key bytes.
    pub public_key: Vec<u8>,
    /// Secret key bytes.
    pub secret_key: Vec<u8>,
}

/// Crypto configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Selected ML-DSA parameter set.
    pub ml_dsa_parameter: MlDsaParameter,
}

#[cfg(test)]
mod tests {
    use super::NodeConfig;

    #[test]
    fn default_config_serializes_to_toml() {
        let config = NodeConfig::default();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let loaded: NodeConfig = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(loaded.node_id, config.node_id);
        assert_eq!(loaded.chain_id, config.chain_id);
    }

    #[test]
    fn config_roundtrips_through_file() {
        let config = NodeConfig::default();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("node.toml");
        config.save(&path).expect("save");
        let loaded = NodeConfig::load(&path).expect("load");
        assert_eq!(loaded.node_id, config.node_id);
        assert_eq!(loaded.rpc.listen, config.rpc.listen);
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_id: "node-0".to_string(),
            chain_id: ChainId("zeno-devnet".to_string()),
            metadata: NetworkMetadata {
                network_name: "Zeno PQ Devnet".to_string(),
                ticker: "ZPQ".to_string(),
                rpc_urls: vec![
                    "http://127.0.0.1:8000".to_string(),
                    "http://127.0.0.1:8001".to_string(),
                    "http://127.0.0.1:8002".to_string(),
                    "http://127.0.0.1:8003".to_string(),
                ],
                block_explorer_url: "http://127.0.0.1:8000/explorer".to_string(),
                metamask_compatible: false,
                metamask_snap_compatible: true,
                smart_contracts_supported: true,
                evm_chain_id: Some(424242),
                compatibility_notice: "Solidity-compatible EVM execution is enabled. Standard MetaMask network compatibility remains unavailable because user transaction authorization stays ML-DSA based; use the Zeno MetaMask Snap plus relayer/account-abstraction flow instead.".to_string(),
                metamask_snap_id: Some("local:http://127.0.0.1:8081/zeno-pq-snap".to_string()),
            },
            p2p: P2pConfig {
                listen: "0.0.0.0:7000".to_string(),
                peers: Vec::new(),
                max_frame_bytes: 8 * 1024 * 1024,
            },
            rpc: RpcConfig {
                listen: "0.0.0.0:8000".to_string(),
            },
            storage: StorageConfig {
                data_dir: "./data".to_string(),
            },
            consensus: ConsensusConfig {
                proposal_timeout: Duration::from_millis(1500),
                vote_timeout: Duration::from_millis(1000),
                max_transactions_per_block: 256,
            },
            validator: None,
            crypto: CryptoConfig {
                ml_dsa_parameter: MlDsaParameter::default(),
            },
        }
    }
}
