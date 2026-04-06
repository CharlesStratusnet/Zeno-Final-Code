use std::sync::Arc;

use anyhow::{anyhow, Result};
use zeno_config::NodeConfig;
use zeno_consensus::{ConsensusEngine, LocalValidator};
use zeno_crypto::SecretKeyBytes;
use zeno_mempool::Mempool;
use zeno_types::Genesis;

use crate::execution_plane::SharedExecutionPlane;

/// Consensus plane boundary for validator participation and finality.
pub struct ConsensusPlane {
    engine: Arc<ConsensusEngine>,
}

impl ConsensusPlane {
    /// Builds a consensus plane from the node's current runtime components.
    pub fn new(
        config: &NodeConfig,
        genesis: &Genesis,
        scheme: Arc<dyn zeno_crypto::SignatureScheme>,
        execution_plane: SharedExecutionPlane,
        mempool: Arc<Mempool>,
        store: zeno_storage::SharedStore,
        network: zeno_network::NetworkHandle,
    ) -> Result<Self> {
        let local_validator = config
            .validator
            .as_ref()
            .map(|validator| -> Result<LocalValidator> {
                let descriptor = genesis
                    .validators
                    .iter()
                    .find(|entry| entry.address == validator.address)
                    .cloned()
                    .ok_or_else(|| anyhow!("validator not present in genesis"))?;
                Ok(LocalValidator {
                    validator: descriptor,
                    secret_key: SecretKeyBytes(validator.secret_key.clone()),
                })
            })
            .transpose()?;

        let engine = ConsensusEngine::new(
            genesis,
            scheme,
            execution_plane.engine(),
            mempool,
            store,
            network,
            local_validator,
        )?;
        Ok(Self {
            engine: Arc::new(engine),
        })
    }

    /// Returns the consensus engine.
    pub fn engine(&self) -> Arc<ConsensusEngine> {
        Arc::clone(&self.engine)
    }
}

pub type SharedConsensusPlane = Arc<ConsensusPlane>;
