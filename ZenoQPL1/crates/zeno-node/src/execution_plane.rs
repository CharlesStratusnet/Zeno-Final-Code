use std::sync::Arc;

use anyhow::{anyhow, Result};
use zeno_crypto::SignatureScheme;
use zeno_evm::EvmExecutor;
use zeno_execution::ExecutionEngine;
use zeno_state::StateSnapshot;
use zeno_storage::SharedStore;
use zeno_types::{ChainId, EvmAddress, EvmCallRequest, EvmCallResult, Genesis, Transaction};

/// Execution plane boundary for transaction validation and state transition logic.
pub struct ExecutionPlane {
    chain_id: ChainId,
    evm_chain_id: Option<u64>,
    genesis: Genesis,
}

impl ExecutionPlane {
    /// Builds the execution plane from chain metadata.
    pub fn new(chain_id: ChainId, genesis: &Genesis) -> Self {
        Self {
            chain_id,
            evm_chain_id: genesis.metadata.evm_chain_id,
            genesis: genesis.clone(),
        }
    }

    /// Returns a configured execution engine.
    pub fn engine(&self) -> ExecutionEngine {
        ExecutionEngine::with_protocol(
            self.chain_id.clone(),
            self.evm_chain_id,
            genesis_economics(self),
            genesis_validators(self),
        )
    }

    /// Validates a transaction against the current chain state.
    pub fn validate_transaction(
        &self,
        scheme: &dyn SignatureScheme,
        store: &SharedStore,
        tx: &Transaction,
    ) -> Result<()> {
        let state = StateSnapshot::load(store)?;
        let height = store
            .latest_block()?
            .map(|block| block.block.header.height + 1)
            .unwrap_or(1);
        self.engine().validate_transaction(scheme, &state, height, tx)?;
        Ok(())
    }

    /// Executes a read-only EVM call.
    pub fn eth_call(&self, store: &SharedStore, request: EvmCallRequest) -> Result<Vec<u8>> {
        let chain_id = self
            .evm_chain_id
            .ok_or_else(|| anyhow!("evm is not enabled for this chain"))?;
        EvmExecutor::new(chain_id)
            .eth_call(store, request)
            .map_err(Into::into)
    }

    /// Returns runtime bytecode for an EVM address.
    pub fn eth_get_code(&self, store: &SharedStore, address: EvmAddress) -> Result<Vec<u8>> {
        let Some(chain_id) = self.evm_chain_id else {
            return Ok(Vec::new());
        };
        EvmExecutor::new(chain_id).get_code(store, address.0)
    }

    /// Executes a raw ECDSA-signed Ethereum transaction (from MetaMask).
    pub fn execute_raw_eth_tx(
        &self,
        store: &SharedStore,
        raw_hex: &str,
    ) -> Result<([u8; 32], EvmCallResult)> {
        let chain_id = self
            .evm_chain_id
            .ok_or_else(|| anyhow!("evm is not enabled for this chain"))?;
        EvmExecutor::new(chain_id)
            .execute_raw_ethereum_tx(store, raw_hex)
            .map_err(Into::into)
    }

    /// Returns the configured EVM chain id, if any.
    pub fn evm_chain_id(&self) -> Option<u64> {
        self.evm_chain_id
    }
}

pub type SharedExecutionPlane = Arc<ExecutionPlane>;

fn genesis_economics(plane: &ExecutionPlane) -> zeno_types::EconomicsParams {
    plane.genesis.economics.clone()
}

fn genesis_validators(plane: &ExecutionPlane) -> Vec<zeno_types::Validator> {
    plane.genesis.validators.clone()
}
