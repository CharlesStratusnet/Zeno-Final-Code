//! Genesis and devnet generation.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use zeno_config::{CryptoConfig, NodeConfig, ValidatorConfig};
use zeno_crypto::{default_scheme, MlDsaParameter};
use zeno_types::{Account, Address, ChainId, EconomicsParams, Genesis, Validator};

/// Generated validator artifact bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedValidator {
    /// Node configuration.
    pub config: NodeConfig,
    /// Validator descriptor for genesis.
    pub validator: Validator,
}

/// Generates a local devnet with a configurable number of validators.
pub fn generate_local_devnet(
    output_dir: impl AsRef<Path>,
    chain_id: &str,
    funded_accounts: &[(Address, u128)],
) -> anyhow::Result<Genesis> {
    generate_devnet(output_dir, chain_id, funded_accounts, 4)
}

/// Generates a single-validator network for standalone public deployment.
pub fn generate_solo_devnet(
    output_dir: impl AsRef<Path>,
    chain_id: &str,
    funded_accounts: &[(Address, u128)],
) -> anyhow::Result<Genesis> {
    generate_devnet(output_dir, chain_id, funded_accounts, 1)
}

fn generate_devnet(
    output_dir: impl AsRef<Path>,
    chain_id: &str,
    funded_accounts: &[(Address, u128)],
    validator_count: usize,
) -> anyhow::Result<Genesis> {
    let output_dir = output_dir.as_ref();
    fs::create_dir_all(output_dir)
        .with_context(|| format!("unable to create {}", output_dir.display()))?;

    let scheme = default_scheme();
    let mut validators = Vec::with_capacity(validator_count);
    let mut accounts = BTreeMap::new();
    for (address, balance) in funded_accounts {
        accounts.insert(
            *address,
            Account {
                nonce: 0,
                balance: *balance,
            },
        );
    }

    for index in 0..validator_count {
        let (public_key, secret_key) = scheme.generate_keypair().context("validator keypair")?;
        let address = Address(scheme.derive_address(&public_key).context("validator address")?);
        accounts.entry(address).or_insert(Account {
            nonce: 0,
            balance: 1_000_000_000,
        });

        let p2p_port = 7000 + index as u16;
        let rpc_port = 8000 + index as u16;
        let validator = Validator {
            validator_id: format!("validator-{index}"),
            voting_power: 1,
            p2p_address: format!("validator-{index}:{p2p_port}"),
            rpc_address: format!("validator-{index}:{rpc_port}"),
            public_key: public_key.0.clone(),
            address,
        };

        let mut config = NodeConfig::default();
        config.node_id = format!("validator-{index}");
        config.chain_id = ChainId(chain_id.to_string());
        config.metadata.network_name = "Zeno PQ Devnet".to_string();
        config.metadata.ticker = "ZPQ".to_string();
        config.metadata.block_explorer_url = "http://127.0.0.1:8000/explorer".to_string();
        config.metadata.metamask_compatible = false;
        config.metadata.metamask_snap_compatible = true;
        config.metadata.smart_contracts_supported = true;
        config.metadata.evm_chain_id = Some(424242);
        config.metadata.metamask_snap_id = Some("local:http://127.0.0.1:8081/zeno-pq-snap".to_string());
        config.metadata.compatibility_notice = "Use the Zeno MetaMask Snap plus relayer/account-abstraction flow for ML-DSA-authenticated EVM interactions.".to_string();
        config.metadata.rpc_urls = vec![
            "http://127.0.0.1:8000".to_string(),
            "http://127.0.0.1:8001".to_string(),
            "http://127.0.0.1:8002".to_string(),
            "http://127.0.0.1:8003".to_string(),
        ];
        config.p2p.listen = format!("0.0.0.0:{p2p_port}");
        config.rpc.listen = format!("0.0.0.0:{rpc_port}");
        config.storage.data_dir = output_dir
            .join(format!("node-{index}/data"))
            .display()
            .to_string();
        config.p2p.peers = (0..validator_count)
            .filter(|peer| *peer != index)
            .map(|peer| format!("validator-{peer}:{}", 7000 + peer as u16))
            .collect();
        config.crypto = CryptoConfig {
            ml_dsa_parameter: MlDsaParameter::default(),
        };
        config.validator = Some(ValidatorConfig {
            address,
            public_key: public_key.0.clone(),
            secret_key: secret_key.0.clone(),
        });

        let node_dir = output_dir.join(format!("node-{index}"));
        fs::create_dir_all(&node_dir).with_context(|| format!("unable to create {}", node_dir.display()))?;
        config.save(node_dir.join("node.toml"))?;
        fs::write(
            node_dir.join("validator-key.json"),
            serde_json::to_vec_pretty(config.validator.as_ref().expect("validator")).context("serialize validator key")?,
        )
        .with_context(|| format!("unable to write {}", node_dir.display()))?;
        validators.push(GeneratedValidator { config, validator });
    }

    let genesis = Genesis {
        chain_id: ChainId(chain_id.to_string()),
        metadata: validators[0].config.metadata.clone(),
        accounts,
        validators: validators.iter().map(|entry| entry.validator.clone()).collect(),
        consensus: validators[0].config.consensus_params(),
        crypto: validators[0].config.crypto_params(),
        economics: EconomicsParams {
            minimum_self_bond: 1_000_000,
            epoch_length: 100,
            unbonding_epochs: 7,
            treasury_bps: 1_000,
            downtime_slash_bps: 100,
            double_sign_slash_bps: 500,
        },
    };
    fs::write(
        output_dir.join("genesis.json"),
        serde_json::to_vec_pretty(&genesis).context("serialize genesis")?,
    )
    .with_context(|| format!("unable to write {}", output_dir.join("genesis.json").display()))?;
    Ok(genesis)
}

/// Loads a genesis file from disk.
pub fn load_genesis(path: impl AsRef<Path>) -> anyhow::Result<Genesis> {
    let path = path.as_ref();
    let bytes = fs::read(path).with_context(|| format!("unable to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid genesis {}", path.display()))
}

/// Writes a genesis file.
pub fn save_genesis(path: impl AsRef<Path>, genesis: &Genesis) -> anyhow::Result<()> {
    let path = path.as_ref();
    fs::write(path, serde_json::to_vec_pretty(genesis).context("serialize genesis")?)
        .with_context(|| format!("unable to write {}", path.display()))
}

/// Returns the expected genesis path for a node directory.
pub fn genesis_path(node_root: impl AsRef<Path>) -> PathBuf {
    node_root.as_ref().join("genesis.json")
}

#[cfg(test)]
mod tests {
    use super::{generate_local_devnet, genesis_path, load_genesis, save_genesis};

    #[test]
    fn devnet_generates_4_validators() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let genesis = generate_local_devnet(tempdir.path(), "zeno-testnet", &[]).expect("generate");
        assert_eq!(genesis.validators.len(), 4);
        assert_eq!(genesis.chain_id.0, "zeno-testnet");
    }

    #[test]
    fn genesis_save_and_load_roundtrips() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let genesis = generate_local_devnet(tempdir.path(), "roundtrip", &[]).expect("generate");
        let path = tempdir.path().join("roundtrip.json");
        save_genesis(&path, &genesis).expect("save");
        let loaded = load_genesis(&path).expect("load");
        assert_eq!(loaded.chain_id.0, "roundtrip");
        assert_eq!(loaded.validators.len(), 4);
    }

    #[test]
    fn devnet_creates_node_configs() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let _ = generate_local_devnet(tempdir.path(), "config-test", &[]).expect("generate");
        assert!(tempdir.path().join("node-0/node.toml").exists());
        assert!(tempdir.path().join("node-1/node.toml").exists());
        assert!(tempdir.path().join("node-2/node.toml").exists());
        assert!(tempdir.path().join("node-3/node.toml").exists());
        assert!(tempdir.path().join("genesis.json").exists());
    }

    #[test]
    fn genesis_path_helper() {
        assert_eq!(genesis_path("/tmp/node").to_str().expect("path"), "/tmp/node/genesis.json");
    }
}
