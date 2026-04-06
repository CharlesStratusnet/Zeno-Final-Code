//! Test helpers.

use std::path::PathBuf;

use anyhow::Result;
use tempfile::TempDir;
use zeno_config::NodeConfig;
use zeno_genesis::generate_local_devnet;
use zeno_node::Node;
use zeno_wallet::generate_wallet;

/// Test network bundle.
pub struct TestNetwork {
    /// Temporary directory.
    pub tempdir: TempDir,
    /// Faucet wallet.
    pub faucet: zeno_wallet::WalletKeyFile,
}

/// Creates a temporary devnet on disk.
pub fn create_test_devnet() -> Result<TestNetwork> {
    let tempdir = tempfile::tempdir()?;
    let faucet = generate_wallet()?;
    generate_local_devnet(tempdir.path(), "zeno-testnet", &[(faucet.address, 1_000_000_000)])?;
    Ok(TestNetwork { tempdir, faucet })
}

/// Returns a node config path for an index.
pub fn node_config_path(root: &TempDir, index: usize) -> PathBuf {
    root.path().join(format!("node-{index}/node.toml"))
}

/// Returns the shared genesis path.
pub fn genesis_path(root: &TempDir) -> PathBuf {
    root.path().join("genesis.json")
}

/// Loads a configured node.
pub async fn load_test_node(root: &TempDir, index: usize) -> Result<Node> {
    Node::from_paths(node_config_path(root, index), genesis_path(root)).await
}
