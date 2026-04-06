#[cfg(test)]
mod tests {
    use anyhow::Result;
    use zeno_config::NodeConfig;
    use zeno_genesis::load_genesis;
    use zeno_storage::{ChainStore, RocksStore};
    use zeno_test_utils::{create_test_devnet, genesis_path, node_config_path};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn restart_preserves_genesis_and_state() -> Result<()> {
        let devnet = create_test_devnet()?;
        let config = NodeConfig::load(node_config_path(&devnet.tempdir, 0))?;
        let genesis = load_genesis(genesis_path(&devnet.tempdir))?;

        {
            let store = RocksStore::open(&config.storage.data_dir)?;
            if store.get_genesis()?.is_none() {
                store.put_genesis(&genesis)?;
                for (address, account) in &genesis.accounts {
                    store.put_account(address, account)?;
                }
            }
        }

        let reloaded = RocksStore::open(&config.storage.data_dir)?;
        assert_eq!(reloaded.get_genesis()?.expect("genesis present").chain_id.0, "zeno-testnet");
        assert_eq!(
            reloaded
                .get_account(&devnet.faucet.address)?
                .expect("faucet account present")
                .balance,
            1_000_000_000
        );
        Ok(())
    }
}
