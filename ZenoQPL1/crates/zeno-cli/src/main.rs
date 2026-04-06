use std::{fs, path::PathBuf, str::FromStr, sync::Arc};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use reqwest::Client;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use zeno_genesis::generate_local_devnet;
use zeno_node::{init_tracing, load_wallet_key, Node};
use zeno_types::{Address, EvmAddress, EvmCallRequest, JsonRpcRequest, JsonRpcResponse};
use zeno_wallet::{
    build_signed_contract_call, build_signed_contract_create, build_signed_transfer, generate_wallet,
};

#[derive(Parser)]
#[command(name = "zeno-cli")]
struct Cli {
    #[command(subcommand)]
    command: TopLevelCommand,
}

#[derive(Subcommand)]
enum TopLevelCommand {
    #[command(subcommand)]
    Node(NodeCommand),
    #[command(subcommand)]
    Wallet(WalletCommand),
}

#[derive(Subcommand)]
enum NodeCommand {
    InitDevnet {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "zeno-devnet")]
        chain_id: String,
    },
    /// Initialize a single-validator network for standalone/public deployment.
    InitSolo {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "zeno-mainnet")]
        chain_id: String,
    },
    Start {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        genesis: PathBuf,
    },
    Info {
        #[arg(long)]
        config: PathBuf,
    },
    Status {
        #[arg(long)]
        rpc: String,
    },
}

#[derive(Subcommand)]
enum WalletCommand {
    Generate {
        #[arg(long)]
        output: PathBuf,
    },
    ShowAddress {
        #[arg(long)]
        key: PathBuf,
    },
    Balance {
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        address: String,
    },
    BuildTx {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        amount: u128,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        fee: u128,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        memo: Option<String>,
        #[arg(long)]
        valid_until: Option<u64>,
    },
    BuildEvmCreate {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        fee: u128,
        #[arg(long)]
        gas_limit: u64,
        #[arg(long, default_value_t = 1)]
        gas_price: u128,
        #[arg(long)]
        bytecode_hex: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        valid_until: Option<u64>,
    },
    BuildEvmCall {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        contract: String,
        #[arg(long)]
        calldata_hex: String,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        fee: u128,
        #[arg(long)]
        gas_limit: u64,
        #[arg(long, default_value_t = 1)]
        gas_price: u128,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        valid_until: Option<u64>,
    },
    EthCall {
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        calldata_hex: String,
    },
    GetCode {
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        address: String,
    },
    SubmitTx {
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        tx: PathBuf,
    },
    TxStatus {
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        hash: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .try_init();
    let cli = Cli::parse();
    match cli.command {
        TopLevelCommand::Node(command) => handle_node(command).await,
        TopLevelCommand::Wallet(command) => handle_wallet(command).await,
    }
}

async fn handle_node(command: NodeCommand) -> Result<()> {
    match command {
        NodeCommand::InitDevnet { output, chain_id } => {
            let faucet = generate_wallet()?;
            fs::create_dir_all(&output)?;
            fs::write(
                output.join("faucet.json"),
                serde_json::to_vec_pretty(&faucet).context("serialize faucet")?,
            )?;
            let _ = generate_local_devnet(
                &output,
                &chain_id,
                &[(faucet.address, 10_000_000_000)],
            )?;
            println!("{}", output.display());
            Ok(())
        }
        NodeCommand::InitSolo { output, chain_id } => {
            let faucet = generate_wallet()?;
            fs::create_dir_all(&output)?;
            fs::write(
                output.join("faucet.json"),
                serde_json::to_vec_pretty(&faucet).context("serialize faucet")?,
            )?;
            let _ = zeno_genesis::generate_solo_devnet(
                &output,
                &chain_id,
                &[(faucet.address, 10_000_000_000)],
            )?;
            println!("{}", output.display());
            Ok(())
        }
        NodeCommand::Start { config, genesis } => {
            init_tracing();
            Arc::new(Node::from_paths(config, genesis).await?).run().await
        }
        NodeCommand::Info { config } => {
            let config = zeno_config::NodeConfig::load(config)?;
            println!("{}", serde_json::to_string_pretty(&config.node_info())?);
            Ok(())
        }
        NodeCommand::Status { rpc } => {
            let status = rpc_call::<(), serde_json::Value>(&rpc, "get_chain_status", ()).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
    }
}

async fn handle_wallet(command: WalletCommand) -> Result<()> {
    match command {
        WalletCommand::Generate { output } => {
            let wallet = generate_wallet()?;
            fs::write(&output, serde_json::to_vec_pretty(&wallet)?)?;
            println!("{}", wallet.address);
            Ok(())
        }
        WalletCommand::ShowAddress { key } => {
            let wallet = load_wallet_key(key)?;
            println!("{}", wallet.address);
            Ok(())
        }
        WalletCommand::Balance { rpc, address } => {
            let address = parse_address(&address)?;
            let balance: u128 = rpc_call(&rpc, "get_balance", address).await?;
            println!("{balance}");
            Ok(())
        }
        WalletCommand::BuildTx {
            key,
            chain_id,
            recipient,
            amount,
            nonce,
            fee,
            output,
            memo,
            valid_until,
        } => {
            let wallet = load_wallet_key(key)?;
            let tx = build_signed_transfer(
                &wallet,
                chain_id,
                parse_address(&recipient)?,
                amount,
                nonce,
                fee,
                memo,
                valid_until,
            )?;
            fs::write(&output, serde_json::to_vec_pretty(&tx)?)?;
            println!("{}", tx.id());
            Ok(())
        }
        WalletCommand::BuildEvmCreate {
            key,
            chain_id,
            nonce,
            fee,
            gas_limit,
            gas_price,
            bytecode_hex,
            output,
            valid_until,
        } => {
            let wallet = load_wallet_key(key)?;
            let tx = build_signed_contract_create(
                &wallet,
                chain_id,
                nonce,
                fee,
                gas_limit,
                gas_price,
                hex::decode(bytecode_hex)?,
                valid_until,
            )?;
            fs::write(&output, serde_json::to_vec_pretty(&tx)?)?;
            println!("{}", tx.id());
            Ok(())
        }
        WalletCommand::BuildEvmCall {
            key,
            chain_id,
            contract,
            calldata_hex,
            nonce,
            fee,
            gas_limit,
            gas_price,
            output,
            valid_until,
        } => {
            let wallet = load_wallet_key(key)?;
            let tx = build_signed_contract_call(
                &wallet,
                chain_id,
                parse_evm_address(&contract)?,
                hex::decode(calldata_hex)?,
                nonce,
                fee,
                gas_limit,
                gas_price,
                valid_until,
            )?;
            fs::write(&output, serde_json::to_vec_pretty(&tx)?)?;
            println!("{}", tx.id());
            Ok(())
        }
        WalletCommand::EthCall {
            rpc,
            to,
            calldata_hex,
        } => {
            let result: String = rpc_call(
                &rpc,
                "eth_call",
                EvmCallRequest {
                    from: None,
                    to: parse_evm_address(&to)?,
                    data: hex::decode(calldata_hex)?,
                    gas_limit: None,
                    value: None,
                },
            )
            .await?;
            println!("{result}");
            Ok(())
        }
        WalletCommand::GetCode { rpc, address } => {
            let result: String = rpc_call(&rpc, "eth_getCode", parse_evm_address(&address)?).await?;
            println!("{result}");
            Ok(())
        }
        WalletCommand::SubmitTx { rpc, tx } => {
            let bytes = fs::read(tx)?;
            let tx: zeno_types::Transaction = serde_json::from_slice(&bytes)?;
            let hash: zeno_hash::Hash32 = rpc_call(&rpc, "submit_tx", tx).await?;
            println!("{hash}");
            Ok(())
        }
        WalletCommand::TxStatus { rpc, hash } => {
            let hash = zeno_hash::Hash32::from_str(&hash)?;
            let status: serde_json::Value = rpc_call(&rpc, "get_tx_status", hash).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
    }
}

fn parse_address(value: &str) -> Result<Address> {
    let bytes = hex::decode(value).context("invalid address hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!("address must be 32 bytes"));
    }
    let mut address = [0u8; 32];
    address.copy_from_slice(&bytes);
    Ok(Address(address))
}

fn parse_evm_address(value: &str) -> Result<EvmAddress> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).context("invalid evm address hex")?;
    if bytes.len() != 20 {
        return Err(anyhow!("evm address must be 20 bytes"));
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes);
    Ok(EvmAddress(address))
}

async fn rpc_call<P: serde::Serialize, R: serde::de::DeserializeOwned>(
    rpc: &str,
    method: &str,
    params: P,
) -> Result<R> {
    let client = Client::new();
    let response = client
        .post(format!("http://{rpc}/"))
        .json(&JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: serde_json::Value::String(uuid::Uuid::new_v4().to_string()),
            method: method.to_string(),
            params: serde_json::to_value(params)?,
        })
        .send()
        .await?;
    let body: JsonRpcResponse<R> = response.json().await?;
    if let Some(error) = body.error {
        return Err(anyhow!(error.message));
    }
    body.result.ok_or_else(|| anyhow!("missing rpc result"))
}
