//! Operations plane boundary for observability and operator-facing controls.

use std::sync::OnceLock;

use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry, TextEncoder,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Operations plane boundary for observability and operator-facing controls.
#[derive(Debug, Clone, Default)]
pub struct OperationsPlane;

impl OperationsPlane {
    /// Creates the operations plane.
    pub fn new() -> Self {
        Self
    }
}

/// Initializes tracing once for binaries.
pub fn init_tracing() {
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .try_init();
}

/// Prometheus metrics for all node subsystems.
pub struct NodeMetrics {
    registry: Registry,
    // -- Consensus --
    /// Current consensus height.
    pub consensus_height: IntGauge,
    /// Current consensus round.
    pub consensus_round: IntGauge,
    /// Total blocks finalized.
    pub blocks_finalized: IntCounter,
    /// Total blocks proposed by this node.
    pub blocks_proposed: IntCounter,
    // -- Execution --
    /// Total transactions executed successfully.
    pub transactions_executed: IntCounter,
    /// Total transactions that failed validation.
    pub transactions_failed: IntCounter,
    /// Block execution latency in seconds.
    pub block_execution_time: Histogram,
    // -- Mempool --
    /// Current mempool size.
    pub mempool_size: IntGauge,
    /// Total mempool insertions.
    pub mempool_insertions: IntCounter,
    /// Total mempool rejections.
    pub mempool_rejections: IntCounter,
    // -- Network --
    /// Connected peers count.
    pub peers_connected: IntGauge,
    /// Total inbound messages received.
    pub messages_received: IntCounter,
    /// Total outbound messages sent.
    pub messages_sent: IntCounter,
    // -- Storage --
    /// Total storage read operations.
    pub storage_reads: IntCounter,
    /// Total storage write operations.
    pub storage_writes: IntCounter,
    // -- EVM --
    /// Total EVM calls executed.
    pub evm_calls: IntCounter,
    /// Total EVM gas consumed.
    pub evm_gas_used: IntCounter,
}

impl NodeMetrics {
    fn new() -> Self {
        let registry = Registry::new();

        let consensus_height =
            IntGauge::with_opts(Opts::new("zeno_consensus_height", "Current consensus height"))
                .expect("metric creation must succeed");
        let consensus_round =
            IntGauge::with_opts(Opts::new("zeno_consensus_round", "Current consensus round"))
                .expect("metric creation must succeed");
        let blocks_finalized =
            IntCounter::with_opts(Opts::new("zeno_blocks_finalized_total", "Total blocks finalized"))
                .expect("metric creation must succeed");
        let blocks_proposed =
            IntCounter::with_opts(Opts::new("zeno_blocks_proposed_total", "Total blocks proposed by this node"))
                .expect("metric creation must succeed");

        let transactions_executed =
            IntCounter::with_opts(Opts::new("zeno_transactions_executed_total", "Total successful transactions"))
                .expect("metric creation must succeed");
        let transactions_failed =
            IntCounter::with_opts(Opts::new("zeno_transactions_failed_total", "Total failed transactions"))
                .expect("metric creation must succeed");
        let block_execution_time = Histogram::with_opts(
            HistogramOpts::new("zeno_block_execution_seconds", "Block execution latency")
                .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
        )
        .expect("metric creation must succeed");

        let mempool_size =
            IntGauge::with_opts(Opts::new("zeno_mempool_size", "Current mempool transaction count"))
                .expect("metric creation must succeed");
        let mempool_insertions =
            IntCounter::with_opts(Opts::new("zeno_mempool_insertions_total", "Total mempool insertions"))
                .expect("metric creation must succeed");
        let mempool_rejections =
            IntCounter::with_opts(Opts::new("zeno_mempool_rejections_total", "Total mempool rejections"))
                .expect("metric creation must succeed");

        let peers_connected =
            IntGauge::with_opts(Opts::new("zeno_peers_connected", "Number of connected peers"))
                .expect("metric creation must succeed");
        let messages_received =
            IntCounter::with_opts(Opts::new("zeno_messages_received_total", "Total messages received"))
                .expect("metric creation must succeed");
        let messages_sent =
            IntCounter::with_opts(Opts::new("zeno_messages_sent_total", "Total messages sent"))
                .expect("metric creation must succeed");

        let storage_reads =
            IntCounter::with_opts(Opts::new("zeno_storage_reads_total", "Total storage reads"))
                .expect("metric creation must succeed");
        let storage_writes =
            IntCounter::with_opts(Opts::new("zeno_storage_writes_total", "Total storage writes"))
                .expect("metric creation must succeed");

        let evm_calls =
            IntCounter::with_opts(Opts::new("zeno_evm_calls_total", "Total EVM calls"))
                .expect("metric creation must succeed");
        let evm_gas_used =
            IntCounter::with_opts(Opts::new("zeno_evm_gas_used_total", "Total EVM gas consumed"))
                .expect("metric creation must succeed");

        registry.register(Box::new(consensus_height.clone())).expect("register metric");
        registry.register(Box::new(consensus_round.clone())).expect("register metric");
        registry.register(Box::new(blocks_finalized.clone())).expect("register metric");
        registry.register(Box::new(blocks_proposed.clone())).expect("register metric");
        registry.register(Box::new(transactions_executed.clone())).expect("register metric");
        registry.register(Box::new(transactions_failed.clone())).expect("register metric");
        registry.register(Box::new(block_execution_time.clone())).expect("register metric");
        registry.register(Box::new(mempool_size.clone())).expect("register metric");
        registry.register(Box::new(mempool_insertions.clone())).expect("register metric");
        registry.register(Box::new(mempool_rejections.clone())).expect("register metric");
        registry.register(Box::new(peers_connected.clone())).expect("register metric");
        registry.register(Box::new(messages_received.clone())).expect("register metric");
        registry.register(Box::new(messages_sent.clone())).expect("register metric");
        registry.register(Box::new(storage_reads.clone())).expect("register metric");
        registry.register(Box::new(storage_writes.clone())).expect("register metric");
        registry.register(Box::new(evm_calls.clone())).expect("register metric");
        registry.register(Box::new(evm_gas_used.clone())).expect("register metric");

        Self {
            registry,
            consensus_height,
            consensus_round,
            blocks_finalized,
            blocks_proposed,
            transactions_executed,
            transactions_failed,
            block_execution_time,
            mempool_size,
            mempool_insertions,
            mempool_rejections,
            peers_connected,
            messages_received,
            messages_sent,
            storage_reads,
            storage_writes,
            evm_calls,
            evm_gas_used,
        }
    }
}

static METRICS: OnceLock<NodeMetrics> = OnceLock::new();

/// Returns the global metrics instance.
pub fn metrics() -> &'static NodeMetrics {
    METRICS.get_or_init(NodeMetrics::new)
}

/// Encodes all Prometheus metrics as text.
pub fn encode_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = metrics().registry.gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .expect("metric encoding must succeed");
    String::from_utf8(buffer).expect("metrics must be valid utf8")
}
