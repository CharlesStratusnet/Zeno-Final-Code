//! Node runtime.

mod consensus_plane;
mod execution_plane;
mod network_plane;
/// Operations plane: observability, metrics, and operator tooling.
pub mod operations_plane;
mod runtime;

pub use operations_plane::init_tracing;
pub use runtime::{in_memory_node, load_wallet_key, Node};
