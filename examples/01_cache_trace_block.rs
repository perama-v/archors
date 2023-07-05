use anyhow::Result;
use archors_inventory::cache::{store_block_prestate_tracer, store_blockhash_opcode_reads};

/// Calls an archive node eth_traceBlock twice and caches the tracing results.
///
/// The tracing is performed twice because two types of information are needed:
/// - state accesses (prestateTracer), stored entirely.
/// - BLOCKHASH opcode accesses (default tracer), only store blockhashes accessed.
#[tokio::main]
async fn main() -> Result<()> {
    const NODE: &str = "http://127.0.0.1:8545";
    const BLOCK_NUMBER: u64 = 17539445;

    // store_block_prestate_tracer(NODE, BLOCK_NUMBER).await?;
    store_blockhash_opcode_reads(NODE, BLOCK_NUMBER).await?;

    Ok(())
}
