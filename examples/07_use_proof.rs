
use anyhow::Result;
use archors_tracer::trace::trace_block;
use archors_inventory::cache::{get_block_from_cache, get_proofs_from_cache};

/// Consume one block state proof.
fn main() -> Result<()> {
    let block_number = 17190873;
    // Get block to execute (eth_getBlockByNumber).
    let block = get_block_from_cache(block_number)?;

    // Get state proofs (from peer / disk).
    let state = get_proofs_from_cache(block_number)?;

    // Trace block using state (eth_debugTraceTransaction).
    let trace = trace_block(block, state)?;

    Ok(())
}
