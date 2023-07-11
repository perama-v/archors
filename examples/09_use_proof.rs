use anyhow::Result;
use archors_inventory::cache::{get_block_from_cache, get_required_state_from_cache};
use archors_tracer::trace::BlockExecutor;

/// Consume one block state proof.
fn main() -> Result<()> {
    let block_number = 17190873;
    // Get block to execute (eth_getBlockByNumber).
    let block = get_block_from_cache(block_number)?;

    // Get state proofs (from peer / disk).
    let state = get_required_state_from_cache(block_number)?;

    let executor = BlockExecutor::load(block, state)?;

    // Either trace the full block or a single transaction of interest.
    executor.trace_transaction(204)?;
    //executor.trace_block()?;

    Ok(())
}
