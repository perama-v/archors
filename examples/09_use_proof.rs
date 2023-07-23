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
    /*
    Notable transactions for block: 17190873
    - 2,
    - 14: Failed swap
    - 28: Failed contract execution
    - 37: Failed contract execution
    - 95: Coinbase using multiple CALL to send ether to EOAs.
    - 196, 204,
    - 205 simple transfer (final tx)
    */
    executor.trace_transaction(95)?;
    //executor.trace_block()?;

    Ok(())
}
