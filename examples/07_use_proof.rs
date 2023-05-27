use anyhow::Result;
use archors_inventory::cache::{
    get_block_from_cache, get_contracts_from_cache, get_proofs_from_cache,
};
use archors_tracer::{state::BlockProofsBasic, trace::BlockExecutor};

/// Consume one block state proof.
fn main() -> Result<()> {
    let block_number = 17190873;
    // Get block to execute (eth_getBlockByNumber).
    let block = get_block_from_cache(block_number)?;

    // Get state proofs (from peer / disk).
    let required_state = get_proofs_from_cache(block_number)?;
    let required_code = get_contracts_from_cache(block_number)?;

    // Trace block using state (eth_debugTraceTransaction).
    let state = BlockProofsBasic {
        proofs: required_state.proofs,
        code: required_code,
    };
    let executor = BlockExecutor::load(block, state)?;

    // Either trace the full block or a single transaction of interest.
    executor.trace_transaction(14)?;
    //executor.trace_block()?;

    Ok(())
}
