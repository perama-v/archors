use anyhow::Result;
use archors_inventory::cache::{
    get_block_from_cache, get_required_state_from_cache, store_block_with_transactions,
    store_required_state,
};
use archors_tracer::trace::{BlockExecutor, PostExecutionProof};

/// Create, cache and then use the RequiredBlockState data type.
///
/// Calls an archive node and gets all information that is required to trace a block locally.
/// Discards intermediate data. Resulting RequiredBlockState data type can be sent to a
/// peer who can use it to trustlessly trace an historical Ethereum block.
///
/// Involves:
/// - debug_traceBlock for state accesses
/// - debug_traceBlock for blockhash use
/// - eth_getProof for proof of historical state
#[tokio::main]
async fn main() -> Result<()> {
    // Create and cache RequiredBlockState
    const NODE: &str = "http://127.0.0.1:8545";
    let proof_node =
        std::env::var("GET_PROOF_NODE").expect("Environment variable GET_PROOF_NODE not found");
    const BLOCK_NUMBER: u64 = 17190873;

    store_block_with_transactions(&NODE, BLOCK_NUMBER).await?;
    store_required_state(&NODE, &proof_node, BLOCK_NUMBER).await?;

    // Use the cached RequiredBlockState
    let block = get_block_from_cache(BLOCK_NUMBER)?;
    let state = get_required_state_from_cache(BLOCK_NUMBER)?;
    let executor = BlockExecutor::load(block, state, PostExecutionProof::Ignore)?;

    // Either trace the full block or a single transaction of interest.
    executor.trace_transaction(13)?;
    //executor.trace_block()?;
    Ok(())
}
