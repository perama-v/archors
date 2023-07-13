use anyhow::Result;
use archors_inventory::cache::{store_block_with_transactions, store_required_state};

/// Calls an archive node and gets all information that is required to trace a block locally.
/// Discards intermediate data.
///
/// Involves:
/// - eth_traceBlock for state accesses
/// - eth_traceBlock for blockhash use
/// - eth_getProof for proof of historical state
#[tokio::main]
async fn main() -> Result<()> {
    let url =
        std::env::var("GET_PROOF_NODE").expect("Environment variable GET_PROOF_NODE not found");
    const BLOCK_NUMBER: u64 = 17170873;

    store_block_with_transactions(&url, BLOCK_NUMBER).await?;
    store_required_state(&url, BLOCK_NUMBER).await?;

    Ok(())
}
