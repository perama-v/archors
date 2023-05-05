use std::env;

use anyhow::Result;
use archors::cache::store_state_proofs;

/// Uses cached account and storage keys and gets a proof with respect
/// to a block.
#[tokio::main]
async fn main() -> Result<()> {
    let url = env::var("GET_PROOF_NODE").expect("Environment variable GET_PROOF_NODE not found");

    store_state_proofs(&url, 17190873).await?;

    Ok(())
}
