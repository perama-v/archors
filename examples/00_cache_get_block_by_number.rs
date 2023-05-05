use anyhow::Result;
use archors::cache::store_block_with_transactions;

/// Request and store a block for later use.
#[tokio::main]
async fn main() -> Result<()> {
    store_block_with_transactions("http://127.0.0.1:8545", 17190873).await?;
    Ok(())
}
