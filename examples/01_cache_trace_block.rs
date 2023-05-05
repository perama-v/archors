use anyhow::Result;
use archors::cache::store_block_prestate_tracer;

/// Uses a cached block to trace each transaction. Caches the result.
#[tokio::main]
async fn main() -> Result<()> {
    store_block_prestate_tracer("http://127.0.0.1:8545", 17190873).await?;
    Ok(())
}
