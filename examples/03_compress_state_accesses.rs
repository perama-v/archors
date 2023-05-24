use anyhow::Result;
use archors_inventory::cache::compress_deduplicated_state;

/// Uses a cached deduplicated block prestate, compress the data for reduced
/// disk use.
fn main() -> Result<()> {
    // After deduplication there is still room for compression.
    // In block 17190873, one contract is repeated 27 times.
    // Representing state as .snappy can improve the footprint.
    compress_deduplicated_state(17190873)?;

    Ok(())
}
