use anyhow::Result;
use archors_inventory::cache::store_deduplicated_state;

/// Uses a cached block prestate and groups account state data when it is accessed
/// in more than one transaction during a block.
fn main() -> Result<()> {
    // For example, deduplication reduces state data for block 17190873 from 13MB to 4MB.
    store_deduplicated_state(17190873)?;
    // After deduplication there is still room for compression as data is represented
    // multiple times still.
    Ok(())
}
