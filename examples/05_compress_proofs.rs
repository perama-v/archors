use anyhow::Result;
use archors_inventory::cache::compress_proofs;

/// Uses a cached block accessed state proof, compresses the file.
fn main() -> Result<()> {
    // A block state proof has many merkle tree nodes common between individual
    // account proofs. These can be compressed.

    // In block 17190873, one account proof node is repeated 162 times.
    // Representing state as .snappy can improve the footprint.
    compress_proofs(17190873)?;

    Ok(())
}
