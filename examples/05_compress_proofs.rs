use anyhow::Result;
use archors_inventory::cache::{compress_proofs, create_transferrable_proof};

/// Uses a cached block accessed state proof and either:
/// - compresses the file.
/// - creates a file with a transferrable ssz format.
fn main() -> Result<()> {
    // A block state proof has many merkle tree nodes common between individual
    // account proofs. These can be compressed.

    // In block 17190873, one account proof node is repeated 162 times.
    // Representing state as .snappy can improve the footprint.
    // compress_proofs(17190873)?;

    // Package block state proof into a ssz format with minimal duplication of
    // data, optimised for transfer to a peer.
    create_transferrable_proof(17190873)?;

    Ok(())
}
