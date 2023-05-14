use anyhow::Result;
use archors::cache::get_proof_from_cache;

/// Uses cached accessed-state proofs and verifies them.
fn main() -> Result<()> {
    // Load a proofs for a block from cache.
    let proofs = get_proof_from_cache(17190873)?;
    proofs.verify()?;
    Ok(())
}
