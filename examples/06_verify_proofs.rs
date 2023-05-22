use anyhow::Result;
use archors::{cache::get_proof_from_cache, utils::hex_decode};

/// Uses cached accessed-state proofs and verifies them.
fn main() -> Result<()> {
    // Load a proofs for a block from cache.
    let proofs = get_proof_from_cache(17190873)?;
    let state_root = hex_decode("0x38e5e1dd67f7873cd8cfff08685a30734c18d0075318e9fca9ed64cc28a597da")?;

    proofs.verify(&state_root)?;
    Ok(())
}
