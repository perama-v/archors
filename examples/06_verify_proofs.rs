use anyhow::Result;
use archors_inventory::{cache::get_proofs_from_cache, types::BlockProofs, utils::hex_decode};
use archors_verify::eip1186::{verify_proof};

/// Uses cached accessed-state proofs and verifies them.
fn main() -> Result<()> {
    // Load a proofs for a block from cache.
    let root_17190873 = "0x38e5e1dd67f7873cd8cfff08685a30734c18d0075318e9fca9ed64cc28a597da";
    let root_17193270 = "0xd4a8ad280d35fb08d20cffc275e9295db83b77366c2f75050bf6e61d1ef303bd";
    let root_17193183 = "0xeb7a68f112989f0584f91e09d7db1181cd35f6498abc41689d5ed68c96a3666e";

    prove_block_state(root_17190873, &get_proofs_from_cache(17190873)?)?;
    prove_block_state(root_17193270, &get_proofs_from_cache(17193270)?)?;
    prove_block_state(root_17193183, &get_proofs_from_cache(17193183)?)?;

    Ok(())
}

/// Verifies every EIP-1186 proof within a BlockProofs collection.
///
/// A block has proofs for many accounts (each with many storage proofs). Each
/// is verified separately.
fn prove_block_state(state_root: &str, block_state_proofs: &BlockProofs) -> Result<()> {
    let root = hex_decode(state_root)?;
    for proof in block_state_proofs.proofs.values() {
        verify_proof(&root, proof)?;
    }
    Ok(())
}
