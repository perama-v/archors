use anyhow::Result;
use archors::{cache::get_proof_from_cache, utils::hex_decode};

/// Uses cached accessed-state proofs and verifies them.
fn main() -> Result<()> {
    // Load a proofs for a block from cache.
    let state_root_17190873 =
        hex_decode("0x38e5e1dd67f7873cd8cfff08685a30734c18d0075318e9fca9ed64cc28a597da")?;
    let state_root_17193270 =
        hex_decode("0xd4a8ad280d35fb08d20cffc275e9295db83b77366c2f75050bf6e61d1ef303bd")?;
    let state_root_17193183 =
        hex_decode("0xeb7a68f112989f0584f91e09d7db1181cd35f6498abc41689d5ed68c96a3666e")?;

    get_proof_from_cache(17193270)?.verify(&state_root_17193270)?;
    get_proof_from_cache(17190873)?.verify(&state_root_17190873)?;
    get_proof_from_cache(17193183)?.verify(&state_root_17193183)?;

    Ok(())
}
