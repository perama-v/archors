use anyhow::Result;
use archors_inventory::cache::{get_block_from_cache, get_proofs_from_cache};
use archors_multiproof::eip1186::EIP1186MultiProof;
use archors_types::execution::StateForEvm;

/// Uses cached accessed-state proofs and combines them into a multiproof that can be updated.
fn main() -> Result<()> {
    // Load a proofs for a block from cache.
    let _root_17190873 = "0x38e5e1dd67f7873cd8cfff08685a30734c18d0075318e9fca9ed64cc28a597da";
    let block_number = 17190873;
    // Get EIP-1186 proofs (one proof per account) for every state needed for a block.
    let proofs = get_proofs_from_cache(block_number)?
        .proofs
        .into_values()
        .collect();

    let prior_block = get_block_from_cache(block_number - 1)?;

    // Combine into a multiproof.
    let mut multiproof = EIP1186MultiProof::from_separate(proofs, prior_block.state_root)?;

    // Modify a slot.
    let account = "0xTODO";
    let storage_key = "0xTODO";
    let storage_value = "0xTODO";

    // Get the new state root.
    let changes = todo!();
    let post_block_root = multiproof.state_root_post_block(changes)?;
    println!("Block state root after slot modification {post_block_root}");

    // Check that it matches the state root in that block.
    let block = get_block_from_cache(block_number)?;
    assert_eq!(block.state_root, post_block_root);

    Ok(())
}
