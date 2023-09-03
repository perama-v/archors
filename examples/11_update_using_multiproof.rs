use anyhow::Result;
use archors_inventory::cache::get_proofs_from_cache;
use archors_multiproof::eip1186::EIP1186MultiProof;

/// Uses cached accessed-state proofs and combines them into a multiproof that can be updated.
fn main() -> Result<()> {
    // Load a proofs for a block from cache.
    let _root_17190873 = "0x38e5e1dd67f7873cd8cfff08685a30734c18d0075318e9fca9ed64cc28a597da";

    // Get EIP-1186 proofs (one proof per account) for every state needed for a block.
    let proofs = get_proofs_from_cache(17190873)?
        .proofs
        .into_values()
        .collect();

    // Combine into a multiproof.
    let mut multiproof = EIP1186MultiProof::from_separate(proofs)?;

    // Modify a slot.
    let account = "0xTODO";
    let storage_key = "0xTODO";
    let storage_value = "0xTODO";
    multiproof.modify_slot(account, storage_key, storage_value)?;

    // Get the new state root.
    let root = multiproof.root();
    println!("Block state root after slot modification {root}");

    Ok(())
}
