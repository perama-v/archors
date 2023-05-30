use anyhow::Result;
use archors_inventory::overlap::measure_proof_overlap;

/// Compares cached transferrable block proofs and quantifies the degree
/// of data overlap (contracts, nodes). This represents data that a node
/// would not have to duplicate on disk.
fn main() -> Result<()> {
    let data_saved = measure_proof_overlap(vec![17190873, 17193183 /*, 17193270*/])?;
    println!("{data_saved}");

    Ok(())
}
