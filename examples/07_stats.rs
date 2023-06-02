use anyhow::Result;
use archors_inventory::{
    cache::{get_block_from_cache, get_transferrable_proofs_from_cache},
    overlap::measure_proof_overlap,
    utils::compress,
};

/// Request and store a block for later use.
#[tokio::main]
async fn main() -> Result<()> {
    let blocks = vec![
        17370975, 17370925, 17370875, 17370825, 17370775, 17370725, 17370675, 17370625, 17370575,
        17370525, 17370475, 17370425, 17370375, 17370325, 17370275, 17370225, 17370175, 17370125,
        17370075, 17370025,
    ];
    let blocks: Vec<u64> = blocks.into_iter().rev().collect();
    println!("|block number|block gas|block .ssz_snappy p2p wire|block wire per gas|block .ssz disk| block disk per gas|block count|cumulative sum duplicate discardable data|percentage disk saved");
    println!("|-|-|-|-|-|-|-|-|-|");
    let mut total_ssz_disk_kb = 0;
    let mut total_kgas = 0;
    let mut total_snappy_kb_per_mgas = 0;
    let mut total_data_saved_kb = 0;
    for i in 0..20 {
        let block_num = blocks[i];
        // Get gas
        let block = get_block_from_cache(block_num)?;
        let kgas = (block.gas_used / 1000).as_usize();
        total_kgas += kgas;

        let proof = get_required_state_from_cache(block_num)?;

        // Get disk size ssz
        let ssz_bytes = proof.to_ssz_bytes()?;
        let ssz_size_kb = ssz_bytes.len() / 1000;
        total_ssz_disk_kb += ssz_size_kb;
        let ssz_kb_per_mgas = 1000 * ssz_size_kb / kgas;

        // Get wire size ssz_snappy
        let snappy_size = compress(ssz_bytes)?.len();
        let snappy_size_kb = snappy_size / 1000;
        let snappy_kb_per_mgas = 1000 * snappy_size_kb / kgas;
        total_snappy_kb_per_mgas += snappy_kb_per_mgas;

        total_data_saved_kb =
            measure_proof_overlap(blocks[..=i].to_owned())?.total_savings() / 1000;
        let percentage_saved = 100 * total_data_saved_kb / total_ssz_disk_kb;
        let count = i + 1;

        let mgas = kgas / 1000;
        println!("|{block_num}|{mgas} Mgas|{snappy_size_kb} kB|{snappy_kb_per_mgas} KB/Mgas|{ssz_size_kb} KB|{ssz_kb_per_mgas} KB/Mgas|{count}|{total_data_saved_kb} kB|{percentage_saved}%|");
    }
    let final_disk = total_ssz_disk_kb - total_data_saved_kb;
    let average_disk_kb_per_mgas = final_disk / (total_kgas / 1000);
    println!("\nAverage disk (duplicate data excluded): {average_disk_kb_per_mgas} KB/Mgas");

    let average_wire_kb_per_mgas = total_snappy_kb_per_mgas / blocks.len();
    println!("Average wire: {average_wire_kb_per_mgas} KB/Mgas");
    Ok(())
}
