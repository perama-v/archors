use std::{fs::{File, self}, io::Write};

use anyhow::Result;
use archors_inventory::{cache::fetch_required_block_state, utils::compress};
use archors_types::state::RequiredBlockState;
use clap::Parser;
use cli::OutputKind;

use crate::cli::AppArgs;

mod cli;

/// Create RequiredBlockState data type.
///
/// Calls an archive node and gets all information that is required to trace a block locally.
/// Discards intermediate data. Resulting RequiredBlockState data type can be sent to a
/// peer who can use it to trustlessly trace an historical Ethereum block.
///
/// Involves:
/// - debug_traceBlock for state accesses
/// - debug_traceBlock for blockhash use
/// - eth_getProof for proof of historical state
#[tokio::main]
async fn main() -> Result<()> {
    let args = AppArgs::parse();

    // store_block_with_transactions(&args.trace_block_node.as_ref(), args.block_number).await?;

    let required_block_state = fetch_required_block_state(
        args.trace_block_node.as_ref(),
        args.get_proof_node.as_ref(),
        args.block_number,
    )
    .await?;

    let bytes = encode_ssz_snappy(required_block_state)?;
    match args.output {
        OutputKind::HexString => {
            let filename = format!("{}.txt", args.filename);
            fs::metadata(&filename).expect("Oops, file already exists.");
            let mut file = File::create(filename)?;

            let string = format!("{:02X?}", bytes);
            file.write_all(string.as_bytes())?;
        }
        OutputKind::Binary => {
            let filename = format!("{}.ssz_snappy", args.filename);
            fs::metadata(&filename).expect("Oops, file already exists.");
            let mut file = File::create(filename)?;
            
            file.write_all(&bytes)?;
        }
    };
    Ok(())
}

/// required block state -> .ssz_snappy
fn encode_ssz_snappy(state: RequiredBlockState) -> anyhow::Result<Vec<u8>> {
    let ssz = state.to_ssz_bytes()?;
    let ssz_snappy = compress(ssz)?;
    Ok(ssz_snappy)
}
