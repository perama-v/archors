use std::{
    fs::{self, File},
    io::Write,
};

use anyhow::{bail, Result};
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
    env_logger::init();

    let args = AppArgs::parse();

    let mut file = prepare_file(&args).expect("Could not prepare file");

    let required_block_state = fetch_required_block_state(
        args.trace_block_node.as_ref(),
        args.get_proof_node.as_ref(),
        args.block_number,
    )
    .await?;

    let bytes = encode_ssz_snappy(required_block_state)?;
    match args.output {
        OutputKind::HexString => {
            let string = format!("0x{}", hex::encode(&bytes));
            file.write_all(string.as_bytes())?;
        }
        OutputKind::Binary => {
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

/// Creates a file and returns the handle to write to.
fn prepare_file(args: &AppArgs) -> Result<File> {
    let mut filename = format!("{}_{}", args.filename_prefix, args.block_number);
    match args.output {
        OutputKind::HexString => filename.push_str(".txt"),
        OutputKind::Binary => filename.push_str(".ssz_snappy"),
    };
    if fs::metadata(&filename).is_ok() {
        bail!("{} file aleady exists", filename);
    };
    Ok(File::create(filename)?)
}
