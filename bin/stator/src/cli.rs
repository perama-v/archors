//! For Command Line Interface for archors_stator

use clap::{Parser, ValueEnum};
use url::Url;

pub const LOCALHOST: &str = "http://127.0.0.1:8545/";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct AppArgs {
    /// File to create. E.g., <prefix>_<block_number>.txt / <prefix>_<block_number>.ssz_snappy
    #[clap(short, long, default_value_t = String::from("required_block_state"))]
    pub filename_prefix: String,
    /// Kind of data to write to file.
    #[clap(value_enum, default_value_t=OutputKind::HexString)]
    pub output: OutputKind,
    /// Url of node for eth_getProof requests
    #[clap(short, long, default_value_t = Url::parse(LOCALHOST).expect("Couldn't read node"))]
    pub get_proof_node: Url,
    /// Url of node for eth_getBlockByNumber and debug_traceBlock requests
    #[clap(short, long, default_value_t = Url::parse(LOCALHOST).expect("Couldn't read node"))]
    pub trace_block_node: Url,
    /// Block number to get state information for (the block that will be re-executed)
    #[clap(short, long)]
    pub block_number: u64,
}

/// Format of data to be written to file.
#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputKind {
    /// Create .txt with 0x-prefixed hex-string
    HexString,
    /// Create .ssz_snappy binary
    Binary,
}
