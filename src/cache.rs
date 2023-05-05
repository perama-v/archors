//! Used for calling a node and storing the result locally for testing.
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
};

use reqwest::Client;
use thiserror::Error;
use url::{ParseError, Url};
use web3::types::{Block, H256};

use crate::{
    rpc::{
        debug_trace_block_prestate, debug_trace_transaction_prestate, eth_get_proof,
        get_block_by_number, AccountProofResponse, BlockPrestateInnerTx, BlockPrestateResponse,
        BlockResponse, TxPrestateResponse,
    },
    types::{BlockPrestateTrace, BlockProofs, BlockStateAccesses},
    utils::hex_encode,
};

static CACHE_DIR: &str = "data/blocks";

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Block retrieved does not yet have a number")]
    NoBlockNumber,
    #[error("Reqwest error {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("IO error {0}")]
    IoError(#[from] io::Error),
    #[error("serde_json error {0}")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("Url error {0}")]
    UrlError(#[from] ParseError),
}

pub async fn store_block_with_transactions(url: &str, target_block: u64) -> Result<(), CacheError> {
    let block_number_hex = format!("0x{:x}", target_block);
    let client = Client::new();
    // Get a block.
    let block = client
        .post(Url::parse(url)?)
        .json(&get_block_by_number(&block_number_hex))
        .send()
        .await?
        .json::<BlockResponse>()
        .await?;

    let Some(block_number) = block.result.number else {
        return Err(CacheError::NoBlockNumber)
    };
    let dirname = PathBuf::from(format!("{CACHE_DIR}/{block_number}"));
    fs::create_dir_all(&dirname)?;
    let mut block_file = File::create(dirname.join("block_with_transactions.json"))?;
    block_file.write_all(serde_json::to_string_pretty(&block.result)?.as_bytes())?;
    Ok(())
}

/// Calls debug trace transaction with prestate tracer and caches the result.
pub async fn store_block_prestate_tracer(url: &str, target_block: u64) -> Result<(), CacheError> {
    let client = Client::new();
    let block_number_hex = format!("0x{:x}", target_block);

    let response: BlockPrestateResponse = client
        .post(Url::parse(url)?)
        .json(&debug_trace_block_prestate(&block_number_hex))
        .send()
        .await?
        .json()
        .await?;

    let dirname = PathBuf::from(format!("{CACHE_DIR}/{target_block}"));
    fs::create_dir_all(&dirname)?;
    let mut block_file = File::create(dirname.join("block_prestate_trace.json"))?;
    block_file.write_all(serde_json::to_string_pretty(&response.result)?.as_bytes())?;
    Ok(())
}

/// Uses a cached block prestate and groups account state data when it is accessed
/// in more than one transaction during a block.
///
/// Note that accounts can have the same bytecode (e.g., redeployments) and this
/// represent duplication that can be resolved with compression.
pub fn store_deduplicated_state(target_block: u64) -> Result<(), CacheError> {
    let dirname = PathBuf::from(format!("{CACHE_DIR}/{target_block}"));
    let block_file = dirname.join("block_prestate_trace.json");
    let data = fs::read_to_string(block_file)?;
    let block: Vec<BlockPrestateInnerTx> = serde_json::from_str(&data)?;

    let mut state_accesses = BlockStateAccesses::new();
    for tx_state in block {
        state_accesses.include_new_state_accesses_for_tx(&tx_state.result);
    }
    let dirname = PathBuf::from(format!("{CACHE_DIR}/{target_block}"));
    fs::create_dir_all(&dirname)?;
    let mut block_file = File::create(dirname.join("block_accessed_state_deduplicated.json"))?;
    block_file.write_all(serde_json::to_string_pretty(&state_accesses)?.as_bytes())?;
    Ok(())
}

/// Uses a cached record of accounts and storage slots and for each account calls
/// eth_getProof for those slots then stores all the proofs together.
pub async fn store_state_proofs(url: &str, target_block: u64) -> Result<(), CacheError> {
    let client = Client::new();
    let block_number_hex = format!("0x{:x}", target_block);
    let dirname = PathBuf::from(format!("{CACHE_DIR}/{target_block}"));
    let block_state_file = dirname.join("block_accessed_state_deduplicated.json");
    let data = fs::read_to_string(block_state_file)?;
    let state_accesses: BlockStateAccesses = serde_json::from_str(&data)?;
    let accounts_to_prove = state_accesses.get_all_accounts_to_prove();

    let mut block_proofs = BlockProofs {
        proofs: HashMap::new(),
    };

    for account in accounts_to_prove {
        let proof_request = eth_get_proof(&account, &block_number_hex);
        let response: AccountProofResponse = client
            .post(Url::parse(url)?)
            .json(&proof_request)
            .send()
            .await?
            .json()
            .await?;
        block_proofs.proofs.insert(account.address, response.result);
    }

    let dirname = PathBuf::from(format!("{CACHE_DIR}/{target_block}"));
    fs::create_dir_all(&dirname)?;
    let mut block_file = File::create(dirname.join("block_state_proofs.json"))?;
    block_file.write_all(serde_json::to_string_pretty(&block_proofs)?.as_bytes())?;
    Ok(())
}

/// Uses a cached deduplicated block prestate compresses the data.
///
/// This is important because some bytecode may exist multiple times
/// at different addresses.
pub fn compress_deduplicated_state(target_block: u64) -> Result<(), CacheError> {
    let dirname = PathBuf::from(format!("{CACHE_DIR}/{target_block}"));
    let block_file = dirname.join("block_accessed_state_deduplicated.json");
    let data = fs::read_to_string(block_file)?;
    let block: BlockStateAccesses = serde_json::from_str(&data)?;

    todo!("snappy");
    let compressed = "todo";

    let dirname = PathBuf::from(format!("{CACHE_DIR}/{target_block}"));
    fs::create_dir_all(&dirname)?;
    let mut block_file = File::create(dirname.join("block_accessed_state_compressed.snappy"))?;
    block_file.write_all(serde_json::to_string_pretty(&compressed)?.as_bytes())?;
    Ok(())
}

/// Uses a cached block accessed state proofs and compresses the data.
///
/// This is effective because there are many nodes within the proofs that are
/// common between proofs.
pub fn compress_proofs(target_block: u64) -> Result<(), CacheError> {
    let dirname = PathBuf::from(format!("{CACHE_DIR}/{target_block}"));
    let block_file = dirname.join("block_state_proofs.json");
    let data = fs::read_to_string(block_file)?;
    let proofs: BlockProofs = serde_json::from_str(&data)?;

    todo!("snappy");
    let compressed = "todo";

    let dirname = PathBuf::from(format!("{CACHE_DIR}/{target_block}"));
    fs::create_dir_all(&dirname)?;
    let mut block_file = File::create(dirname.join("block_state_proof_compressed.snappy"))?;
    block_file.write_all(serde_json::to_string_pretty(&compressed)?.as_bytes())?;
    Ok(())
}

/// Uses a cached block to individually prestate trace each transaction and store the result.
pub async fn _store_block_prestate_tracer_granular(
    url: &str,
    target_block: u64,
) -> Result<(), CacheError> {
    let dirname = PathBuf::from(format!("{CACHE_DIR}/{target_block}"));
    let block_file = dirname.join("block_with_transactions.json");
    let data = fs::read_to_string(block_file)?;
    let block: Block<H256> = serde_json::from_str(&data)?;

    let client = Client::new();
    let mut block_trace = BlockPrestateTrace {
        block_number: target_block,
        prestate_traces: vec![],
    };

    for tx in block.transactions {
        let response: TxPrestateResponse = client
            .post(Url::parse(url)?)
            .json(&debug_trace_transaction_prestate(&hex_encode(
                tx.as_bytes(),
            )))
            .send()
            .await?
            .json()
            .await?;

        block_trace.prestate_traces.push(response.result);
    }

    let dirname = PathBuf::from(format!("data/blocks/{}", target_block));
    fs::create_dir_all(&dirname)?;
    let mut block_file = File::create(dirname.join("block_transactions_prestate_traces.json"))?;
    block_file.write_all(serde_json::to_string_pretty(&block_trace)?.as_bytes())?;
    Ok(())
}
