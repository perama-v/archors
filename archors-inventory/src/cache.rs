//! Used for calling a node and storing the result locally for testing.
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufReader, Write},
    path::PathBuf,
};

use reqwest::Client;
use thiserror::Error;
use url::{ParseError, Url};

use crate::{
    rpc::{
        debug_trace_block_prestate, eth_get_proof, get_block_by_number, AccountProofResponse,
        BlockPrestateInnerTx, BlockPrestateResponse, BlockResponse,
    },
    types::{BlockProofs, BlockStateAccesses},
    utils::{compress, UtilsError},
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
    #[error("Utils error {0}")]
    UtilsError(#[from] UtilsError),
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
    let names = CacheFileNames::new(block_number.as_u64());
    fs::create_dir_all(names.dirname())?;
    let mut block_file = File::create(names.block_with_transactions())?;
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

    let names = CacheFileNames::new(target_block);
    fs::create_dir_all(names.dirname())?;
    let mut block_file = File::create(names.block_prestate_trace())?;
    block_file.write_all(serde_json::to_string_pretty(&response.result)?.as_bytes())?;
    Ok(())
}

/// Uses a cached block prestate and groups account state data when it is accessed
/// in more than one transaction during a block.
///
/// Note that accounts can have the same bytecode (e.g., redeployments) and this
/// represent duplication that can be resolved with compression.
pub fn store_deduplicated_state(target_block: u64) -> Result<(), CacheError> {
    let names = CacheFileNames::new(target_block);
    let data = fs::read_to_string(names.block_prestate_trace())?;
    let block: Vec<BlockPrestateInnerTx> = serde_json::from_str(&data)?;

    let mut state_accesses = BlockStateAccesses::new();
    for tx_state in block {
        state_accesses.include_new_state_accesses_for_tx(&tx_state.result);
    }
    fs::create_dir_all(names.dirname())?;
    let mut block_file = File::create(names.block_accessed_state_deduplicated())?;
    block_file.write_all(serde_json::to_string_pretty(&state_accesses)?.as_bytes())?;
    Ok(())
}

/// Uses a cached record of accounts and storage slots and for each account calls
/// eth_getProof for those slots then stores all the proofs together.
pub async fn store_state_proofs(url: &str, target_block: u64) -> Result<(), CacheError> {
    let client = Client::new();
    let block_number_hex = format!("0x{:x}", target_block);
    let names = CacheFileNames::new(target_block);
    let data = fs::read_to_string(names.block_accessed_state_deduplicated())?;
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
    fs::create_dir_all(names.dirname())?;
    let mut block_file = File::create(names.block_state_proofs())?;
    block_file.write_all(serde_json::to_string_pretty(&block_proofs)?.as_bytes())?;
    Ok(())
}

/// Uses a cached deduplicated block prestate compresses the data.
///
/// This is important because some bytecode may exist multiple times
/// at different addresses.
pub fn compress_deduplicated_state(target_block: u64) -> Result<(), CacheError> {
    let names = CacheFileNames::new(target_block);
    let data = fs::read(names.block_accessed_state_deduplicated())?;
    let compressed = compress(data)?;
    let mut file = File::create(names.block_accessed_state_deduplicated_compressed())?;
    file.write_all(&compressed)?;
    Ok(())
}

/// Uses a cached block accessed state proofs and compresses the data.
///
/// This is effective because there are many nodes within the proofs that are
/// common between proofs.
pub fn compress_proofs(target_block: u64) -> Result<(), CacheError> {
    let names = CacheFileNames::new(target_block);
    let block_file = names.block_state_proofs();
    let data = fs::read(block_file)?;
    let compressed = compress(data)?;
    let mut file = File::create(names.block_state_proofs_compressed())?;
    file.write_all(&compressed)?;
    Ok(())
}

/// Retrieves the accessed-state proofs for a single block from cache.
pub fn get_proofs_from_cache(block: u64) -> Result<BlockProofs, CacheError> {
    let proof_cache_path = CacheFileNames::new(block).block_state_proofs();
    let file = File::open(proof_cache_path)?;
    let reader = BufReader::new(file);
    let block_proofs = serde_json::from_reader(reader)?;
    Ok(block_proofs)
}

/// Helper for consistent cached file and directory names.
struct CacheFileNames {
    block: u64,
}

impl CacheFileNames {
    fn new(block: u64) -> Self {
        Self { block }
    }
    fn dirname(&self) -> PathBuf {
        PathBuf::from(format!("{CACHE_DIR}/{}", self.block))
    }
    fn block_accessed_state_deduplicated(&self) -> PathBuf {
        self.dirname()
            .join("block_accessed_state_deduplicated.json")
    }
    fn block_accessed_state_deduplicated_compressed(&self) -> PathBuf {
        self.dirname()
            .join("block_accessed_state_deduplicated.snappy")
    }
    fn block_prestate_trace(&self) -> PathBuf {
        self.dirname().join("block_prestate_trace.json")
    }
    fn block_state_proofs(&self) -> PathBuf {
        self.dirname().join("block_state_proofs.json")
    }
    fn block_state_proofs_compressed(&self) -> PathBuf {
        self.dirname().join("block_state_proofs.snappy")
    }
    fn block_with_transactions(&self) -> PathBuf {
        self.dirname().join("block_with_transactions.json")
    }
}
