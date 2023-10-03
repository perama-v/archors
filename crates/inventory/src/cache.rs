//! Used for calling a node and storing the result locally for testing.
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufReader, Write},
    path::PathBuf,
};

use archors_types::{
    oracle::TrieNodeOracle,
    state::{RequiredBlockState, StateError},
};
use ethers::{
    abi::ethereum_types::FromStrRadixErr,
    types::{Block, Transaction, H160, H256, U64},
    utils::keccak256,
};
use futures::stream::StreamExt;
use log::{info, debug};
use reqwest::Client;
use thiserror::Error;
use url::{ParseError, Url};

use crate::{
    oracle::{detect_removed_storage, OracleError},
    rpc::{
        debug_trace_block_default, debug_trace_block_prestate, eth_get_proof, get_block_by_number,
        AccountProofResponse, BlockDefaultTraceResponse, BlockPrestateResponse,
        BlockPrestateTransactions, BlockResponse, JsonRpcRequest,
    },
    transferrable::{state_from_parts, TransferrableError},
    types::{BlockHashAccess, BlockHashAccesses, BlockProofs, BlockStateAccesses},
    utils::{compress, decompress, hex_decode, string_to_h256, UtilsError},
};

static CACHE_DIR: &str = "data/blocks";

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Unable to decode JSON-RPC request ({request}) response {source}")]
    DecodingFailed {
        source: reqwest::Error,
        request: JsonRpcRequest,
    },
    #[error("Block retrieved does not yet have a number")]
    NoBlockNumber,
    #[error("Node oracle error {0}")]
    OracleError(#[from] OracleError),
    #[error("Reqwest error {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("IO error {0}")]
    IoError(#[from] io::Error),
    #[error("Unable to create block number from string {0}")]
    InvalidBlockNumber(#[from] FromStrRadixErr),
    #[error("Unable to peek next EVM step")]
    EvmPeekAbsent,
    #[error("serde_json error {0}")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("EVM stack empty, expected item")]
    StackEmpty,
    #[error("State type error {0}")]
    StateError(#[from] StateError),
    #[error("Transferrable error {0}")]
    TransferrableError(#[from] TransferrableError),
    #[error("Url error {0}")]
    UrlError(#[from] ParseError),
    #[error("Utils error {0}")]
    UtilsError(#[from] UtilsError),
    #[error("File {filename} could not be opened {source}")]
    FileOpener {
        source: io::Error,
        filename: PathBuf,
    },
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
        return Err(CacheError::NoBlockNumber);
    };
    let names = CacheFileNames::new(block_number.as_u64());
    fs::create_dir_all(names.dirname())?;
    let mut block_file = File::create(names.block_with_transactions())?;
    block_file.write_all(serde_json::to_string_pretty(&block.result)?.as_bytes())?;
    Ok(())
}

/// Retrieves required state for a particular cached block.
///
/// Creates a transferrable state parcel without the creation of intermediate cache files.
pub async fn fetch_required_block_state(
    url: &str,
    get_proof_url: &str,
    target_block: u64,
) -> Result<RequiredBlockState, CacheError> {
    // Prestate-trace the block. Then deduplicate. Then getProof for prior block.
    info!("1/6 requesting debug_traceBlock with prestate tracer");
    let tx_prestates = request_prestate_tracer(url, target_block).await?;
    info!("2/6 extracting unique state accesses");
    let accesses = BlockStateAccesses::from_prestate_accesses(tx_prestates);
    let account_num = accesses.access_data.len();
    info!("3/6 requesting eth_getProof for accessed states ({account_num} separate calls)");
    let proofs = request_proofs(get_proof_url, &accesses, target_block).await?;
    // Parse from prestate-trace.
    info!("4/6 extracting contract bytecode from state access response");
    let mut contracts: Vec<ContractBytes> = contracts_from_state(accesses)?.into_values().collect();
    contracts.sort();
    // Trace (no-memory) the block. Then filter for BLOCKHASH opcode.
    info!("5/6 requesting debug_traceBlock with default trace (for BLOCKHASH opcode)");
    let blockhashes = fetch_blockhashes(url, target_block).await?;
    info!("6/6 constructing RequiredBlockState");
    let required_block_state = state_from_parts(proofs, contracts, blockhashes)?;
    Ok(required_block_state)
}

/// Retrieves and stores required state for a particular cached block.
///
/// Creates a transferrable state parcel without the creation of intermediate cache files.
pub async fn store_required_state(
    url: &str,
    get_proof_url: &str,
    target_block: u64,
) -> Result<(), CacheError> {
    let data = fetch_required_block_state(url, get_proof_url, target_block).await?;
    save_transferrable_data(target_block, data)?;
    Ok(())
}

/// Calls debug trace transaction with prestate tracer and caches the result.
///
/// This inclues accounts, each with
/// - balance
/// - code
///     - Needed to be able to execute the code.
///     - Codehash will be part of the block state proof.
/// - nonce
///     - Does not need to be in block state proof.
///     - Tx sender nonce is in the block (eth_getBlockByNumber).
/// - storage
///     - Composed of (key, value).
///     - Will be used with eth_getProof.
pub async fn store_block_prestate_tracer(url: &str, target_block: u64) -> Result<(), CacheError> {
    let tx_prestates = request_prestate_tracer(url, target_block).await?;
    let names = CacheFileNames::new(target_block);
    fs::create_dir_all(names.dirname())?;
    let mut block_file = File::create(names.block_prestate_trace())?;
    block_file.write_all(serde_json::to_string_pretty(&tx_prestates)?.as_bytes())?;
    Ok(())
}

async fn request_prestate_tracer(
    url: &str,
    target_block: u64,
) -> Result<Vec<BlockPrestateTransactions>, CacheError> {
    let client = Client::new();
    let block_number_hex = format!("0x{:x}", target_block);
    let request = debug_trace_block_prestate(&block_number_hex);
    let response: BlockPrestateResponse = client
        .post(Url::parse(url)?)
        .json(&request)
        .send()
        .await?
        .json()
        .await
        .map_err(|e| CacheError::DecodingFailed { source: e, request })?;
    Ok(response.result)
}

/// Obtains and stores BLOCKHASH opcode use as cache file.
pub async fn store_blockhash_opcode_reads(url: &str, target_block: u64) -> Result<(), CacheError> {
    let hashes = fetch_blockhashes(url, target_block).await?;

    let names = CacheFileNames::new(target_block);
    let dir = names.dirname();
    fs::create_dir_all(dir)?;
    let mut blockhash_file = File::create(names.blockhashes())?;
    blockhash_file.write_all(serde_json::to_string_pretty(&hashes)?.as_bytes())?;

    Ok(())
}

/// Calls debug_traceBlock with the default tracer and filters the result
/// for BLOCKHASH opcode use.
///
/// The results (up to 256 pairs of block number / blockhash pairs) are stored.
///
/// Uses a temp file to store the trace instead of holding in memory.
///
/// Alternative, use terminal and use grep/jq to avoid disk write.
async fn fetch_blockhashes(url: &str, target_block: u64) -> Result<BlockHashAccesses, CacheError> {
    let names = CacheFileNames::new(target_block);
    let dir = names.dirname();
    fs::create_dir_all(dir)?;

    let mut trace_filename = names.dirname();
    trace_filename.push("temp_trace_for_blockhash_opcode.txt");
    let mut trace_file = File::create(&trace_filename)?;
    // Get the trace from the node and store temporarily.
    let client = Client::new();
    let block_number_hex = format!("0x{:x}", target_block);

    let response = client
        .post(Url::parse(url)?)
        .json(&debug_trace_block_default(&block_number_hex))
        .send()
        .await?;

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        trace_file.write_all(&chunk?)?;
    }
    drop(trace_file);

    // Read the trace from file and filter for blockhash opcode.
    let file = File::open(&trace_filename).map_err(|e| CacheError::FileOpener {
        source: e,
        filename: trace_filename.to_owned(),
    })?;
    let mut reader = BufReader::new(file);
    let stream =
        serde_json::Deserializer::from_reader(&mut reader).into_iter::<BlockDefaultTraceResponse>();

    let mut blockhash_reads: HashMap<U64, H256> = HashMap::new();
    for response in stream {
        for tx in response?.result {
            let mut steps = tx.result.struct_logs.iter().peekable();
            while let Some(step) = steps.next() {
                if step.op == "BLOCKHASH" {
                    let block_number_string = step.stack.last().ok_or(CacheError::StackEmpty)?;
                    let block_number = U64::from_str_radix(block_number_string, 16)
                        .map_err(CacheError::InvalidBlockNumber)?;
                    let block_hash_string = steps
                        .peek()
                        .ok_or(CacheError::EvmPeekAbsent)?
                        .stack
                        .last()
                        .ok_or(CacheError::StackEmpty)?;
                    let block_hash = string_to_h256(block_hash_string)?;
                    blockhash_reads.insert(block_number.to_owned(), block_hash.to_owned());
                }
            }
        }
    }

    let hashes = BlockHashAccesses {
        blockhash_accesses: blockhash_reads
            .into_iter()
            .map(|(block_number, block_hash)| BlockHashAccess {
                block_number,
                block_hash,
            })
            .collect::<Vec<BlockHashAccess>>(),
    };

    // Remove the temp trace file
    fs::remove_file(trace_filename)?;

    Ok(hashes)
}

/// Uses a cached block prestate and groups account state data when it is accessed
/// in more than one transaction during a block.
///
/// Note that accounts can have the same bytecode (e.g., redeployments) and this
/// represent duplication that can be resolved with compression.
pub fn store_deduplicated_state(target_block: u64) -> Result<(), CacheError> {
    let names = CacheFileNames::new(target_block);
    let filename = names.block_prestate_trace();
    let data = fs::read_to_string(&filename).map_err(|e| CacheError::FileOpener {
        source: e,
        filename,
    })?;
    let block: Vec<BlockPrestateTransactions> = serde_json::from_str(&data)?;
    let state_accesses = BlockStateAccesses::from_prestate_accesses(block);
    fs::create_dir_all(names.dirname())?;
    let mut block_file = File::create(names.block_accessed_state_deduplicated())?;
    block_file.write_all(serde_json::to_string_pretty(&state_accesses)?.as_bytes())?;
    Ok(())
}

/// Uses a cached record of accounts and storage slots and for each account calls
/// eth_getProof for those slots then stores all the proofs together.
///
/// The block used for eth_getProof will be the block prior to the target block.
/// This is because the state will be used to execute a block with.
///
/// The prior block's state root is the root after transactions have been applied.
/// Hence it is the state on which the target block should be applied.
///
/// The proofs are also requested for the block, which are used in two ways: debugging
/// and to potentially provide internal nodes which may be required in post-execution
/// state root computation. This doubles the calls to get_proof, and this second set of
/// calls is not required if the post-execution root is not required.
pub async fn store_state_proofs(url: &str, target_block: u64) -> Result<(), CacheError> {
    let prior_block = target_block - 1;
    let names = CacheFileNames::new(target_block);
    let filename = names.block_accessed_state_deduplicated();
    let data = fs::read_to_string(&filename).map_err(|e| CacheError::FileOpener {
        source: e,
        filename,
    })?;
    let state_accesses: BlockStateAccesses = serde_json::from_str(&data)?;

    // Get proofs for prior block
    let block_proofs = request_proofs(url, &state_accesses, prior_block).await?;
    fs::create_dir_all(names.dirname())?;
    let mut block_file = File::create(names.prior_block_state_proofs())?;
    block_file.write_all(serde_json::to_string_pretty(&block_proofs)?.as_bytes())?;

    // Get proofs for block. These are used for debugging post-execution proofs.
    let block_proofs = request_proofs(url, &state_accesses, target_block).await?;
    fs::create_dir_all(names.dirname())?;
    let mut block_file = File::create(names.block_state_proofs())?;
    block_file.write_all(serde_json::to_string_pretty(&block_proofs)?.as_bytes())?;
    // They could also be used for internal nodes.
    Ok(())
}

/// Calls a node eth_getProof endpoint for every given accessed state.
///
/// Note that proofs are post-execution.
///
/// To get the proofs for "state ready to trace the target block", the target
/// block should be the block prior to the one that will be traced.
async fn request_proofs(
    url: &str,
    accesses: &BlockStateAccesses,
    target_block: u64,
) -> Result<BlockProofs, CacheError> {
    let client = Client::new();
    let accounts_to_prove = accesses.get_all_accounts_to_prove();

    let mut block_proofs = BlockProofs {
        proofs: HashMap::new(),
    };
    let prior_block_number_hex = format!("0x{:x}", target_block);
    for account in accounts_to_prove {
        let proof_request = eth_get_proof(&account, &prior_block_number_hex);
        let account = H160::from_slice(&hex_decode(account.address)?);
        let response: AccountProofResponse = client
            .post(Url::parse(url)?)
            .json(&proof_request)
            .send()
            .await?
            .json()
            .await
            .map_err(|e| CacheError::DecodingFailed {
                source: e,
                request: proof_request,
            })?;
        block_proofs.proofs.insert(account, response.result);
    }
    Ok(block_proofs)
}

/// Uses a cached deduplicated block prestate compresses the data.
///
/// This is important because some bytecode may exist multiple times
/// at different addresses.
pub fn compress_deduplicated_state(target_block: u64) -> Result<(), CacheError> {
    let names = CacheFileNames::new(target_block);
    let filename = names.block_accessed_state_deduplicated();
    let data = fs::read(&filename).map_err(|e| CacheError::FileOpener {
        source: e,
        filename,
    })?;
    let compressed = compress(data)?;
    let mut file = File::create(names.block_accessed_state_deduplicated_compressed())?;
    file.write_all(&compressed)?;
    Ok(())
}

/// Uses a cached block accessed state proofs and compresses the data.
///
/// This is effective because there are many nodes within the proofs that are
/// common between proofs.
///
/// ## Effect
/// State pre and post compression for different blocks:
/// - 17190873 8.9MB to 6.4MB = -28%
/// - 17193183 5.1MB to 3.4MB = -33%
/// - 17193270 10.1MB to 7.8MB = -22%
///
/// Total size for the three blocks: 24.1MB to 17.6MB = -26%
///
/// ## Limitation
/// Ultimately there are better ways to compress state because intermediate
/// nodes (and contract code) may be repeated across proofs and a different
/// storage representation would be better.
///
/// If compression is done on a per-block level then inter-block duplicates
/// are not efficiently compressed.
pub fn compress_proofs(target_block: u64) -> Result<(), CacheError> {
    let names = CacheFileNames::new(target_block);
    let block_file = names.prior_block_state_proofs();
    let data = fs::read(&block_file).map_err(|e| CacheError::FileOpener {
        source: e,
        filename: block_file,
    })?;
    let compressed = compress(data)?;
    let mut file = File::create(names.prior_block_state_proofs_compressed())?;
    file.write_all(&compressed)?;
    Ok(())
}

/// Retrieves all state data required for a block and creates and stores
/// an SSZ+snappy encoded format redy for P2P transfer.
pub fn create_transferrable_proof(target_block: u64) -> Result<(), CacheError> {
    let proofs = get_proofs_from_cache(target_block)?;
    let mut contracts: Vec<ContractBytes> = get_contracts_from_cache(target_block)?
        .into_values()
        .collect();
    contracts.sort();
    let blockhashes = get_blockhashes_from_cache(target_block)?;

    let transferrable = state_from_parts(proofs, contracts, blockhashes)?;
    save_transferrable_data(target_block, transferrable)?;
    Ok(())
}

fn save_transferrable_data(target_block: u64, data: RequiredBlockState) -> Result<(), CacheError> {
    let names = CacheFileNames::new(target_block);
    let ssz = data.to_ssz_bytes()?;
    let bytes = compress(ssz)?;
    let mut file = File::create(names.prior_block_transferrable_state_proofs())?;
    file.write_all(&bytes)?;
    Ok(())
}

/// Retrieves the node oracle from the cached pre- and post-state proofs.
pub fn get_node_oracle_from_cache(block: u64) -> Result<TrieNodeOracle, CacheError> {
    let post = get_post_state_proofs_from_cache(block)?;
    let pre = get_proofs_from_cache(block)?;
    //let oracle = demo_detect_removed_storage(pre, post);
    let oracle = detect_removed_storage(pre, post)?;
    debug!("oracle has been constructed");
    Ok(oracle)
}

/// Retrieves the accessed-state proofs for a single block from cache.
pub fn get_proofs_from_cache(block: u64) -> Result<BlockProofs, CacheError> {
    let proof_cache_path = CacheFileNames::new(block).prior_block_state_proofs();
    let file = File::open(&proof_cache_path).map_err(|e| CacheError::FileOpener {
        source: e,
        filename: proof_cache_path,
    })?;
    let reader = BufReader::new(file);
    let block_proofs = serde_json::from_reader(reader)?;
    Ok(block_proofs)
}

/// Retrieves the post-state accessed-state proofs for a single block from cache.
/// This can be used to debug the block executor and proof update mechanisms.
pub fn get_post_state_proofs_from_cache(block: u64) -> Result<BlockProofs, CacheError> {
    let proof_cache_path = CacheFileNames::new(block).block_state_proofs();
    let file = File::open(&proof_cache_path).map_err(|e| CacheError::FileOpener {
        source: e,
        filename: proof_cache_path,
    })?;
    let reader = BufReader::new(file);
    let block_proofs = serde_json::from_reader(reader)?;
    Ok(block_proofs)
}

/// Retrieves the transferrable (ssz+snappy) proofs for a single block from cache.
pub fn get_required_state_from_cache(block: u64) -> Result<RequiredBlockState, CacheError> {
    let proof_cache_path = CacheFileNames::new(block).prior_block_transferrable_state_proofs();
    let data = fs::read(&proof_cache_path).map_err(|e| CacheError::FileOpener {
        source: e,
        filename: proof_cache_path,
    })?;
    let ssz = decompress(data)?;
    let block_proofs = RequiredBlockState::from_ssz_bytes(ssz)?;
    Ok(block_proofs)
}

/// Retrieves a single block that has been stored.
pub fn get_block_from_cache(block: u64) -> Result<Block<Transaction>, CacheError> {
    let block_cache_path = CacheFileNames::new(block).block_with_transactions();
    let file = File::open(&block_cache_path).map_err(|e| CacheError::FileOpener {
        source: e,
        filename: block_cache_path,
    })?;
    let reader = BufReader::new(file);
    let mut block: Block<Transaction> = serde_json::from_reader(reader)?;
    block.transactions.sort_by_key(|tx| tx.nonce);
    Ok(block)
}

/// Retrieves all BLOCKHASH use values for a single block.
pub fn get_blockhashes_from_cache(block: u64) -> Result<BlockHashAccesses, CacheError> {
    let blockhash_path = CacheFileNames::new(block).blockhashes();
    let file = File::open(&blockhash_path).map_err(|e| CacheError::FileOpener {
        source: e,
        filename: blockhash_path,
    })?;
    let reader = BufReader::new(file);
    let accesses: BlockHashAccesses = serde_json::from_reader(reader)?;
    Ok(accesses)
}

pub(crate) type ContractBytes = Vec<u8>;

/// Retrieves the contract code for a particular cached block.
pub fn get_contracts_from_cache(block: u64) -> Result<HashMap<H256, ContractBytes>, CacheError> {
    let block_state_path = CacheFileNames::new(block).block_accessed_state_deduplicated();
    let file = File::open(&block_state_path).map_err(|e| CacheError::FileOpener {
        source: e,
        filename: block_state_path,
    })?;
    let reader = BufReader::new(file);
    let state: BlockStateAccesses = serde_json::from_reader(reader)?;
    contracts_from_state(state)
}

/// Extracts contract bytecode from accessed state.
fn contracts_from_state(
    state: BlockStateAccesses,
) -> Result<HashMap<H256, ContractBytes>, CacheError> {
    let mut code_map = HashMap::new();
    for (_, account) in state.access_data {
        if let Some(code_string) = account.code {
            let code = hex_decode(code_string)?;
            let code_hash = H256::from_slice(&keccak256(&code));
            code_map.insert(code_hash, code);
        }
    }
    Ok(code_map)
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
    /// The state proof is eth_getProof for the prior block.
    fn prior_block_state_proofs(&self) -> PathBuf {
        self.dirname().join("prior_block_state_proofs.json")
    }
    fn block_state_proofs(&self) -> PathBuf {
        self.dirname().join("block_state_proofs.json")
    }
    fn prior_block_state_proofs_compressed(&self) -> PathBuf {
        self.dirname().join("prior_block_state_proofs.snappy")
    }
    fn prior_block_transferrable_state_proofs(&self) -> PathBuf {
        self.dirname()
            .join("prior_block_transferrable_state_proofs.ssz_snappy")
    }
    fn block_with_transactions(&self) -> PathBuf {
        self.dirname().join("block_with_transactions.json")
    }
    fn blockhashes(&self) -> PathBuf {
        self.dirname().join("blockhash_opcode_use.json")
    }
}
