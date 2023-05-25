use ethers::types::{Block, EIP1186ProofResponse, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::types::{AccountToProve, TransactionAccountStates};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct AccountProofResponse {
    id: u32,
    jsonrpc: String,
    pub(crate) result: EIP1186ProofResponse,
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<Value>,
    id: u64,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlockResponse {
    id: u32,
    jsonrpc: String,
    pub(crate) result: Block<Transaction>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct TxPrestateResponse {
    id: u32,
    jsonrpc: String,
    pub(crate) result: TransactionAccountStates,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BlockPrestateResponse {
    id: u32,
    jsonrpc: String,
    pub(crate) result: Vec<BlockPrestateInnerTx>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BlockPrestateInnerTx {
    pub(crate) result: TransactionAccountStates,
}

/// Generates a JSON-RPC request for debug_traceBlockByNumber for
/// the given block.
pub(crate) fn debug_trace_block_prestate(block: &str) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "debug_traceBlockByNumber".to_owned(),
        params: vec![json!(block), json!({"tracer": "prestateTracer"})],
        id: 1,
    }
}

/// Generates a JSON-RPC request for eth_getBlockByNumber for
/// the specified block (e.g., "0xabc", "latest", "finalized").
pub(crate) fn get_block_by_number(block: &str) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "eth_getBlockByNumber".to_owned(),
        params: vec![json!(block), Value::Bool(true)],
        id: 1,
    }
}

/// Generates a JSON-RPC request for eth_getProof for
/// the given account and storage slots at the specified block.
pub(crate) fn eth_get_proof(account: &AccountToProve, block_number: &str) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "eth_getProof".to_owned(),
        params: vec![
            json!(account.address),
            json!(account.slots),
            json!(block_number),
        ],
        id: 1,
    }
}
