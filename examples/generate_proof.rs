use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;
use web3::{self, types::H256};

use archors::{
    self,
    types::{AccountStates, BasicBlockState, BlockStateProof},
};

static NODE: &str = "http://127.0.0.1:8545";

/// Generate one block state proof for the latest finalized block.
#[tokio::main]
async fn main() -> Result<()> {
    // Connect to a node.
    let url = Url::parse(NODE)?;
    let client = Client::new();

    // Get a block.
    let block = client
        .post(url.as_ref())
        .json(&get_block_by_number())
        .send()
        .await?
        .json::<BlockResponse>()
        .await?;

    println!("{}", serde_json::to_string_pretty(&block)?);

    let basic_block = BasicBlockState {
        state_root: block.result.state_root,
        transactions: block.result.transactions,
    };
    // Empty proof.
    let mut proof = BlockStateProof::new();
    // Add state needed each transaction.
    for tx in basic_block.transactions {
        // Get transaction.
        let prestate_response = client
            .post(url.as_ref())
            .json(&debug_trace_transaction_prestate(&hex_encode(tx)))
            .send()
            .await?
            .json::<PrestateResponse>()
            .await?;
        // Add to proof.
        proof.insert_tx(&tx, &prestate_response.result);
    }

    // Serialize proof for transmission or storage.

    Ok(())
}

#[derive(Deserialize, Serialize)]
struct BlockResponse {
    id: u32,
    jsonrpc: String,
    result: web3::types::Block<H256>,
}

#[derive(Deserialize, Serialize)]
struct PrestateResponse {
    id: u32,
    jsonrpc: String,
    result: AccountStates,
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<Value>,
    id: u64,
}

fn get_block_by_number() -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "eth_getBlockByNumber".to_owned(),
        params: vec![json!("finalized"), Value::Bool(false)],
        id: 1,
    }
}

fn debug_trace_transaction_prestate(tx: &str) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "debug_traceTransaction".to_owned(),
        params: vec![json!(tx), json!({"tracer": "prestateTracer"})],
        id: 1,
    }
}

fn _debug_trace_transaction_prestate_diffmode(tx: &str) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "debug_traceTransaction".to_owned(),
        params: vec![
            json!(tx),
            json!({"tracer": "prestateTracer", "tracerConfig": {"diffMode": true}}),
        ],
        id: 1,
    }
}

fn hex_encode(hash: H256) -> String {
    format!("0x{}", hex::encode(hash.as_bytes()))
}
