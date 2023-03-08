use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;
use web3::{
    self,
    types::{Proof, H256},
};

use archors::{
    self,
    types::{AccountStates, AccountToProve, BasicBlockState, BlockStateAccesses},
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
    let mut accesses = BlockStateAccesses::new();
    // Add state needed each transaction.
    for tx in basic_block.transactions {
        println!("Transaction: {}", archors::utils::hex_encode(tx.as_bytes()));
        // Get transaction.
        let prestate_response = client
            .post(url.as_ref())
            .json(&debug_trace_transaction_prestate(&hex_encode(tx)))
            .send()
            .await?
            .json::<PrestateResponse>()
            .await?;
        // Add to proof.
        accesses.include_new_state_accesses_for_tx(&tx, &prestate_response.result);
    }
    println!("{accesses}");
    let mut account_proofs: Vec<Value> = vec![];
    for account in accesses.get_all_accounts_to_prove() {
        println!("Getting proof for account: {}", account.address);
        // Get proof for account
        let account_proof_response = client
            .post(url.as_ref())
            .json(&eth_get_proof(&account))
            .send()
            .await?
            .json::<Value>()
            //.json::<AccountProofResponse>()
            .await?;
        // Add to proof.
        //println!("Proof: {}", account_proof_response);
        account_proofs.push(account_proof_response)
    }

    // Combine account nodes from proofs in to single state proof.

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

#[derive(Deserialize, Serialize)]
struct AccountProofResponse {
    id: u32,
    jsonrpc: String,
    result: Proof,
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<Value>,
    id: u64,
}

/// Generates a JSON-RPC request for eth_getBlockByNumber for
/// the latest finalized block.
fn get_block_by_number() -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "eth_getBlockByNumber".to_owned(),
        params: vec![json!("finalized"), Value::Bool(false)],
        id: 1,
    }
}

/// Generates a JSON-RPC request for debug_traceTransaction for
/// the given transaction.
fn debug_trace_transaction_prestate(tx: &str) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "debug_traceTransaction".to_owned(),
        params: vec![json!(tx), json!({"tracer": "prestateTracer"})],
        id: 1,
    }
}

/// Generates a JSON-RPC request for eth_getProof for
/// the given account and storage slots at the latest finalized block.
fn eth_get_proof(account: &AccountToProve) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "eth_getProof".to_owned(),
        params: vec![
            json!(account.address),
            json!(account.slots),
            json!("finalized"),
        ],
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
