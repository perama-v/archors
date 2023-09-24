use anyhow::Result;
use archors_inventory::cache::{
    get_block_from_cache, get_blockhashes_from_cache, get_contracts_from_cache,
    get_proofs_from_cache, get_required_state_from_cache, get_node_oracle_from_cache,
};
use archors_multiproof::{EIP1186MultiProof, StateForEvm};
use archors_tracer::{
    state::BlockProofsBasic,
    trace::{BlockExecutor, PostExecutionProof},
};

/// Consume one block state proof.
///
/// Shows how a transferrable RequiredBlockState (spec compliant) data structure is
/// used to trace a block.
///
/// ## Example
/// Either trace the full block or a single transaction of interest.
/// Notable transactions for block: 17190873
/// - 2,
/// - 14: Failed swap
/// - 28: Failed contract execution
/// - 37: Failed contract execution
/// - 95: Coinbase using multiple CALL to send ether to EOAs.
/// - 185: CREATEs 5 contracts
/// - 196, 204,
/// - 205 simple transfer (final tx)
fn main() -> Result<()> {
    env_logger::init();
    let block_number = 17190873;
    // Get block to execute (eth_getBlockByNumber).
    let block = get_block_from_cache(block_number)?;
    let form = StateDataForm::MultiProof;

    match form {
        StateDataForm::Basic => {
            let state = BlockProofsBasic {
                proofs: get_proofs_from_cache(block_number)?.proofs,
                code: get_contracts_from_cache(block_number)?,
                block_hashes: get_blockhashes_from_cache(block_number)?.to_hashmap(),
            };
            let executor = BlockExecutor::load(block, state, PostExecutionProof::Ignore)?;
            re_execute_block(executor)?;
        }
        StateDataForm::MultiProof => {
            let proofs = get_proofs_from_cache(block_number)?
                .proofs
                .into_values()
                .collect();
            let code = get_contracts_from_cache(block_number)?;
            let block_hashes = get_blockhashes_from_cache(block_number)?.to_hashmap();
            let node_oracle = get_node_oracle_from_cache(block_number)?;

            let state = EIP1186MultiProof::from_separate(proofs, code, block_hashes, node_oracle)?;
            let executor = BlockExecutor::load(block, state, PostExecutionProof::Update)?;
            re_execute_block(executor)?;
        }
        StateDataForm::SpecCompliant => {
            // Get state proofs (from peer / disk).
            let state = get_required_state_from_cache(block_number)?;
            let executor = BlockExecutor::load(block, state, PostExecutionProof::Ignore)?;
            re_execute_block(executor)?;
        }
    }
    Ok(())
}

fn re_execute_block<T: StateForEvm>(executor: BlockExecutor<T>) -> Result<()> {
    //let post_state = executor.trace_block()?;
    let post_state = executor.trace_transaction(2)?;

    post_state.print_storage_proof(
        "0x00000000000000adc04c56bf30ac9d3c0aaf14dc",
        "0xfe073a4a8a654ccc9ca8e39369abc3b9919fde0aa58577acb685c63e0603a5a1",
    )?;

    Ok(())
}

/// The format of the state data (proofs, blockhashes) that will be fed to the EVM.
///
/// The library has different forms for prototyping.
#[allow(dead_code)]
enum StateDataForm {
    /// Simplest prototype, data is aggregated naively which involves some duplication of
    /// internal trie nodes.
    Basic,
    /// Data is aggregated as a multiproof for deduplication of internal trie nodes and easier
    /// computation of post-block root.
    MultiProof,
    /// Spec-compliant `RequiredBlockState` data structure optimised for peer to peer transfer.
    SpecCompliant,
}
