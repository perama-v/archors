use anyhow::Result;
use archors_inventory::cache::{
    get_block_from_cache, get_blockhashes_from_cache, get_contracts_from_cache,
    get_proofs_from_cache, get_required_state_from_cache,
};
use archors_tracer::{state::BlockProofsBasic, trace::BlockExecutor};

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
    let block_number = 17190873;
    // Get block to execute (eth_getBlockByNumber).
    let block = get_block_from_cache(block_number)?;
    let form = StateDataForm::SpecCompliant;

    match form {
        StateDataForm::Basic => {
            let state = BlockProofsBasic {
                proofs: get_proofs_from_cache(block_number)?.proofs,
                code: get_contracts_from_cache(block_number)?,
                block_hashes: get_blockhashes_from_cache(block_number)?.to_hashmap(),
            };
            let executor = BlockExecutor::load(block, state)?;

            //executor.trace_transaction(95)?;
            executor.trace_block()?;
        }
        StateDataForm::MultiProof => todo!(),
        StateDataForm::SpecCompliant => {
            // Get state proofs (from peer / disk).
            let state = get_required_state_from_cache(block_number)?;
            let executor = BlockExecutor::load(block, state)?;
            //executor.trace_transaction(95)?;
            executor.trace_block()?;
        }
    }
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
