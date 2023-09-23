use std::str::FromStr;

use archors_inventory::{
    cache::{
        get_block_from_cache, get_blockhashes_from_cache, get_contracts_from_cache,
        get_proofs_from_cache,
    },
    utils::hex_encode,
};
use archors_multiproof::{EIP1186MultiProof, StateForEvm};
use archors_tracer::trace::{BlockExecutor, PostExecutionProof};
use archors_types::utils::rb160_to_eh160;
use ethers::types::{H160, H256};
use revm::primitives::{Account, AccountInfo, HashMap as rHashMap, B160, B256, U256};

/**
Loads the state multiproof, executes the block, updates the multiproof for all changes
the block caused and then checks that the storage in a particular account is correct.

Canonical account storage roots were obtained vai eth_getProof.

Account 0x00000000000000adc04c56bf30ac9d3c0aaf14dc has 3 keys modified by the block 17190873:
- 0xfe073a4a8a654ccc9ca8e39369abc3b9919fde0aa58577acb685c63e0603a5a1 from 0 -> 0x0000000000000000000000000000010000000000000000000000000000010001.
- 0xde1877e04330e34e13ed4a88ad37f2de41cb2cc9e5f0539ca4718f353374cbe2 from 0 -> 0x10000000000000000000000000000010001
- 0x8b047007c345eab12063c0f43cc4c85dd576613e88dd595ed36f7ed99d774a9b from 0x20000000000000000000000000000010001 -> 0x20000000000000000000000000000020001
*/
#[test]
#[ignore]
fn test_single_account_update_from_block_17190873() {
    let block_number = 17190873;
    let block = get_block_from_cache(block_number).unwrap();
    let proofs = get_proofs_from_cache(block_number)
        .unwrap()
        .proofs
        .into_values()
        .collect();
    let code = get_contracts_from_cache(block_number).unwrap();
    let block_hashes = get_blockhashes_from_cache(block_number)
        .unwrap()
        .to_hashmap();

    let state: EIP1186MultiProof =
        EIP1186MultiProof::from_separate(proofs, code, block_hashes).unwrap();

    let address = H160::from_str("0x00000000000000adc04c56bf30ac9d3c0aaf14dc").unwrap();

    // Check storage root for account prior to block execution (rooted in block 17190872).
    let known_storage_root_17190872 =
        H256::from_str("0x8a150b46c0f63a2330dcb3a20c526798768e000f1d911ac70853c199d2accb94")
            .unwrap();
    let computed_storage_root_17190872 = state.storage_proofs.get(&address).unwrap().root;
    assert_eq!(known_storage_root_17190872, computed_storage_root_17190872);

    // Check storage root for account after block execution (rooted in block 17190873).
    let executor = BlockExecutor::load(block, state, PostExecutionProof::UpdateAndIgnore).unwrap();
    let post_state = executor.trace_transaction(2).unwrap();

    let computed_storage_root_17190873 = post_state.storage_proofs.get(&address).unwrap().root;
    let known_storage_root_17190873 =
        H256::from_str("0x4b8ea4eb3e8cafce4e8b35a4a3560c3f4a86ef33b804b25c406707139387a2c1")
            .unwrap();
    assert_eq!(known_storage_root_17190873, computed_storage_root_17190873);
    post_state
        .print_storage_proof(
            "0x00000000000000adc04c56bf30ac9d3c0aaf14dc",
            "0xfe073a4a8a654ccc9ca8e39369abc3b9919fde0aa58577acb685c63e0603a5a1",
        )
        .unwrap();
}

#[test]
#[ignore]
fn test_state_root_update_from_block_17190873() {
    todo!("similar to the account test, but check the state root")
}