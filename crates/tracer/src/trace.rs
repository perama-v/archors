//! For executing a block using state.

use std::str::FromStr;

use archors_inventory::{types::BlockProofs, utils::hex_decode};
use ethers::types::{Block, Transaction};
use revm::{
    db::{CacheDB, EmptyDB},
    primitives::{AccountInfo, Bytes, TransactTo, B160, U256},
    EVM,
};
use thiserror::Error;

/// An error with tracing a block
#[derive(Debug, Error, Eq, PartialEq)]
pub enum TraceError {
    #[error("TODO")]
    Todo,
}

pub fn trace_block(block: Block<Transaction>, state_db: &BlockProofs) -> Result<(), TraceError> {
    // For all important states, load into db.
    let address = B160::default();
    let account = AccountInfo::default();
    let mut cache_db = CacheDB::new(EmptyDB::default());
    cache_db.insert_account_info(address, account);

    let slot = U256::default();
    let value = U256::default();
    cache_db
        .insert_account_storage(address, slot, value)
        .unwrap();

    let mut evm = EVM::new();
    // insert the db
    evm.database(cache_db);

    for transaction in block.transactions {}
    // change that to whatever caller you want to be
    evm.env.tx.caller = B160::from_str("0x0000000000000000000000000000000000000000").unwrap();
    // account you want to transact with
    evm.env.tx.transact_to = TransactTo::Call(B160::default());
    // calldata formed via abigen
    evm.env.tx.data = Bytes::from(hex_decode(&"0xabcd1234").unwrap());
    // transaction value in wei
    evm.env.tx.value = U256::from(0);
    evm.transact_commit().unwrap();

    Ok(())
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use archors_inventory::types::BlockProofs;
    use revm::db::{CacheDB, DatabaseRef, EmptyDB};

    use super::*;
    #[test]
    fn test_trace_block() {
        let block: Block<Transaction> = Block::default();
        let state = BlockProofs {
            proofs: HashMap::default(),
        };
        trace_block(block, &state).unwrap()
    }

    #[test]
    pub fn test_replace_account_storage() {
        let account = 42.into();
        let nonce = 42;
        let mut init_state = CacheDB::new(EmptyDB::default());
        init_state.insert_account_info(
            account,
            AccountInfo {
                nonce,
                ..Default::default()
            },
        );

        let (key0, value0) = (U256::from(123), U256::from(456));
        let (key1, value1) = (U256::from(789), U256::from(999));
        let _ = init_state.insert_account_storage(account, key0, value0);

        let mut new_state = CacheDB::new(init_state);
        let _ = new_state.replace_account_storage(account, [(key1, value1)].into());

        assert_eq!(new_state.basic(account).unwrap().unwrap().nonce, nonce);
        assert_eq!(new_state.storage(account, key0), Ok(U256::ZERO));
        assert_eq!(new_state.storage(account, key1), Ok(value1));
    }
}
