//! For executing a block using state.

use ethers::types::{Block, Transaction};
use revm::{
    primitives::{Bytes, EVMError, Env, ExecutionResult, TransactTo, B160},
    EVM,
};
use thiserror::Error;

use crate::{
    state::{build_state_from_proofs, CompleteAccounts, StateError},
    utils::{eu256_to_ru256, UtilsError},
};

/// An error with tracing a block
#[derive(Debug, Error, PartialEq)]
pub enum TraceError {
    #[error("StateError {0}")]
    StateError(#[from] StateError),
    #[error("UtilsError {0}")]
    UtilsError(#[from] UtilsError),
    #[error("Unable to commit transaction (index = {index}, {error}")]
    TxCommitFailed { error: String, index: usize },
}

pub fn trace_block<T>(block: Block<Transaction>, block_proofs: &T) -> Result<(), TraceError>
where
    T: CompleteAccounts,
{
    // For all important states, load into db.
    let cache_db = build_state_from_proofs(block_proofs)?;

    let mut evm = EVM::new();
    // insert the db
    evm.database(cache_db);

    for (index, tx) in block.transactions.into_iter().enumerate() {
        set_up_tx(&mut evm.env, tx)?;
        let outcome = evm.transact_commit().map_err(|e| {
            let error = match e {
                EVMError::Transaction(t) => serde_json::to_string(&t).unwrap(),
                EVMError::Database(_d) => "database error".to_string(), // _d is Infallible
                EVMError::PrevrandaoNotSet => String::from("prevrandao error"),
            };
            TraceError::TxCommitFailed { error, index }
        })?;
        println!("\n\n{:?}", outcome);
    }

    Ok(())
}

/// Set up the transaction details in the evm environment.
fn set_up_tx(env: &mut Env, tx: Transaction) -> Result<(), TraceError> {
    env.tx.caller = B160::from(tx.from.0);
    match tx.to {
        Some(dest) => {
            env.tx.transact_to = TransactTo::Call(B160::from(dest));
        }
        None => todo!("handle contract creation"),
    }
    env.tx.data = tx.input.0;
    env.tx.value = eu256_to_ru256(tx.value)?;
    Ok(())
}

// Execute a transaction

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use revm::{
        db::{CacheDB, DatabaseRef, EmptyDB},
        primitives::{AccountInfo, U256},
    };

    use crate::state::BlockProofsBasic;

    use super::*;
    #[test]
    fn test_trace_block() {
        let block: Block<Transaction> = Block::default();
        let state = BlockProofsBasic {
            proofs: HashMap::default(),
            code: HashMap::default(),
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
