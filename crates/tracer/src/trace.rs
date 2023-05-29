//! For executing a block using state.

use ethers::types::{Block, Transaction};
use revm::primitives::U256;
use thiserror::Error;

use crate::{
    evm::{BlockEvm, EvmError},
    state::{build_state_from_proofs, CompleteAccounts, StateError},
    utils::UtilsError,
};

/// An error with tracing a block
#[derive(Debug, Error, PartialEq)]
pub enum TraceError {
    #[error("StateError {0}")]
    StateError(#[from] StateError),
    #[error("UtilsError {0}")]
    UtilsError(#[from] UtilsError),
    #[error("EvmError {0}")]
    EvmError(#[from] EvmError),
    #[error("Unable to set transaction (tx_index {index}) environment {source}")]
    TxEnvError { source: EvmError, index: usize },
    #[error("Unable to execute transaction (tx_index {index}) {source}")]
    TxExecutionError { source: EvmError, index: usize },
}

/// Holds an EVM configured for single block execution.
pub struct BlockExecutor {
    block_evm: BlockEvm,
    block: Block<Transaction>,
}

impl BlockExecutor {
    /// Loads the tracer so that it is ready to trace a block.
    pub fn load<T>(block: Block<Transaction>, block_proofs: T) -> Result<Self, TraceError>
    where
        T: CompleteAccounts,
    {
        // For all important states, load into db.
        let cache_db = build_state_from_proofs(&block_proofs)?;

        let mut block_evm = BlockEvm::init_from_db(cache_db);
        block_evm
            .add_chain_id(U256::from(1))
            .add_spec_id(&block)? // TODO
            .add_block_environment(&block)?;
        Ok(BlockExecutor { block_evm, block })
    }
    /// Traces a single transaction in the block.
    ///
    /// Preceeding transactions are executed but not traced.
    pub fn trace_transaction(mut self, target_tx_index: usize) -> Result<(), TraceError> {
        for (index, tx) in self.block.transactions.into_iter().enumerate() {
            if index == target_tx_index {
                // Execute with tracing.
                let outcome = self
                    .block_evm
                    .add_transaction_environment(tx)
                    .map_err(|source| TraceError::TxEnvError { source, index })?
                    .execute_with_inspector_eip3155()
                    .map_err(|source| TraceError::TxExecutionError { source, index })?;
                // Ignore remaining transactions.
                return Ok(());
            }
            // Execute without tracing.
            let outcome = self
                .block_evm
                .add_transaction_environment(tx)
                .map_err(|source| TraceError::TxEnvError { source, index })?
                .execute_without_inspector()
                .map_err(|source| TraceError::TxExecutionError { source, index })?;
        }
        Ok(())
    }
    /// Traces every transaction in the block.
    pub fn trace_block(mut self) -> Result<(), TraceError> {
        for (index, tx) in self.block.transactions.into_iter().enumerate() {
            let outcome = self
                .block_evm
                .add_transaction_environment(tx)
                .map_err(|source| TraceError::TxEnvError { source, index })?
                .execute_with_inspector_eip3155()
                .map_err(|source| TraceError::TxExecutionError { source, index })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{collections::HashMap, str::FromStr};

    use ethers::types::{EIP1186ProofResponse, H160};
    use revm::{
        db::{CacheDB, DatabaseRef, EmptyDB},
        primitives::{AccountInfo, U256},
    };

    use crate::state::BlockProofsBasic;

    /// Tests that a EVM environnment can be constructed from proof data for a block
    /// Values are set for an account, transactions are created and then
    /// applied by running the EVM.
    #[test]
    fn test_trace_block() {
        let mut state = BlockProofsBasic {
            proofs: HashMap::default(),
            code: HashMap::default(),
        };
        let mut proof = EIP1186ProofResponse::default();
        let address = H160::from_str("0x0300000000000000000000000000000000000000").unwrap();
        proof.address = address;
        proof.balance = ethers::types::U256::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000009",
        )
        .unwrap();
        state.proofs.insert(address, proof);

        let mut block: Block<Transaction> = Block::default();
        let mut tx = Transaction::default();
        tx.from = address;
        tx.to = Some(H160::from_str("0x0200000000000000000000000000000000000000").unwrap());
        // Enough balance (succeeds)
        tx.value = ethers::types::U256::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000009",
        )
        .unwrap();
        block.transactions.push(tx.clone());
        // Not enough balance (fails): LackOfFundForMaxFee
        tx.value = ethers::types::U256::from_str(
            "0x0000000000000000000000900000000000000000000000000000000000000000",
        )
        .unwrap();
        block.transactions.push(tx);
        // Trace fails due to the failing transaction.
        let mut executor = BlockExecutor::load(block, state).unwrap();
        assert!(executor.trace_block().is_err());
    }

    /// Test case from revm crate.
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
