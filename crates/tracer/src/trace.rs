//! For executing a block using state.

use std::collections::HashMap;

use ethers::types::{Block, Transaction};
use revm::primitives::U256;
use thiserror::Error;

use crate::{
    evm::{BlockEvm, EvmError},
    state::{build_state_from_proofs, BlockHashes, CompleteAccounts, StateError},
    utils::{hex_encode, UtilsError},
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
    #[error("Computed state root {computed_root} does not match header state root {header_root}")]
    PostBlockStateRoot {
        computed_root: String,
        header_root: String,
    },
    #[error("Unable to set transaction (tx_index {index}) environment {source}")]
    TxEnvError { source: EvmError, index: usize },
    #[error("Unable to execute transaction (tx_index {index}) {source}")]
    TxExecutionError { source: EvmError, index: usize },
    #[error("Transaction does not have an index")]
    TxWithoutIndex,
}

/// Holds an EVM configured for single block execution.
pub struct BlockExecutor<T: CompleteAccounts + BlockHashes> {
    block_evm: BlockEvm,
    block: Block<Transaction>,
    /// Keeps block proof data up to date as transactions are applied.
    block_proof_cache: T,
}

impl<T: CompleteAccounts + BlockHashes> BlockExecutor<T> {
    /// Loads the tracer so that it is ready to trace a block.
    pub fn load(block: Block<Transaction>, block_proofs: T) -> Result<Self, TraceError> {
        // For all important states, load into db.
        let mut cache_db = build_state_from_proofs(&block_proofs)?;
        cache_db.block_hashes = block_proofs.get_blockhash_accesses()?;
        let mut block_evm = BlockEvm::init_from_db(cache_db);
        block_evm
            .add_chain_id(U256::from(1))
            .add_spec_id(&block)? // TODO
            .add_block_environment(&block)?;
        Ok(BlockExecutor {
            block_evm,
            block,
            block_proof_cache: block_proofs,
        })
    }
    /// Traces a single transaction in the block.
    ///
    /// Preceeding transactions are executed but not traced.
    pub fn trace_transaction(mut self, target_tx_index: usize) -> Result<(), TraceError> {
        for tx in self.block.transactions.into_iter() {
            let index = tx
                .transaction_index
                .ok_or(TraceError::TxWithoutIndex)?
                .as_u64() as usize;
            if index == target_tx_index {
                // Execute with tracing.
                let _outcome = self
                    .block_evm
                    .add_transaction_environment(tx)
                    .map_err(|source| TraceError::TxEnvError { source, index })?
                    .execute_with_inspector_eip3155()
                    .map_err(|source| TraceError::TxExecutionError { source, index })?;
                // Ignore remaining transactions.
                return Ok(());
            }
            // Execute without tracing.
            let _outcome = self
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
        let mut post_block_state_delta = HashMap::new();
        for (index, tx) in self.block.transactions.into_iter().enumerate() {
            let post_tx = self
                .block_evm
                .add_transaction_environment(tx)
                .map_err(|source| TraceError::TxEnvError { source, index })?
                .execute_with_inspector_eip3155()
                .map_err(|source| TraceError::TxExecutionError { source, index })?;

            let _result = post_tx.result;
            // Update a proof object with state that changed after a transaction was executed.
            post_block_state_delta.extend(post_tx.state);
        }
        // After all transactions have been run, apply the final state diff to the proof data.
        for (address, account) in post_block_state_delta.into_iter() {
            self.block_proof_cache.update_account(&address, account)?;
        }
        // Get new post-block root.
        let root = self.block_proof_cache.root_hash()?;
        if root != self.block.state_root {
            return Err(TraceError::PostBlockStateRoot {
                computed_root: hex_encode(root),
                header_root: hex_encode(self.block.state_root),
            });
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
    fn test_trace_block_composable() {
        let mut state = BlockProofsBasic {
            proofs: HashMap::default(),
            code: HashMap::default(),
            block_hashes: HashMap::default(),
        };
        let mut proof = EIP1186ProofResponse::default();
        let address = H160::from_str("0x0300000000000000000000000000000000000000").unwrap();
        proof.address = address;
        proof.balance = ethers::types::U256::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000009",
        )
        .unwrap();
        state.proofs.insert(address, proof);

        let mut block: Block<Transaction> = Block {
            author: Some(H160::default()),
            number: Some(10_000_000.into()),
            ..Default::default()
        };
        let tx = Transaction {
            from: address,
            to: Some(H160::from_str("0x0200000000000000000000000000000000000000").unwrap()),
            value: ethers::types::U256::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000009",
            )
            .unwrap(),
            gas_price: Some(ethers::types::U256::default()),
            ..Default::default()
        };

        block.transactions.push(tx);
        let executor = BlockExecutor::load(block, state).unwrap();
        // The dummy block should not successfully execute.
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
