//! For executing a block using state.

use std::collections::HashMap;

use archors_types::{
    execution::{EvmStateError, StateForEvm},
    utils::hex_encode,
};
use ethers::types::{Block, Transaction, H256};
use log::{info, warn};
use revm::primitives::{Account, HashMap as rHashMap, B160, B256, U256};
use thiserror::Error;

use crate::{
    evm::{BlockEvm, EvmError},
    state::build_state_from_proofs,
};

/// An error with tracing a block
#[derive(Debug, Error, PartialEq)]
pub enum TraceError {
    #[error("StateError {0}")]
    StateError(#[from] EvmStateError),
    #[error("UtilsError {0}")]
    UtilsError(#[from] archors_types::utils::UtilsError),
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

/// Whether after tracing a block the post-execution state root should be computed
/// and checked against the root in the block header.
///
/// Some data formats that implement StateForEvm do not provide this functionality.
pub enum PostExecutionProof {
    UpdateAndIgnore,
    Update,
    Ignore,
}

/// Holds an EVM configured for single block execution.
pub struct BlockExecutor<T: StateForEvm> {
    block_evm: BlockEvm,
    block: Block<Transaction>,
    /// After transactions are applied, the delta is applied to get post-execution proofs and
    /// state root.
    block_proof_cache: T,
    /// Flag to check post-execution state root or not.
    root_check: PostExecutionProof,
}

impl<T: StateForEvm> BlockExecutor<T> {
    /// Loads the tracer so that it is ready to trace a block.
    pub fn load(
        block: Block<Transaction>,
        block_proofs: T,
        root_check: PostExecutionProof,
    ) -> Result<Self, TraceError> {
        // For all important states, load into db.
        let mut cache_db = build_state_from_proofs(&block_proofs)?;
        cache_db.block_hashes = block_proofs.get_blockhash_accesses()?;
        let mut block_evm = BlockEvm::init_from_db(cache_db);
        warn!("Did not set spec_id for hard fork");
        block_evm
            .add_chain_id(U256::from(1))
            .add_spec_id(&block)? // TODO
            .add_block_environment(&block)?;
        Ok(BlockExecutor {
            block_evm,
            block,
            block_proof_cache: block_proofs,
            root_check,
        })
    }
    /// Traces a single transaction in the block.
    ///
    /// The entire block is executed but only the specified transaction is inspected
    /// (trace sent to stdout)
    pub fn trace_transaction(mut self, target_tx_index: usize) -> Result<T, TraceError> {
        let mut post_block_state_delta = PostBlockStateDelta::default();

        for (check_idx, tx) in self.block.transactions.into_iter().enumerate() {
            let index = tx
                .transaction_index
                .ok_or(TraceError::TxWithoutIndex)?
                .as_u64() as usize;
            assert_eq!(check_idx, index);
            let primed = self
                .block_evm
                .add_transaction_environment(tx)
                .map_err(|source| TraceError::TxEnvError { source, index })?;

            let post_tx = match index {
                i if i == target_tx_index => {
                    // Execute with tracing.
                    primed
                        .execute_with_inspector_eip3155()
                        .map_err(|source| TraceError::TxExecutionError { source, index })?
                }
                _ => {
                    // Execute without tracing.
                    primed
                        .execute_without_inspector()
                        .map_err(|source| TraceError::TxExecutionError { source, index })?
                }
            };
            post_block_state_delta.append_tx_changes(post_tx.state)?;
        }

        post_execution_check(
            self.root_check,
            self.block.state_root,
            &mut self.block_proof_cache,
            post_block_state_delta,
        )?;
        Ok(self.block_proof_cache)
    }
    /// Traces every transaction in the block.
    pub fn trace_block(self) -> Result<T, TraceError> {
        self.trace_block_internal(false)
    }
    /// Trace a block without producing a trace to stdout. Used for debugging.
    pub fn trace_block_silent(self) -> Result<T, TraceError> {
        self.trace_block_internal(true)
    }
    /// Executes a block. The execution trace can be toggled off.
    fn trace_block_internal(mut self, silent: bool) -> Result<T, TraceError> {
        info!("Executing block using pre-state and transactions");
        let mut post_block_state_delta = PostBlockStateDelta::default();
        for (check_idx, tx) in self.block.transactions.into_iter().enumerate() {
            let index = tx
                .transaction_index
                .ok_or(TraceError::TxWithoutIndex)?
                .as_u64() as usize;
            assert_eq!(check_idx, index);
            let primed = self
                .block_evm
                .add_transaction_environment(tx)
                .map_err(|source| TraceError::TxEnvError { source, index })?;

            let post_tx = match silent {
                false => primed
                    .execute_with_inspector_eip3155()
                    .map_err(|source| TraceError::TxExecutionError { source, index })?,
                true => primed
                    .execute_without_inspector()
                    .map_err(|source| TraceError::TxExecutionError { source, index })?,
            };

            let _result = post_tx.result;
            // Update a proof object with state that changed after a transaction was executed.
            post_block_state_delta.append_tx_changes(post_tx.state)?;
        }

        post_execution_check(
            self.root_check,
            self.block.state_root,
            &mut self.block_proof_cache,
            post_block_state_delta,
        )?;
        Ok(self.block_proof_cache)
    }
}

/// If required, updates the state multiproof with the changes acquired from block execution, then
/// checks that the post-block state root matches the root in the header.
fn post_execution_check<T: StateForEvm>(
    root_check: PostExecutionProof,
    expected_root: H256,
    block_proof_cache: &mut T,
    post_block_state_delta: PostBlockStateDelta,
) -> Result<(), TraceError> {
    match root_check {
        PostExecutionProof::Update => {
            info!("Started post-execution state proof update");
            let computed_root =
                block_proof_cache.state_root_post_block(post_block_state_delta.get_changes())?;
            post_root_ok(&expected_root, &computed_root)?;
        }
        PostExecutionProof::UpdateAndIgnore => {
            info!("Started post-execution state proof update");
            block_proof_cache.state_root_post_block(post_block_state_delta.get_changes())?;

            warn!("Skipped post-execution state root verification");
        }
        PostExecutionProof::Ignore => {
            warn!("Skipped post-execution state proof update and verification");
        }
    }
    Ok(())
}

/// Checks that the post-block state root matches the state root in the block header.
fn post_root_ok(&header_root: &H256, computed_root: &B256) -> Result<(), TraceError> {
    let header_root = B256::from(header_root);
    if computed_root != &header_root {
        return Err(TraceError::PostBlockStateRoot {
            computed_root: hex_encode(computed_root),
            header_root: hex_encode(header_root),
        });
    }
    info!("Post-execution state root verified.");
    Ok(())
}

/// Produces the net account changes caused by running the EVM across multiple transactions.
///
/// REVM produces net changes after one transaction. If two transactions affect the same
/// account, the storage slot changes should be included from both transactions. Later
/// changes overwrite earlier changes.
///
/// Other members in Account (.is_destroyed, etc) are not updated and are not used elsewhere.
#[derive(Default, Debug, Clone)]
pub struct PostBlockStateDelta(HashMap<B160, Account>);

impl PostBlockStateDelta {
    /// Add state changes for multiple accounts to the state delta accumulator.
    fn append_tx_changes(
        &mut self,
        changed_accounts: rHashMap<B160, Account>,
    ) -> Result<(), TraceError> {
        for (address, account) in changed_accounts {
            self.append_account_changes(address, account)?;
        }
        Ok(())
    }
    /// Add state changes for one account to the state delta accumulator.
    fn append_account_changes(
        &mut self,
        address: B160,
        changes: Account,
    ) -> Result<(), TraceError> {
        let summary = match self.0.get_mut(&address) {
            Some(acc) => acc,
            None => {
                self.0.insert(address, changes);
                return Ok(());
            }
        };
        // Overwrite any new slot changes individually.
        for (key, val) in changes.storage {
            summary.storage.insert(key, val);
        }
        // Update account components
        summary.info = changes.info;
        Ok(())
    }
    /// Returns the inner map of account changes.
    fn get_changes(self) -> HashMap<B160, Account> {
        self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    use ethers::types::{EIP1186ProofResponse, H160};
    use revm::{
        db::{CacheDB, DatabaseRef, EmptyDB},
        primitives::{AccountInfo, HashMap as rHashMap, StorageSlot, U256},
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
        let executor = BlockExecutor::load(block, state, PostExecutionProof::Ignore).unwrap();
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

    fn account_factory() -> Account {
        Account {
            info: AccountInfo {
                balance: U256::from_str("1").unwrap(),
                nonce: 1u64,
                code_hash: B256::from_str(
                    "0xce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99",
                )
                .unwrap(),
                code: None,
            },
            storage: rHashMap::default(),
            storage_cleared: false,
            is_destroyed: false,
            is_touched: false,
            is_not_existing: false,
        }
    }

    #[test]
    fn test_slot_changes_from_two_transactions_are_combined() {
        let mut changes = PostBlockStateDelta::default();
        let address = B160::from_str("0x00000000000000adc04c56bf30ac9d3c0aaf14dc").unwrap();
        // First tx (0, 9) (1, 1)
        let mut account_update = account_factory();
        account_update.storage.insert(
            U256::from_str("0x0").unwrap(),
            StorageSlot {
                present_value: U256::from_str("0x9").unwrap(),
                ..Default::default()
            },
        );
        account_update.storage.insert(
            U256::from_str("0x1").unwrap(),
            StorageSlot {
                present_value: U256::from_str("0x1").unwrap(),
                ..Default::default()
            },
        );
        changes
            .append_account_changes(address, account_update)
            .unwrap();
        // Second tx (1, 100), (2, 200), nonce=2
        let mut account_update = account_factory();
        account_update.info.nonce = 2;
        account_update.storage.insert(
            U256::from_str("0x1").unwrap(),
            StorageSlot {
                present_value: U256::from_str("0x100").unwrap(),
                ..Default::default()
            },
        );
        account_update.storage.insert(
            U256::from_str("0x2").unwrap(),
            StorageSlot {
                present_value: U256::from_str("0x200").unwrap(),
                ..Default::default()
            },
        );
        changes
            .append_account_changes(address, account_update)
            .unwrap();
        let net = changes.get_changes();
        let net_account = net.get(&address).unwrap();

        assert_eq!(
            net_account
                .storage
                .get(&U256::from_str("0x0").unwrap())
                .unwrap()
                .present_value,
            U256::from_str("0x9").unwrap()
        );
        assert_eq!(
            net_account
                .storage
                .get(&U256::from_str("0x1").unwrap())
                .unwrap()
                .present_value,
            U256::from_str("0x100").unwrap()
        );
        assert_eq!(
            net_account
                .storage
                .get(&U256::from_str("0x2").unwrap())
                .unwrap()
                .present_value,
            U256::from_str("0x200").unwrap()
        );
        assert_eq!(net_account.info.nonce, 2);
    }
}
