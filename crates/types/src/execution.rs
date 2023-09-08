//! Interface types for making a data structure executable in the revm.

use std::collections::HashMap;

use revm::primitives::{Account, AccountInfo, HashMap as rHashMap, B160, B256, U256};
use thiserror::Error;

use crate::utils::UtilsError;

/// An error with tracing a block
#[derive(Debug, Error, PartialEq)]
pub enum EvmStateError {
    #[error("Unable to get account state proof for address")]
    NoProofForAddress(String),
    #[error("Could not initialise storage for account {address}, error {error}")]
    AccountStorageInit { error: String, address: String },
    #[error("Utils Error {0}")]
    UtilsError(#[from] UtilsError),
    #[error("Unable to verify post-execution state root: {0}")]
    PostRoot(String),
}

/// Behaviour that any proof-based format must provide to be convertible into
/// a revm DB. In other words, behaviour that makes the state data extractable for re-execution.
///
/// Returned types are revm-based.
pub trait StateForEvm {
    /// Gets account information in a format that can be inserted into a
    /// revm db. This includes contract bytecode.
    fn get_account_info(&self, address: &B160) -> Result<AccountInfo, EvmStateError>;
    /// Gets all the addresses.
    fn addresses(&self) -> Vec<B160>;
    /// Gets the storage key-val pairs for the account of the address.
    fn get_account_storage(&self, address: &B160) -> Result<rHashMap<U256, U256>, EvmStateError>;
    /// Gets BLOCKAHSH opcode accesses required for the block.
    /// Pairs are (block_number, block_hash).
    fn get_blockhash_accesses(&self) -> Result<rHashMap<U256, B256>, EvmStateError>;
    /// Apply account changes received from the EVM for the entire block, compute the state
    /// root and return it.
    ///
    /// This consumes the state object to avoid reuse of the state data, which is only
    /// to be used for a single block.
    ///
    /// Note that some account updates may require additional information. Key deletion may
    /// remove nodes and restructure the trie. In this case, some additional nodes must be
    /// provided.
    fn state_root_post_block(self, changes: HashMap<B160, Account>) -> Result<B256, EvmStateError>;
}
