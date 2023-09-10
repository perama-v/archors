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
    #[error("Unable to parse address: {0}")]
    InvalidAddress(String),
    #[error("Unable to parse storage key: {0}")]
    InvalidStorageKey(String),
    #[error("Unable to display proof: {0}")]
    DisplayError(String),
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
    /// This function updates the proofs, but does not necessarily update the block prestate
    /// values in the data. That is, one should not assume that post-execution that the
    /// non-proof values are up to date.
    ///
    /// Note that some account updates may require additional information. Key deletion may
    /// remove nodes and restructure the trie. In this case, some additional nodes must be
    /// provided.
    fn state_root_post_block(
        &mut self,
        changes: HashMap<B160, Account>,
    ) -> Result<B256, EvmStateError>;
    /// Print an account proof.
    fn print_account_proof<T: AsRef<str>>(&self, account_address: T) -> Result<(), EvmStateError>;
    /// Print a storage proof for a given account.
    fn print_storage_proof<T: AsRef<str>>(
        &self,
        account_address: T,
        storage_key: T,
    ) -> Result<(), EvmStateError>;
}
