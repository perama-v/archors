//! For representing state for an historical block.

use archors_inventory::utils::hex_encode;
use ethers::types::EIP1186ProofResponse;
use revm::{
    db::{CacheDB, EmptyDB},
    primitives::{AccountInfo, Bytecode, Bytes, HashMap, B160},
};

use thiserror::Error;

/// An error with tracing a block
#[derive(Debug, Error, Eq, PartialEq)]
pub enum StateError {
    #[error("Unable to get account state proof for address")]
    NoProofForAddress(String),
    #[error("Unable to get account code for address")]
    NoCodeForAddress(String),
}

/// A basic map of accounts to proofs. Contains duplicated data and
/// does not contain contract code.
pub struct BlockProofsBasic {
    /// Map of codehash -> code
    pub code: HashMap<B160, Bytes>,
    /// Map of account -> proof
    pub proofs: HashMap<B160, EIP1186ProofResponse>,
}

/// Behaviour that any proof-based format must provide to be convertible into
/// a reth DB.
pub trait CompleteAccounts {
    /// Gets account information in a format that can be inserted into a
    /// revm db.
    fn to_account_info(&self, address: &B160) -> Result<AccountInfo, StateError>;

    fn addresses(&self) -> Vec<B160>;
}

impl CompleteAccounts for BlockProofsBasic {
    fn to_account_info(&self, address: &B160) -> Result<AccountInfo, StateError> {
        let account = self
            .proofs
            .get(address)
            .ok_or_else(|| StateError::NoProofForAddress(hex_encode(address)))?;
        let code: Option<Bytecode> = self
            .code
            .get(address)
            .map(|bytes| Bytecode::new_raw(bytes.clone()));

        let info = AccountInfo {
            balance: account.balance.into(),
            nonce: account.nonce.as_u64(),
            code_hash: account.code_hash.0.into(),
            code: code.into(),
        };
        Ok(info)
    }
    fn addresses(&self) -> Vec<B160> {
        self.proofs
            .iter()
            .map(|(address, _proof)| *address)
            .collect()
    }
}

/// Inserts state from a collection of EIP-1186 proof into an in-memory DB.
/// The DB can then be used to trace a block, recording state changes as they occur.
pub fn build_state_from_proofs<T>(block_proofs: T) -> Result<CacheDB<EmptyDB>, StateError>
where
    T: CompleteAccounts,
{
    let mut db = CacheDB::new(EmptyDB::default());

    for address in block_proofs.addresses() {
        let info = block_proofs.to_account_info(&address)?;
        db.insert_account_info(address, info);
    }

    Ok(db)
}
