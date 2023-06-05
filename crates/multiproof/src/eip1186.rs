//! For working with multiple EIP-1186 proofs in concert.
use std::collections::HashMap;

use ethers::types::{EIP1186ProofResponse, H160, H256, U256};
use thiserror::Error;

use crate::proof::{MultiProof, ProofError};

#[derive(Debug, Error)]
pub enum MultiProofError {
    #[error("ProofError {0}")]
    ProofError(#[from] ProofError),
}

/// Multiple EIP-1186 proofs in a representation that can be updated.
/// This allows post-transaction state root calculation.
///
/// Contains relevant data only, meaning
/// that which is state that the current block accesses (reads/writes).
///
/// Accounts all go in one trie. Storage goes in one trie per account.
pub struct EIP1186MultiProof {
    /// Proof for all relevant accounts
    pub accounts: MultiProof,
    /// For each relevant account, a proof for all relevant storage.
    pub storage: HashMap<H160, MultiProof>,
    /// For each relevant account, a list of storage keys.
    pub storage_keys: Vec<H256>
}

impl EIP1186MultiProof {
    /// Proofs for different accounts combined into a single multiproof.
    ///
    /// Proofs must be from the same tree with the same root.
    pub fn from_separate(proofs: Vec<EIP1186ProofResponse>) -> Result<Self, MultiProofError> {
        let mut account_multi = MultiProof::default();
        for proof in proofs {
            account_multi.insert(proof.account_proof)?;
        }

       Ok(todo!())
    }

    pub fn root(&self) -> H256 {
        todo!()
    }

    pub fn modify_slot(
        &mut self,
        account: H160,
        slot_key: H256,
        slot_value: U256,
    ) -> Result<(), MultiProofError> {
        Ok(todo!())
    }

    /// Update the proof so that the values in the provided account match.
    pub fn modify_account (&mut self) {
        todo!()
    }
}

