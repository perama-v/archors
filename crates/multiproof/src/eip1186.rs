//! For working with multiple EIP-1186 proofs in concert.
use std::collections::HashMap;

use archors_types::execution::StateForEvm;
use ethers::types::{EIP1186ProofResponse, H160, H256, U64};
use ethers::utils::keccak256;
use revm::primitives::{AccountInfo, HashMap as rHashMap, B160, B256, U256, Account};
use rlp::Encodable;
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::Deserialize;
use thiserror::Error;

use crate::{
    proof::{Intent, MultiProof, ProofError},
    utils::{hex_decode, UtilsError},
};

#[derive(Debug, Error)]
pub enum MultiProofError {
    #[error("ProofError {0}")]
    MultiProofError(#[from] ProofError),
    #[error("UtilsError {0}")]
    UtilsError(#[from] UtilsError),
}

/// Multiple EIP-1186 proofs in a representation that can be updated.
/// This allows post-transaction state root calculation.
///
/// Contains relevant data only, meaning
/// that which is state that the current block accesses (reads/writes).
///
/// Accounts all go in one trie. Storage goes in one trie per account.
pub struct EIP1186MultiProof {
    /// Multiproof for all relevant accounts
    pub accounts: MultiProof,
    /// For each relevant account, a multiproof for all relevant storage.
    pub storage: HashMap<H160, MultiProof>,
    /// For each relevant account, a collection of storage keys.
    pub storage_keys: HashMap<H160, Vec<H256>>,
}

impl EIP1186MultiProof {
    /// Proofs for different accounts combined into a single multiproof.
    ///
    /// Proofs must be from the same tree with the same root.
    pub fn from_separate(
        proofs: Vec<EIP1186ProofResponse>,
        root: H256,
    ) -> Result<Self, MultiProofError> {
        let mut accounts = MultiProof::init(root);
        let mut storage: HashMap<H160, MultiProof> = HashMap::default();
        let mut storage_keys: HashMap<H160, Vec<H256>> = HashMap::default();
        for acc_proof in proofs {
            // Account
            accounts.insert_proof(acc_proof.account_proof)?;
            let mut storage_multiproof = MultiProof::init(acc_proof.storage_hash);
            let mut keys: Vec<H256> = vec![];
            for storage_proof in acc_proof.storage_proof {
                // Storage for account
                storage_multiproof.insert_proof(storage_proof.proof)?;
                keys.push(storage_proof.key);
            }
            storage.insert(acc_proof.address, storage_multiproof);
            storage_keys.insert(acc_proof.address, keys);
        }
        Ok(EIP1186MultiProof {
            accounts,
            storage,
            storage_keys,
        })
    }
    /// Get the state root.
    pub fn root(&self) -> H256 {
        self.accounts.root
    }

    pub fn modify_slot(
        &mut self,
        _account: &str,
        _slot_key: &str,
        _slot_value: &str,
    ) -> Result<(), MultiProofError> {
        // let key = ethers::types::H256::from_str(slot_key);

        // First traverse the storage multiproof and make changes.
        // Then get the storage hash and update the account. Then
        // traverse the account multiproof and make changes.
        // Then get the root.
        todo!()
    }

    /// Update the proof so that the values in the provided account match.
    pub fn modify_account<T: AsRef<str>>(
        &mut self,
        address_string: T,
        account: AccountModifier,
    ) -> Result<H256, MultiProofError> {
        let address = H160::from_slice(&hex_decode(address_string)?);
        let path = keccak256(address);
        let intent = Intent::Modify(account.rlp_bytes().into());

        self.accounts.traverse(path.into(), &intent)?;
        let new_state_root = self.root();
        Ok(new_state_root)
    }
    /// Verifies that every key present in this multiproof is valid with respect to the
    /// root.
    pub fn check_every_key() -> Result<(), MultiProofError> {
        todo!()
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
pub struct AccountModifier {
    pub nonce: U64,
    pub balance: U256,
    pub storage_hash: H256,
    pub code_hash: H256,
}

impl StateForEvm for EIP1186MultiProof {
    fn get_account_info(
        &self,
        address: &B160,
    ) -> Result<AccountInfo, archors_types::execution::EvmStateError> {
        todo!()
    }

    fn addresses(&self) -> Vec<B160> {
        todo!()
    }

    fn get_account_storage(
        &self,
        address: &B160,
    ) -> Result<rHashMap<U256, U256>, archors_types::execution::EvmStateError> {
        todo!()
    }

    fn get_blockhash_accesses(
        &self,
    ) -> Result<rHashMap<U256, B256>, archors_types::execution::EvmStateError> {
        todo!()
    }

    fn update_account(
        &mut self,
        address: &B160,
        account: Account,
    ) -> Result<(), archors_types::execution::EvmStateError> {
        todo!()
    }

    fn state_root_pre_block(&self) -> Result<H256, archors_types::execution::EvmStateError> {
        todo!()
    }

    fn state_root_post_block(
        self,
        changes: HashMap<B160, Account>,
    ) -> Result<H256, archors_types::execution::EvmStateError> {
        todo!()
    }
}
