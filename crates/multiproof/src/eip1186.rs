//! For working with multiple EIP-1186 proofs in concert.
use std::collections::HashMap;

use archors_types::execution::{EvmStateError, StateForEvm};
use archors_types::utils::{eh256_to_ru256, eu256_to_ru256, eu64_to_ru256, rb160_to_eh160};
use ethers::types::{EIP1186ProofResponse, H160, H256, U256 as eU256, U64};
use ethers::utils::keccak256;
use revm::db::{AccountState, DbAccount};
use revm::primitives::{
    Account, AccountInfo, Bytecode, BytecodeState, Bytes, HashMap as rHashMap, B160, B256, U256,
};
use rlp::Encodable;
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::Deserialize;
use thiserror::Error;

use crate::utils::hex_encode;
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
/// For the proof components, duplicate internal nodes are removed.
/// Accounts all go in one trie. Storage goes in one trie per account.
///
/// Includes state data that is necessary and sufficient to execute a block.
pub struct EIP1186MultiProof {
    /// Accounts
    pub accounts: HashMap<H160, AccountData>,
    /// Multiproof for all relevant accounts
    pub account_proofs: MultiProof,
    /// For each relevant account, a multiproof for all relevant storage.
    pub storage_proofs: HashMap<H160, MultiProof>,
    /// For each relevant account, a collection of storage keys.
    pub storage: HashMap<H160, Vec<StorageData>>,
    /// Contract bytecode
    pub code: HashMap<H256, Vec<u8>>,
    /// Map of block number -> block hash
    pub block_hashes: HashMap<U64, H256>,
}

impl EIP1186MultiProof {
    /// Proofs for different accounts combined into a single multiproof.
    ///
    /// Proofs must be from the same tree with the same root.
    pub fn from_separate(
        proofs: Vec<EIP1186ProofResponse>,
        code: HashMap<H256, Vec<u8>>,
        block_hashes: HashMap<U64, H256>,
    ) -> Result<Self, MultiProofError> {
        let mut account_proofs = MultiProof::default();
        let mut storage_proofs: HashMap<H160, MultiProof> = HashMap::default();
        let mut storage: HashMap<H160, Vec<StorageData>> = HashMap::default();
        let mut accounts: HashMap<H160, AccountData> = HashMap::default();
        for acc_proof in proofs {
            // Account
            let account = AccountData {
                nonce: acc_proof.nonce,
                balance: acc_proof.balance.into(),
                storage_hash: acc_proof.storage_hash,
                code_hash: acc_proof.code_hash,
            };
            accounts.insert(acc_proof.address, account);
            // Account proof
            account_proofs.insert_proof(acc_proof.account_proof)?;
            let mut storage_multiproof = MultiProof::init(acc_proof.storage_hash);
            let mut acc_storage: Vec<StorageData> = vec![];
            for storage_proof in acc_proof.storage_proof {
                // Storage for account
                storage_multiproof.insert_proof(storage_proof.proof)?;
                acc_storage.push(StorageData {
                    key: storage_proof.key,
                    value: storage_proof.value,
                });
            }
            storage_proofs.insert(acc_proof.address, storage_multiproof);
            storage.insert(acc_proof.address, acc_storage);
        }
        Ok(EIP1186MultiProof {
            account_proofs,
            accounts,
            storage_proofs,
            storage,
            code,
            block_hashes,
        })
    }
    /// Get the state root.
    pub fn root(&self) -> H256 {
        self.account_proofs.root
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
        account: AccountData,
    ) -> Result<H256, MultiProofError> {
        let address = H160::from_slice(&hex_decode(address_string)?);
        let path = keccak256(address);
        let intent = Intent::Modify(account.rlp_bytes().into());

        self.account_proofs.traverse(path.into(), &intent)?;
        let new_state_root = self.root();
        Ok(new_state_root)
    }
    /// Verifies that every key present in this multiproof is valid with respect to the
    /// root.
    pub fn check_every_key() -> Result<(), MultiProofError> {
        todo!()
    }
}

/// Information about an account with enough data to uniquely identify all components
/// required for an account proof.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
pub struct AccountData {
    pub nonce: U64,
    pub balance: U256,
    pub storage_hash: H256,
    pub code_hash: H256,
}

pub struct StorageData {
    pub key: H256,
    pub value: eU256,
}

impl StateForEvm for EIP1186MultiProof {
    fn get_account_info(&self, address: &B160) -> Result<AccountInfo, EvmStateError> {
        let acc = self
            .accounts
            .get(&rb160_to_eh160(address))
            .ok_or_else(|| EvmStateError::NoProofForAddress(format!("{}", hex_encode(address))))?;

        let info = AccountInfo {
            balance: acc.balance,
            nonce: acc.nonce.as_u64(),
            code_hash: acc.code_hash.into(),
            code: self.code.get(&acc.code_hash).map(|code| Bytecode {
                bytecode: Bytes::copy_from_slice(&code),
                hash: B256::from(acc.code_hash.0),
                state: BytecodeState::Raw,
            }),
        };

        Ok(info)
    }

    fn addresses(&self) -> Vec<B160> {
        self.accounts.keys().map(|key| B160::from(*key)).collect()
    }

    fn get_account_storage(&self, address: &B160) -> Result<rHashMap<U256, U256>, EvmStateError> {
        let mut storage_map = rHashMap::new();
        if let Some(storage) = self.storage.get(&rb160_to_eh160(address)) {
            for entry in storage {
                let key = eh256_to_ru256(entry.key);
                let value = eu256_to_ru256(entry.value)?;
                storage_map.insert(key, value);
            }
        }

        Ok(storage_map)
    }

    fn get_blockhash_accesses(&self) -> Result<rHashMap<U256, B256>, EvmStateError> {
        let mut accesses = rHashMap::new();
        for access in self.block_hashes.iter() {
            let num: U256 = eu64_to_ru256(*access.0);
            let hash: B256 = access.1 .0.into();
            accesses.insert(num, hash);
        }
        Ok(accesses)
    }

    fn update_account(&mut self, address: &B160, account: Account) -> Result<(), EvmStateError> {
        todo!()
    }

    fn state_root_pre_block(&self) -> Result<H256, EvmStateError> {
        todo!()
    }

    fn state_root_post_block(self, changes: HashMap<B160, Account>) -> Result<H256, EvmStateError> {
        todo!()
    }
}
