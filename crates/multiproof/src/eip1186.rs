//! For working with multiple EIP-1186 proofs in concert.
use std::collections::HashMap;
use std::str::FromStr;

use archors_types::execution::{EvmStateError, StateForEvm};
use archors_types::oracle::TrieNodeOracle;
use archors_types::proof::{DisplayProof, DisplayStorageProof};
use archors_types::utils::{
    eh256_to_ru256, eu256_to_ru256, eu64_to_ru256, rb160_to_eh160, ru256_to_eh256,
};
use ethers::types::{EIP1186ProofResponse, H160, H256, U256 as eU256, U64};
use ethers::utils::keccak256;
use log::{debug, info};
use revm::primitives::{
    Account, AccountInfo, Bytecode, BytecodeState, Bytes, HashMap as rHashMap, B160, B256, U256,
};
use rlp::Encodable;
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::Deserialize;
use thiserror::Error;

use crate::oracle::OracleTask;
use crate::proof::ProofOutcome;
use crate::utils::hex_encode;
use crate::{
    proof::{Intent, MultiProof, ProofError},
    utils::UtilsError,
};

#[derive(Debug, Error)]
pub enum MultiProofError {
    #[error("Unable to update account proof for address {address}: {source}")]
    AccountProofError { source: ProofError, address: String },
    #[error("Unable to update storage proof for address {address}, key {key}: {source}")]
    StorageProofError {
        source: ProofError,
        address: String,
        key: String,
    },
    #[error("ProofError {0}")]
    ProofError(#[from] ProofError),
    #[error("UtilsError {0}")]
    UtilsError(#[from] UtilsError),
    #[error("Unable to find account {0} in data structure.")]
    NoAccount(String),
}

/// Multiple EIP-1186 proofs in a representation that can be updated.
/// This allows post-transaction state root calculation.
///
/// For the proof components, duplicate internal nodes are removed.
/// Accounts all go in one trie. Storage goes in one trie per account.
///
/// Includes state data that is necessary and sufficient to execute a block.
#[derive(Debug, Default)]
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
    /// Oracle based nodes cached for trie deletions.
    pub node_oracle: TrieNodeOracle,
}

impl EIP1186MultiProof {
    /// Proofs for different accounts combined into a single multiproof.
    ///
    /// Proofs must be from the same tree with the same root.
    pub fn from_separate(
        proofs: Vec<EIP1186ProofResponse>,
        code: HashMap<H256, Vec<u8>>,
        block_hashes: HashMap<U64, H256>,
        node_oracle: TrieNodeOracle,
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
            node_oracle,
        })
    }
    /// Get the state root. If changes have been made to the trie, the state root will
    /// reflect these changes.
    pub fn current_state_root(&self) -> H256 {
        self.account_proofs.root
    }
    /// Update the storage multiproof for the given account storage key/value pair.
    ///
    /// Returns the updated storage hash for the account, or if an update requires an
    /// oracle lookup, the oracle task is teturned.
    pub fn update_storage_proof(
        &mut self,
        address: &H160,
        storage_key: H256,
        storage_value: eU256,
    ) -> Result<ProofOutcome, MultiProofError> {
        //let key = ru256_to_eh256(storage_key);
        let path = H256::from(keccak256(&storage_key));
        debug!("Storage proof update started for key {}", hex_encode(storage_key));
        let intent = match storage_value == eU256::default() {
            true => Intent::Remove,
            false => Intent::Modify(slot_rlp_from_value(storage_value.into())),
        };

        let proof = self
            .storage_proofs
            .get_mut(&address)
            .ok_or_else(|| MultiProofError::NoAccount(hex_encode(address).to_string()))?;

        proof
            .traverse(path, &intent)
            .map_err(|e| MultiProofError::StorageProofError {
                source: e,
                address: hex_encode(address),
                key: hex_encode(storage_key),
            })?;
        Ok(match &proof.traversal_index_for_oracle_task {
            Some(index) => {
                let outcome = ProofOutcome::IndexForOracle(*index);
                // Wipe the index from the multiproof so that later storage updates have fresh value.
                proof.traversal_index_for_oracle_task = None;
                outcome
            }
            None => ProofOutcome::Root(proof.root),
        })
    }

    /// Update the account multiproof so that the values in the provided account match.
    /// Returns the updated state root.
    fn update_account_proof(
        &mut self,
        address: &B160,
        account: AccountData,
    ) -> Result<H256, MultiProofError> {
        let path = keccak256(address);
        // Even if SELFDESCTRUCT is used, Intent::Remove is not used because the account is kept
        // in the trie (with null storage/code hashes).
        let intent = Intent::Modify(account.rlp_bytes().into());
        self.account_proofs
            .traverse(path.into(), &intent)
            .map_err(|e| MultiProofError::AccountProofError {
                source: e,
                address: hex_encode(address),
            })?;
        Ok(self.current_state_root())
    }
    /// Accepts all changes for a single account returned from REVM and returns the
    /// updated state root.
    ///
    /// 1. If storage changes, update storage proof and get new storage hash.
    /// 2. Use storage hash and update account
    /// 3. Return state root.
    ///
    // Data outside the proofs is not updated because it is not required.
    // Though this is technically feasible.
    pub fn apply_account_delta(
        &mut self,
        address: &B160,
        account_updates: Account,
    ) -> Result<H256, MultiProofError> {
        debug!(
            "Account proof update started for address {}",
            hex_encode(address)
        );
        let address_eh = rb160_to_eh160(address);
        let existing_account = self
            .accounts
            .get(&address_eh)
            .ok_or_else(|| MultiProofError::NoAccount(hex_encode(address)))?
            .clone();
        let mut storage_hash = existing_account.storage_hash;
        let mut tasks: Vec<OracleTask> = vec![];
        for (storage_key, storage_value) in account_updates.storage {
            let key = ru256_to_eh256(storage_key);
            if storage_value.is_changed() {
                match self.update_storage_proof(
                    &address_eh,
                    key,
                    storage_value.present_value.into(),
                )? {
                    ProofOutcome::Root(hash) => storage_hash = hash,
                    ProofOutcome::IndexForOracle(traversal_index) => {
                        debug!(
                            "Task received for key {}",
                            hex_encode(&storage_key.to_be_bytes_vec())
                        );
                        let task = OracleTask {
                            address: address_eh,
                            key,
                            traversal_index,
                        };
                        tasks.push(task)
                    }
                }
            }
        }
        // Start with oracle tasks with deepest traversal depth. This prevents tasks from clashing.
        tasks.sort_by_key(|x| x.traversal_index);
        let task_count = tasks.len();
        for (index, task) in tasks.into_iter().rev().enumerate() {
            debug!("Starting {} ({} of {})", task, index + 1, task_count);
            let proof = self
                .storage_proofs
                .get_mut(&address_eh)
                .expect("No account");
            proof.traverse_oracle_update(task, &self.node_oracle)?;
            storage_hash = proof.root;
        }
        if task_count != 0 {
            debug!(
                "Finished {} oracle task(s) for account {}",
                task_count,
                hex_encode(address)
            );
        }

        let updated_account = AccountData {
            nonce: account_updates.info.nonce.into(),
            balance: account_updates.info.balance,
            storage_hash,
            code_hash: account_updates.info.code_hash.into(),
        };
        match updated_account.eq(&existing_account) {
            true => Ok(self.current_state_root()),
            false => {
                let state_root = self.update_account_proof(address, updated_account)?;
                Ok(state_root)
            }
        }
    }
    /// Verifies that every key present in this multiproof is valid with respect to the
    /// root.
    pub fn check_every_key() -> Result<(), MultiProofError> {
        todo!()
    }
}

/// Get the RLP-encoded form of a storage value.
pub fn slot_rlp_from_value(storage_value: U256) -> Vec<u8> {
    let trimmed = storage_value.to_be_bytes_trimmed_vec();
    rlp::encode(&trimmed).to_vec()
}

/// Information about an account with enough data to uniquely identify all components
/// required for an account proof.
///
/// An account consists of these four members, RLP-encoded in this order.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
pub struct AccountData {
    pub nonce: U64,
    pub balance: U256,
    pub storage_hash: H256,
    pub code_hash: H256,
}

#[derive(Debug, Default)]
pub struct StorageData {
    pub key: H256,
    pub value: eU256,
}

impl StateForEvm for EIP1186MultiProof {
    fn get_account_info(&self, address: &B160) -> Result<AccountInfo, EvmStateError> {
        let acc = self
            .accounts
            .get(&rb160_to_eh160(address))
            .ok_or_else(|| EvmStateError::NoProofForAddress(hex_encode(address).to_string()))?;

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

    fn state_root_post_block(
        &mut self,
        changes: HashMap<B160, Account>,
    ) -> Result<B256, EvmStateError> {
        // Sort by address for debugging reliability. TODO remove if not needed or use BTreeMap.
        let mut changes: Vec<(B160, Account)> = changes.into_iter().collect();
        changes.sort_by_key(|x| x.0);
        let mut root = self.account_proofs.root;
        for (address, account_updates) in changes.into_iter() {
            root = self
                .apply_account_delta(&address, account_updates)
                .map_err(|e| EvmStateError::PostRoot(e.to_string()))?;
        }

        info!("Post-execution state root computed");
        Ok(B256::from(root))
    }

    fn print_account_proof<T: AsRef<str>>(
        &self,
        account_address: T,
    ) -> Result<DisplayProof, EvmStateError> {
        let address = H160::from_str(account_address.as_ref())
            .map_err(|e| EvmStateError::InvalidAddress(e.to_string()))?;
        let proof = self
            .account_proofs
            .view(keccak256(address).into())
            .map_err(|e| EvmStateError::DisplayError(e.to_string()))?;
        Ok(proof)
    }

    fn print_storage_proof<T: AsRef<str>>(
        &self,
        account_address: T,
        storage_key: T,
    ) -> Result<DisplayStorageProof, EvmStateError> {
        let address = H160::from_str(account_address.as_ref())
            .map_err(|e| EvmStateError::InvalidAddress(e.to_string()))?;
        // Permit the key to be passed as a uint, though technically should be H256.
        let uint_key = U256::from_str(storage_key.as_ref())
            .map_err(|e| EvmStateError::InvalidStorageKey(e.to_string()))?;
        let h256_key = ru256_to_eh256(uint_key);
        let path = keccak256(h256_key);
        let storage_proofs = self
            .storage_proofs
            .get(&address)
            .ok_or(EvmStateError::NoProofForAddress(address.to_string()))?;
        let proof = storage_proofs
            .view(path.into())
            .map_err(|e| EvmStateError::DisplayError(e.to_string()))?;
        Ok(DisplayStorageProof {
            account: self.print_account_proof(&account_address)?,
            storage: proof,
        })
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, fs::File, io::BufReader, str::FromStr};

    use super::*;
    use archors_verify::path::{NibblePath, TargetNodeEncoding};
    use ethers::types::H256;

    use revm::primitives::{HashMap as rHashMap, StorageSlot};

    use crate::{proof::Node, utils::hex_decode, EIP1186MultiProof};
    fn load_proof(path: &str) -> EIP1186MultiProof {
        let file = File::open(&path).expect(&format!("no proof found at {}", path));
        let reader = BufReader::new(&file);
        let proof = serde_json::from_reader(reader).expect("could not parse proof");
        EIP1186MultiProof::from_separate(
            vec![proof],
            HashMap::new(),
            HashMap::new(),
            TrieNodeOracle::default(),
        )
        .unwrap()
    }

    fn load_proof_str(string: &str) -> EIP1186MultiProof {
        let proof = serde_json::from_str(string).expect("could not parse proof");
        EIP1186MultiProof::from_separate(
            vec![proof],
            HashMap::new(),
            HashMap::new(),
            TrieNodeOracle::default(),
        )
        .unwrap()
    }

    const PROOF_1: &'static str = r#"{
        "address": "0xaa00000000000000000000000000000000000000",
        "accountProof": [
        "0xf8718080808080a0a2bd2175aed7ed88ed854c914fab94115c092ffb3c3c2ef647b70b7e73e3345880a0457ae8d978cd387f5332f978f5653226588b6cc76a355fc5977cd4325ffcff78a0c4bdbdbb240f8343b7f84bc83d4b7426e803a914138792d1e369907be8098b2d8080808080808080",
        "0xf869a0335649db80be637d281db0cc5896b0ff9869d08379a80fdc38dd073bba633949b846f8440101a08afc95b7d18a226944b9c2070b6bda1c3a36afcc3730429d47579c94b9fe5850a0ce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99"
        ],
        "balance": "0x1",
        "codeHash": "0xce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99",
        "nonce": "0x1",
        "storageHash": "0x8afc95b7d18a226944b9c2070b6bda1c3a36afcc3730429d47579c94b9fe5850",
        "storageProof": [
        {
            "key": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "value": "0x0",
            "proof": [
            "0xf871808080a0ce028e108cf5c832b0a9afd3ed101183857b3b9ddaea5670c4f09b62e4d38d05a0de3ecad66628a5743ed089e3a35ebeedc25a922fb0ac346304613403911c18e0a0128c5f7abac505794cda09bde44d143e4736b50b1c42d6807a989c10af51e8d18080808080808080808080"
            ]
        }
        ]
      }"#;

    #[test]
    fn test_root_unchanged_after_no_update_to_account_1() {
        let mut proof = load_proof_str(PROOF_1);
        let state_root = H256::from_slice(
            &hex_decode("0x61effbbcca94f0d3e02e5bd22e986ad57142acabf0cb3d129a6ad8d0f8752e94")
                .unwrap(),
        );
        assert_eq!(proof.current_state_root(), state_root);
        let address = "aa00000000000000000000000000000000000000";
        let storage_hash = proof
            .accounts
            .get(&H160::from_str(address).unwrap())
            .unwrap()
            .storage_hash;
        assert_eq!(
            storage_hash,
            H256::from_str("0x8afc95b7d18a226944b9c2070b6bda1c3a36afcc3730429d47579c94b9fe5850")
                .unwrap()
        );
        let mut storage_update = rHashMap::default();
        storage_update.insert(
            U256::from_str("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            StorageSlot {
                original_value: U256::from_str("0").unwrap(),
                present_value: U256::from_str("0").unwrap(),
            },
        );
        let account_updates = Account {
            info: AccountInfo {
                balance: U256::from_str("1").unwrap(),
                nonce: 1u64,
                code_hash: B256::from_str(
                    "0xce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99",
                )
                .unwrap(),
                code: None,
            },
            storage: storage_update,
            storage_cleared: false,
            is_destroyed: false,
            is_touched: false,
            is_not_existing: false,
        };
        let post_root = proof
            .apply_account_delta(&B160::from_str(address).unwrap(), account_updates)
            .unwrap();
        // Check the root fetcher returns the same new value.
        assert_eq!(post_root, proof.current_state_root());
        // Check that the root is the same (no changes were made).
        assert_eq!(post_root, state_root);
    }

    /**
    Check that the trie update mechanism works for a basic nonce increment.

    Account proof with nonce = 1
    "0xf8718080808080a0a2bd2175aed7ed88ed854c914fab94115c092ffb3c3c2ef647b70b7e73e3345880a0457ae8d978cd387f5332f978f5653226588b6cc76a355fc5977cd4325ffcff78a0c4bdbdbb240f8343b7f84bc83d4b7426e803a914138792d1e369907be8098b2d8080808080808080",
    "0xf869a0335649db80be637d281db0cc5896b0ff9869d08379a80fdc38dd073bba633949b846f8440101a08afc95b7d18a226944b9c2070b6bda1c3a36afcc3730429d47579c94b9fe5850a0ce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99"

    New account RLP (printed above). f8440101a0.. -> f8440201a0...
    0xf8440201a08afc95b7d18a226944b9c2070b6bda1c3a36afcc3730429d47579c94b9fe5850a0ce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99

    Manually insert new RLP to final node:
    Account proof with nonce = 2
    "0xf869a0335649db80be637d281db0cc5896b0ff9869d08379a80fdc38dd073bba633949b846f8440201a08afc95b7d18a226944b9c2070b6bda1c3a36afcc3730429d47579c94b9fe5850a0ce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99"

    Hash of new final node:
    d1e13c77cfc77c181e6c8d0e7a3fe3529368bb36cacc67da80f0b453b03f3617

    Update the first proof node by replacing 457a...ff78 with above hash

    new first node: "0xf8718080808080a0a2bd2175aed7ed88ed854c914fab94115c092ffb3c3c2ef647b70b7e73e3345880a0d1e13c77cfc77c181e6c8d0e7a3fe3529368bb36cacc67da80f0b453b03f3617a0c4bdbdbb240f8343b7f84bc83d4b7426e803a914138792d1e369907be8098b2d8080808080808080",

    Hash of new first node (new state root):
    441ad37ef009dbf8cd6830845d658e58c6a6620172de4e93daef90352f284de1

    */
    #[test]
    fn test_root_after_account_nonce_increment() {
        // Manually computed the new state root.
        let _account = AccountData {
            nonce: U64::from_str("0x2").unwrap(), // incremented
            balance: U256::from_str("0x1").unwrap(),
            storage_hash: H256::from_str(
                "0x8afc95b7d18a226944b9c2070b6bda1c3a36afcc3730429d47579c94b9fe5850",
            )
            .unwrap(),
            code_hash: H256::from_str(
                "0xce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99",
            )
            .unwrap(),
        };
        // println!("new acc rlp: {}", hex_encode(account.rlp_bytes()));

        // Now use the update function to compute the new root.
        let account_updates = Account {
            info: AccountInfo {
                balance: U256::from_str("1").unwrap(),
                nonce: 2u64, // incremented
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
        };
        let mut proof = load_proof_str(PROOF_1);
        let address = "aa00000000000000000000000000000000000000";
        let post_root = proof
            .apply_account_delta(&B160::from_str(address).unwrap(), account_updates)
            .unwrap();
        // Check the computed root matches the manual calcuation.
        assert_eq!(
            post_root,
            H256::from_str("441ad37ef009dbf8cd6830845d658e58c6a6620172de4e93daef90352f284de1")
                .unwrap()
        );
    }
    /**
    Checks that the manually computed storage root matches the computed root after
    changing a storage slot value.

    Key: 0x000...001
    Key path (hash of key): b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6

    Storage node: 0xf871808080a0ce028e108cf5c832b0a9afd3ed101183857b3b9ddaea5670c4f09b62e4d38d05a0de3ecad66628a5743ed089e3a35ebeedc25a922fb0ac346304613403911c18e0a0128c5f7abac505794cda09bde44d143e4736b50b1c42d6807a989c10af51e8d18080808080808080808080

    The storage node has 3 items, in positions 0x3, 0x4, 0x5. Position 0xb is free, and this is where the leaf node will be added.

    Leaf path (trim the 0xb): 10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6
    Hex-prefixed path (odd leaf = prefix with 3): 310e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6

    Leaf value = 0x7
    Leaf RLP node = 0xe2a0<path><value> = 0xe2a0310e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf607
    Leaf hash = 4784fb4f62cc58a00b3ae50ff62c0a3672be2328c21840707284bb09a77ca21a

    first storage node = 0xf891808080a0ce028e108cf5c832b0a9afd3ed101183857b3b9ddaea5670c4f09b62e4d38d05a0de3ecad66628a5743ed089e3a35ebeedc25a922fb0ac346304613403911c18e0a0128c5f7abac505794cda09bde44d143e4736b50b1c42d6807a989c10af51e8d18080808080a04784fb4f62cc58a00b3ae50ff62c0a3672be2328c21840707284bb09a77ca21a8080808080

    new storage hash = 41d1b06c8a131d1ba094d9157054358df40085906ef614437cbad8a5cd233fe2

    new account rlp = 0xf8440101a041d1b06c8a131d1ba094d9157054358df40085906ef614437cbad8a5cd233fe2a0ce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99

    old account leaf node = 0xf869a0335649db80be637d281db0cc5896b0ff9869d08379a80fdc38dd073bba633949b846 f8440101a08afc95b7d18a226944b9c2070b6bda1c3a36afcc3730429d47579c94b9fe5850a0ce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99

    new account leaf node = 0xf869a0335649db80be637d281db0cc5896b0ff9869d08379a80fdc38dd073bba633949b846f8440101a041d1b06c8a131d1ba094d9157054358df40085906ef614437cbad8a5cd233fe2a0ce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99

    new account leaf hash = fad62b0aae498bcbac391cfb2ae7283eb9ec8f8c2bc283d26063bfa216e6207a

    old account proof first node = 0xf8718080808080a0a2bd2175aed7ed88ed854c914fab94115c092ffb3c3c2ef647b70b7e73e3345880a0457ae8d978cd387f5332f978f5653226588b6cc76a355fc5977cd4325ffcff78a0c4bdbdbb240f8343b7f84bc83d4b7426e803a914138792d1e369907be8098b2d8080808080808080

    new account proof first node = 0xf8718080808080a0a2bd2175aed7ed88ed854c914fab94115c092ffb3c3c2ef647b70b7e73e3345880a0fad62b0aae498bcbac391cfb2ae7283eb9ec8f8c2bc283d26063bfa216e6207aa0c4bdbdbb240f8343b7f84bc83d4b7426e803a914138792d1e369907be8098b2d8080808080808080

    new root hash = 388e66d9a17f8ac62cc95d24d5842e587fd92b55fd31ccb67b0e16a96adc746f

    */
    #[test]
    fn test_root_after_storage_change() {
        // 3 empty, 3 full, new at 0xb.
        let _node = Node::try_from(vec![
            vec![],
            vec![],
            vec![],
            hex_decode("ce028e108cf5c832b0a9afd3ed101183857b3b9ddaea5670c4f09b62e4d38d05").unwrap(),
            hex_decode("de3ecad66628a5743ed089e3a35ebeedc25a922fb0ac346304613403911c18e0").unwrap(),
            hex_decode("128c5f7abac505794cda09bde44d143e4736b50b1c42d6807a989c10af51e8d1").unwrap(),
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            // new leaf hash at 0xb
            hex_decode("fad62b0aae498bcbac391cfb2ae7283eb9ec8f8c2bc283d26063bfa216e6207a").unwrap(),
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        ])
        .unwrap();
        // println!("new storage {}", hex_encode(node.to_rlp_list()));
        // Manually computed the new state root.
        let _account = AccountData {
            nonce: U64::from_str("0x1").unwrap(),
            balance: U256::from_str("0x1").unwrap(),
            // updated
            storage_hash: H256::from_str(
                "0x41d1b06c8a131d1ba094d9157054358df40085906ef614437cbad8a5cd233fe2",
            )
            .unwrap(),
            code_hash: H256::from_str(
                "0xce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99",
            )
            .unwrap(),
        };
        // println!("new acc rlp: {}", hex_encode(account.rlp_bytes()));

        // Slot changed from 0x0 (exclusion proof) to 0x7 (inclusion proof).
        let mut storage = rHashMap::default();
        storage.insert(
            U256::from_str("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            StorageSlot {
                original_value: U256::from_str("0x0").unwrap(),
                present_value: U256::from_str("0x7").unwrap(),
            },
        );
        let account_updates = Account {
            info: AccountInfo {
                balance: U256::from_str("1").unwrap(),
                nonce: 1u64,
                code_hash: B256::from_str(
                    "0xce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99",
                )
                .unwrap(),
                code: None,
            },
            storage, // updated
            storage_cleared: false,
            is_destroyed: false,
            is_touched: false,
            is_not_existing: false,
        };
        let mut proof = load_proof_str(PROOF_1);
        let address = "aa00000000000000000000000000000000000000";
        // Use the update function to compute the new root.
        let post_root = proof
            .apply_account_delta(&B160::from_str(address).unwrap(), account_updates)
            .unwrap();
        // Check the computed root matches the manual calcuation.
        assert_eq!(
            post_root,
            H256::from_str("388e66d9a17f8ac62cc95d24d5842e587fd92b55fd31ccb67b0e16a96adc746f")
                .unwrap()
        );
    }
    #[test]
    fn test_root_unchanged_after_no_update_to_account_2() {
        let mut proof = load_proof("../verify/data/test_proof_2.json");
        let state_root = H256::from_slice(
            &hex_decode("0x57e6e864257daf9d96aaca31edd0cfe4e3892f09061e727c57ab56197dd59287")
                .unwrap(),
        );
        assert_eq!(proof.current_state_root(), state_root);
        let address = "7ae1d57b58fa6411f32948314badd83583ee0e8c";
        let storage_hash = proof
            .accounts
            .get(&H160::from_str(address).unwrap())
            .unwrap()
            .storage_hash;
        assert_eq!(
            storage_hash,
            H256::from_str("0x3836d7e3afb674e5180b7564e096f6f3e30308878a443fe59012ced093544b7f")
                .unwrap()
        );
        let mut storage_update = rHashMap::default();
        storage_update.insert(
            U256::from_str("0").unwrap(),
            StorageSlot {
                original_value: U256::from_str("0").unwrap(),
                present_value: U256::from_str("0").unwrap(),
            },
        );
        let account_updates = Account {
            info: AccountInfo {
                balance: U256::from_str("0").unwrap(),
                nonce: 1u64,
                code_hash: B256::from_str(
                    "2cfdfbdd943ec0153ed07b97f03eb765dc11cc79c6f750effcc2d126f93c4b31",
                )
                .unwrap(),
                code: None,
            },
            storage: storage_update,
            storage_cleared: false,
            is_destroyed: false,
            is_touched: false,
            is_not_existing: false,
        };
        let post_root = proof
            .apply_account_delta(&B160::from_str(address).unwrap(), account_updates)
            .unwrap();
        // Check the root fetcher returns the same new value.
        assert_eq!(post_root, proof.current_state_root());
        // Check that the root is the same (no changes were made).
        assert_eq!(post_root, state_root);
    }

    #[test]
    fn test_slot_rlp_from_value() {
        // Short U256 is stored as U256
        assert_eq!(slot_rlp_from_value(U256::from(3)), vec![0x3]);

        // Round trip for 32 byte value.
        let long_string = "0x64544dd700000000000047b92012b8aa582300001882a426ac785114088bf5d2";
        let big_val = U256::from_str(long_string).unwrap();
        let rlp = slot_rlp_from_value(big_val);
        let derived: Vec<u8> = rlp::decode(&rlp).unwrap();
        assert_eq!(derived, hex_decode(long_string).unwrap());
    }

    #[test]
    fn test_construct_leaf_value() {
        // Source: test_proof_3.json
        let key =
            U256::from_str("0x0000000000000000000000000000000000000000000000000000000000000008")
                .unwrap();
        let value = U256::from_str("0x71afd498d00028de4544dd705613413f88").unwrap();
        let path = NibblePath::init(&keccak256(key.to_be_bytes_vec()));
        let prefixed_leaf_path = path
            .get_encoded_path(TargetNodeEncoding::Leaf, 3, 63)
            .unwrap();
        assert_eq!(
            hex_encode(&prefixed_leaf_path),
            "0x37a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee3"
        );
        let leaf_value = slot_rlp_from_value(value);
        assert_eq!(
            hex_encode(&leaf_value),
            "0x9171afd498d00028de4544dd705613413f88"
        );
        let leaf = Node::try_from(vec![prefixed_leaf_path, leaf_value])
            .unwrap()
            .to_rlp_list();
        assert_eq!(hex_encode(leaf), "0xf39f37a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee3929171afd498d00028de4544dd705613413f88");
    }

    /**
    This account in block 17190873 requires an oracle for internal trie nodes because a key
    is deleted, causing a branch removal. The missing data must be foreseen and provided as
    ancillary data called an oracle. This test confirms the use of the oracle to get the
    correct storage root for the account.

    - account 0x0a6dd5d5a00d6cb0678a4af507ba79a517d5eb64
    - key 0x0381163500ec1bb2a711ed278aa3caac8cd61ce95bc6c4ce50958a5e1a83494b
    */
    #[test]
    fn test_root_after_storage_change_requiring_oracle() {
        todo!()
    }
}
