//! For working with multiple EIP-1186 proofs in concert.
use std::collections::HashMap;

use archors_types::execution::{EvmStateError, StateForEvm};
use archors_types::utils::{
    eh256_to_ru256, eu256_to_ru256, eu64_to_ru256, rb160_to_eh160, ru256_to_eh256,
};
use ethers::types::{EIP1186ProofResponse, H160, H256, U256 as eU256, U64};
use ethers::utils::keccak256;
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
    utils::UtilsError,
};

#[derive(Debug, Error)]
pub enum MultiProofError {
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
    /// Get the state root. If changes have been made to the trie, the state root will
    /// reflect these changes.
    pub fn current_state_root(&self) -> H256 {
        self.account_proofs.root
    }
    /// Update the storage multiproof for the given account storage key/value pair.
    ///
    /// Returns the updated storage hash for the account.
    fn update_storage_proof(
        &mut self,
        address: &B160,
        slot_key: U256,
        slot_value: U256,
    ) -> Result<H256, MultiProofError> {
        let path = keccak256(&ru256_to_eh256(slot_key));
        let slot_rlp = rlp::encode(&slot_value).to_vec();
        let slot_node = match slot_rlp.len() < 32 {
            true => slot_rlp,
            false => keccak256(&slot_rlp).to_vec(),
        };
        let intent = Intent::Modify(slot_node);
        let proof = self
            .storage_proofs
            .get_mut(&rb160_to_eh160(address))
            .ok_or_else(|| MultiProofError::NoAccount(format!("{}", hex_encode(address))))?;
        proof.traverse(H256::from(path), &intent)?;
        Ok(proof.root)
    }

    /// Update the account multiproof so that the values in the provided account match.
    /// Returns the updated state root.
    fn update_account_proof(
        &mut self,
        address: &B160,
        account: AccountData,
    ) -> Result<H256, MultiProofError> {
        let path = keccak256(address);
        let intent = Intent::Modify(account.rlp_bytes().into());

        self.account_proofs.traverse(path.into(), &intent)?;
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
        let existing_account = self
            .accounts
            .get(&rb160_to_eh160(address))
            .ok_or_else(|| MultiProofError::NoAccount(hex_encode(address)))?
            .clone();
        let mut storage_hash = existing_account.storage_hash;

        for (key, slot) in account_updates.storage {
            storage_hash = self.update_storage_proof(address, key, slot.present_value)?
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

    fn state_root_post_block(
        mut self,
        changes: HashMap<B160, Account>,
    ) -> Result<B256, EvmStateError> {
        // Sort by address for debugging reliability.
        let mut changes: Vec<(B160, Account)> = changes.into_iter().collect();
        changes.sort_by_key(|x|x.0);
        let mut root = self.account_proofs.root;
        let total = changes.len() - 1;
        for (index, (address, account_updates)) in changes.into_iter().enumerate() {
            println!("updating account {index} of {total}. Address {}", hex_encode(address));
            root = self
                .apply_account_delta(&address, account_updates)
                .map_err(|e| EvmStateError::PostRoot(e.to_string()))?;
        }
        Ok(B256::from(root))
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, fs::File, io::BufReader, str::FromStr};

    use super::*;
    use ethers::types::H256;

    use revm::primitives::{AccountStatus, HashMap as rHashMap, StorageSlot};

    use crate::{utils::hex_decode, EIP1186MultiProof};
    fn load_proof(path: &str) -> EIP1186MultiProof {
        let file = File::open(&path).expect(&format!("no proof found at {}", path));
        let reader = BufReader::new(&file);
        let proof = serde_json::from_reader(reader).expect("could not parse proof");
        EIP1186MultiProof::from_separate(vec![proof], HashMap::new(), HashMap::new()).unwrap()
    }

    fn load_proof_str(string: &str) -> EIP1186MultiProof {
        let proof = serde_json::from_str(string).expect("could not parse proof");
        EIP1186MultiProof::from_separate(vec![proof], HashMap::new(), HashMap::new()).unwrap()
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
            status: AccountStatus::default(),
        };
        let post_root = proof
            .apply_account_delta(&B160::from_str(address).unwrap(), account_updates)
            .unwrap();
        // Check the root fetcher returns the same new value.
        assert_eq!(post_root, proof.current_state_root());
        // Check that the root is the same (no changes were made).
        assert_eq!(post_root, state_root);
    }

    /// Check that the trie update mechanism works for a basic nonce increment.
    ///
    /// Account proof with nonce = 1
    /// "0xf8718080808080a0a2bd2175aed7ed88ed854c914fab94115c092ffb3c3c2ef647b70b7e73e3345880a0457ae8d978cd387f5332f978f5653226588b6cc76a355fc5977cd4325ffcff78a0c4bdbdbb240f8343b7f84bc83d4b7426e803a914138792d1e369907be8098b2d8080808080808080",
    /// "0xf869a0335649db80be637d281db0cc5896b0ff9869d08379a80fdc38dd073bba633949b846f8440101a08afc95b7d18a226944b9c2070b6bda1c3a36afcc3730429d47579c94b9fe5850a0ce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99"
    ///
    /// New account RLP (printed above). f8440101a0.. -> f8440201a0...
    /// 0xf8440201a08afc95b7d18a226944b9c2070b6bda1c3a36afcc3730429d47579c94b9fe5850a0ce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99
    ///
    /// Manually insert new RLP to final node:
    /// Account proof with nonce = 2
    /// "0xf869a0335649db80be637d281db0cc5896b0ff9869d08379a80fdc38dd073bba633949b846f8440201a08afc95b7d18a226944b9c2070b6bda1c3a36afcc3730429d47579c94b9fe5850a0ce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99"
    ///
    /// Hash of new final node:
    /// d1e13c77cfc77c181e6c8d0e7a3fe3529368bb36cacc67da80f0b453b03f3617
    ///
    /// Update the first proof node by replacing 457a...ff78 with above hash
    ///
    /// new first node: "0xf8718080808080a0a2bd2175aed7ed88ed854c914fab94115c092ffb3c3c2ef647b70b7e73e3345880a0d1e13c77cfc77c181e6c8d0e7a3fe3529368bb36cacc67da80f0b453b03f3617a0c4bdbdbb240f8343b7f84bc83d4b7426e803a914138792d1e369907be8098b2d8080808080808080",
    ///
    /// Hash of new first node (new state root):
    /// 441ad37ef009dbf8cd6830845d658e58c6a6620172de4e93daef90352f284de1
    ///
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
            status: AccountStatus::default(),
        };
        let mut proof = load_proof_str(PROOF_1);
        let address = "aa00000000000000000000000000000000000000";
        let post_root = proof
            .apply_account_delta(&B160::from_str(address).unwrap(), account_updates)
            .unwrap();
        // Check the computed root matches the manual calcuation.
        assert_eq!(post_root, H256::from_str("441ad37ef009dbf8cd6830845d658e58c6a6620172de4e93daef90352f284de1").unwrap());
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
            status: AccountStatus::default(),
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
    fn test_root_after_storage_change() {
        todo!()
    }
}
