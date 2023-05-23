use std::{collections::HashMap, fmt::Display};

use ethers::types::{EIP1186ProofResponse, H256};
use serde::{Deserialize, Serialize};

use crate::eip1186::{verify_proof, VerifyProofError};

/// Helper for caching
#[derive(Deserialize, Serialize)]
pub struct BlockProofs {
    /// Map of account -> proof
    pub proofs: HashMap<String, EIP1186ProofResponse>,
}

#[derive(Deserialize, Serialize)]
pub struct BasicBlockState {
    pub state_root: H256,
    pub transactions: Vec<H256>,
}

/// Prestate tracer for all transactions in a block, as returned by
/// a node.
#[derive(Deserialize, Serialize)]
pub struct BlockPrestateTrace {
    pub block_number: u64,
    pub prestate_traces: Vec<TransactionAccountStates>,
}

pub struct InputData {
    pub transactions: Vec<String>,
    /// State associated with an each account.
    ///
    /// If state is written two after first being accessed, that action
    /// is ignored. It only records "pristine/unaltered" state as of earliest
    /// access in that block.
    pub first_state: HashMap<String, AccountState>,
}

/// Records the account states for a single transaction. A transaction
/// may involve multiple accounts, each with it's own state.
///
/// The mapping is of account -> account_state.
pub type TransactionAccountStates = HashMap<String, AccountState>;

/// Records the state for a particular account.
///
/// A prestate tracer
/// only includes state that was accessed, hence the optional fields.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AccountState {
    // Every account will have a balance.
    pub balance: String,
    pub code: Option<String>,
    pub nonce: Option<u64>,
    pub storage: Option<StorageSlot>,
}

pub type StorageSlot = HashMap<String, String>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockStateAccesses {
    /// Mapping of accounts to accessed states. An account may have slots accessed in different
    /// transactions, they are aggregated here.
    pub(crate) access_data: HashMap<String, AccountState>,
}

impl Display for BlockStateAccesses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Block state proof with {} accounts accessed)",
            self.access_data.keys().count()
        )
    }
}

impl BlockStateAccesses {
    /// Adds new state to the state access record if the state has not previously
    /// been added by a prior transaction.
    ///
    /// When an account has been accessed, any unseen aspects of that account
    /// are included (e.g., if balance was first accessed, then code later, the code
    /// is added to the record).
    pub fn include_new_state_accesses_for_tx(
        &mut self,
        tx_prestate_trace: &TransactionAccountStates,
    ) -> &mut Self {
        for (account, accessed_state) in tx_prestate_trace {
            // Check for an entry for the account
            match self.access_data.get_key_value(account) {
                Some((_, existing)) => {
                    let updated = include_unseen_states(existing, accessed_state);
                    self.access_data
                        .insert(account.to_string(), updated.to_owned());
                }
                None => {
                    // Add whole state data if no entry for the account.
                    self.access_data
                        .insert(account.to_string(), accessed_state.to_owned());
                }
            }
        }
        self
    }
    /// Returns a vector of accounts with storage slots that can be used to query
    /// eth_getProof for a specific block.
    ///
    /// The storage slots have been aggregated and may have been accessed in different transactions
    /// within a block.
    pub fn get_all_accounts_to_prove(&self) -> Vec<AccountToProve> {
        let mut accounts: Vec<AccountToProve> = vec![];
        for account in &self.access_data {
            if let Some(storage) = &account.1.storage {
                let address = account.0.to_owned();
                let mut slots: Vec<String> = vec![];
                for slot in storage.keys() {
                    slots.push(slot.to_owned())
                }
                accounts.push(AccountToProve { address, slots });
            }
        }
        accounts
    }
    pub fn new() -> Self {
        BlockStateAccesses {
            access_data: HashMap::new(),
        }
    }
}

impl BlockProofs {
    /// Verifies the proofs present for the block with respect to a state root.
    pub fn verify(&self, state_root: &[u8]) -> Result<(), VerifyProofError> {
        for (account, proof) in &self.proofs {
            println!("proof for account {account} ok");
            verify_proof(&state_root, proof)?
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountToProve {
    pub address: String,
    pub slots: Vec<String>,
}

impl Default for BlockStateAccesses {
    fn default() -> Self {
        Self::new()
    }
}

/// For an initial set of state values for one account, looks for state accesses to
/// previously untouched state.
///
/// Adds the new state into the old one.
fn include_unseen_states(existing: &AccountState, accessed_state: &AccountState) -> AccountState {
    let mut updated = existing.clone();
    // Work out if any parts are new.
    if existing.code.is_none() {
        updated.code = accessed_state.code.clone();
    }
    if existing.nonce.is_none() {
        updated.nonce = accessed_state.nonce;
    }
    let updated_storage = match existing.storage.clone() {
        None => accessed_state.storage.clone(),
        Some(mut existing_storage) => {
            // Look up each new storage key.
            if let Some(new_storage) = &accessed_state.storage {
                for (k, v) in new_storage {
                    if !existing_storage.contains_key(k) {
                        existing_storage.insert(k.clone(), v.clone());
                    }
                }
            }
            Some(existing_storage)
        }
    };
    updated.storage = updated_storage;
    updated
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_state_1() -> AccountState {
        let mut slots = HashMap::new();
        slots.insert("555".to_string(), "333".to_string());
        AccountState {
            balance: "123".to_string(),
            code: Some("608040".to_string()),
            nonce: Some(2),
            storage: Some(slots),
        }
    }
    fn dummy_state_2() -> AccountState {
        AccountState {
            balance: "123".to_string(),
            code: None,
            nonce: None,
            storage: None,
        }
    }

    /// Tests that changes to previously accessed state are ignored.
    #[test]
    fn test_modified_states_ignored() {
        let initial = dummy_state_1();
        let mut slots = HashMap::new();
        // New storage key.
        slots.insert("777".to_string(), "333".to_string());
        // Previously seen storage key.
        slots.insert("555".to_string(), "444".to_string());
        let accessed = AccountState {
            balance: "456".to_string(),
            code: Some("11111".to_string()),
            nonce: Some(200),
            storage: Some(slots),
        };
        let result = include_unseen_states(&initial, &accessed);
        assert_ne!(initial, result);
        assert_eq!(result.balance, "123");
        assert_eq!(result.code, Some("608040".to_string()));
        assert_eq!(result.nonce, Some(2));
        assert_eq!(result.storage.unwrap().len(), 2);
    }
    #[test]
    fn test_seen_states_ignored() {
        let a = dummy_state_1();
        let b = a.clone();
        let result = include_unseen_states(&a, &b);
        assert_eq!(a, result);
    }
    #[test]
    fn test_seen_states_ignored_2() {
        let a = dummy_state_2();
        let b = a.clone();
        let result = include_unseen_states(&a, &b);
        assert_eq!(a, result);
    }
    /// Tests that if a state has not been seen yet that it is included.
    #[test]
    fn test_new_states_included() {
        let initial = dummy_state_2();
        let mut slots = HashMap::new();
        slots.insert("111".to_string(), "999".to_string());
        let accessed = AccountState {
            balance: "123".to_string(),
            code: Some("608040".to_string()),
            nonce: Some(2),
            storage: Some(slots),
        };
        let result = include_unseen_states(&initial, &accessed);
        assert_ne!(initial, result);
        assert_eq!(result.balance, "123");
        assert_eq!(result.code, Some("608040".to_string()));
        assert_eq!(result.nonce, Some(2));
        assert_eq!(result.storage.unwrap().len(), 1);
    }
}
