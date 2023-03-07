use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use web3::types::H256;

#[derive(Deserialize, Serialize)]
pub struct BasicBlockState {
    pub state_root: H256,
    pub transactions: Vec<H256>,
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

pub type AccountStates = HashMap<String, AccountState>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountState {
    // Every account will have a balance.
    pub balance: String,
    pub code: Option<String>,
    pub nonce: Option<u64>,
    pub storage: Option<StorageSlot>,
}

pub type StorageSlot = HashMap<String, String>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockStateProof {
    data: HashMap<String, AccountState>,
}

impl BlockStateProof {
    /// Adds new state to the proof if the state has not previously been added.
    pub fn insert_tx(&mut self, _tx: &H256, tx_prestate_trace: &AccountStates) -> &mut Self {
        for (account, accessed_state) in tx_prestate_trace {
            // Check for an entry for the account
            match self.data.get_key_value(account) {
                Some((_, existing)) => {
                    let updated = include_unseen_states(existing, accessed_state);
                    self.data.insert(account.to_string(), updated.to_owned());
                }
                None => {
                    // Add whole state data if no entry for the account.
                    self.data
                        .insert(account.to_string(), accessed_state.to_owned());
                }
            }
        }
        self
    }
    pub fn new() -> Self {
        BlockStateProof {
            data: HashMap::new(),
        }
    }
}

impl Default for BlockStateProof {
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
