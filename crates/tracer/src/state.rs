//! For representing state for an historical block.

use std::collections::HashMap;

use archors_types::{alias::SszH160, state::RequiredBlockState};
use ethers::types::{EIP1186ProofResponse, H160, H256, U64};
use revm::{
    db::{CacheDB, EmptyDB},
    primitives::{
        keccak256, Account, AccountInfo, Bytecode, BytecodeState, Bytes, HashMap as rHashMap, B160,
        B256, U256,
    },
};

use thiserror::Error;

use crate::utils::{
    eh256_to_ru256, eu256_to_ru256, eu64_to_ru256, hex_encode, ssz_h256_to_rb256,
    ssz_h256_to_ru256, ssz_u256_to_ru256, ssz_u64_to_u64, UtilsError,
};

/// An error with tracing a block
#[derive(Debug, Error, PartialEq)]
pub enum StateError {
    #[error("Unable to get account state proof for address")]
    NoProofForAddress(String),
    #[error("UtilsError {0}")]
    UtilsError(#[from] UtilsError),
    #[error("Could not initialise storage for account {address}, error {error}")]
    AccountStorageInit { error: String, address: String },
}

/// A basic map of accounts to proofs. Includes all state required to trace a block.
///
/// 'Basic' referring to the presence of duplicated trie nodes throughout the data.
///
/// ### Code
/// The account proofs refer to code by keccack(code), this map provides the code
/// that was obtained with the prestate tracer.
///
/// ### Blockhash
/// The EVM opcode BLOCKHASH accesses old block hashes. These are detected and
/// cached using eth_traceBlock and then included here.
pub struct BlockProofsBasic {
    /// Map of account -> proof
    pub proofs: HashMap<H160, EIP1186ProofResponse>,
    /// Map of codehash -> code
    pub code: HashMap<H256, Vec<u8>>,
    /// Map of block number -> block hash
    pub block_hashes: HashMap<U64, H256>,
}

/// Behaviour that any proof-based format must provide to be convertible into
/// a revm DB. In other words, behaviour that makes the state data extractable for re-execution.
///
/// Returned types are revm-based.
pub trait StateForEvm {
    /// Gets account information in a format that can be inserted into a
    /// revm db. This includes contract bytecode.
    fn get_account_info(&self, address: &B160) -> Result<AccountInfo, StateError>;
    /// Gets all the addresses.
    fn addresses(&self) -> Vec<B160>;
    /// Gets the storage key-val pairs for the account of the address.
    fn get_account_storage(&self, address: &B160) -> Result<rHashMap<U256, U256>, StateError>;
    /// Gets BLOCKAHSH opcode accesses required for the block.
    /// Pairs are (block_number, block_hash).
    fn get_blockhash_accesses(&self) -> Result<rHashMap<U256, B256>, StateError>;
    /// Updates an account.
    ///
    /// Note that some account updates may require additional information. Key deletion may
    /// remove nodes and restructure the trie. In this case, some additional nodes must be
    /// provided.
    ///
    fn update_account(&mut self, address: &B160, account: Account) -> Result<(), StateError>;
    /// Computes the merkle root of the state trie.
    fn state_root_pre_block(&self) -> Result<H256, StateError>;
    /// Apply changes received from the EVM for the entire block, return the root.
    ///
    /// This consumes the state object to avoid reuse of the state data, which is only
    /// to be used for a single block.
    fn state_root_post_block(self, changes: HashMap<B160, Account> ) -> Result<H256, StateError>;
}

impl StateForEvm for BlockProofsBasic {
    fn get_account_info(&self, address: &B160) -> Result<AccountInfo, StateError> {
        let account = self
            .proofs
            .get(&address.0.into())
            .ok_or_else(|| StateError::NoProofForAddress(hex_encode(address)))?;

        let code: Option<Bytecode> = self.code.get(&account.code_hash).map(|data| {
            let revm_bytes = Bytes::copy_from_slice(data);
            Bytecode::new_raw(revm_bytes)
        });
        let info = AccountInfo {
            balance: account.balance.into(),
            nonce: account.nonce.as_u64(),
            code_hash: account.code_hash.0.into(),
            code,
        };
        Ok(info)
    }
    fn get_account_storage(&self, address: &B160) -> Result<rHashMap<U256, U256>, StateError> {
        let account = self
            .proofs
            .get(&address.0.into())
            .ok_or_else(|| StateError::NoProofForAddress(hex_encode(address)))?;

        // Storage key-val pairs for the account.
        let mut storage: rHashMap<U256, U256> = rHashMap::new();

        for storage_data in &account.storage_proof {
            // U256 ethers -> U256 revm
            let key = eh256_to_ru256(storage_data.key);
            let value = eu256_to_ru256(storage_data.value)?;

            storage.insert(key, value);
        }

        Ok(storage)
    }
    fn addresses(&self) -> Vec<B160> {
        self.proofs
            .keys()
            .map(|address| B160::from(address.0))
            .collect()
    }

    fn update_account(&mut self, _address: &B160, _account: Account) -> Result<(), StateError> {
        todo!()
    }

    fn get_blockhash_accesses(&self) -> Result<rHashMap<U256, B256>, StateError> {
        let mut accesses = rHashMap::new();
        for access in self.block_hashes.iter() {
            let num: U256 = eu64_to_ru256(*access.0);
            let hash: B256 = access.1 .0.into();
            accesses.insert(num, hash);
        }
        Ok(accesses)
    }

    fn state_root_pre_block(&self) -> Result<H256, StateError> {
        todo!()
    }

    fn state_root_post_block(self, changes: HashMap<B160, Account> ) -> Result<H256, StateError> {
        todo!()
    }
}


/// Inserts state from a collection of EIP-1186 proof into an in-memory DB.
/// The DB can then be used by the EVM to read/write state during execution.
pub fn build_state_from_proofs<T>(block_proofs: &T) -> Result<CacheDB<EmptyDB>, StateError>
where
    T: StateForEvm,
{
    let mut db = CacheDB::new(EmptyDB::default());

    for address in block_proofs.addresses() {
        let info = block_proofs.get_account_info(&address)?;
        db.insert_account_info(address, info);

        let storage = block_proofs.get_account_storage(&address)?;
        db.replace_account_storage(address, storage)
            .map_err(|source| StateError::AccountStorageInit {
                error: source.to_string(),
                address: hex_encode(address),
            })?;
    }
    Ok(db)
}

impl StateForEvm for RequiredBlockState {
    fn get_account_info(&self, address: &B160) -> Result<AccountInfo, StateError> {
        let target = SszH160::try_from(address.0.to_vec()).unwrap();
        for account in self.compact_eip1186_proofs.iter() {
            if account.address == target {
                let code_hash = ssz_h256_to_rb256(&account.code_hash);

                let code = self
                    .contracts
                    .iter()
                    .find(|contract| keccak256(contract).eq(&code_hash))
                    .map(|ssz_bytes| {
                        let bytes = ssz_bytes.to_vec();
                        let len = bytes.len();
                        Bytecode {
                            bytecode: Bytes::from(bytes),
                            hash: code_hash,
                            state: BytecodeState::Checked { len },
                        }
                    });

                let account = AccountInfo {
                    balance: ssz_u256_to_ru256(account.balance.to_owned())?,
                    nonce: ssz_u64_to_u64(account.nonce.to_owned())?,
                    code_hash,
                    code,
                };
                return Ok(account);
            }
        }
        Err(StateError::NoProofForAddress(address.to_string()))
    }

    fn addresses(&self) -> Vec<B160> {
        self.compact_eip1186_proofs
            .iter()
            .map(|proof| B160::from_slice(&proof.address))
            .collect()
    }

    fn get_account_storage(&self, address: &B160) -> Result<rHashMap<U256, U256>, StateError> {
        let target = SszH160::try_from(address.0.to_vec()).unwrap();
        let mut storage_map = rHashMap::default();
        for account in self.compact_eip1186_proofs.iter() {
            if account.address == target {
                for storage in account.storage_proofs.iter() {
                    let key: U256 = ssz_h256_to_ru256(storage.key.to_owned())?;
                    let value: U256 = ssz_u256_to_ru256(storage.value.to_owned())?;
                    storage_map.insert(key, value);
                }
            }
        }
        Ok(storage_map)
    }

    fn update_account(&mut self, _address: &B160, _account: Account) -> Result<(), StateError> {
        todo!()
    }

    fn get_blockhash_accesses(&self) -> Result<rHashMap<U256, B256>, StateError> {
        let mut accesses = rHashMap::default();
        for access in self.blockhashes.iter() {
            let num = U256::from(ssz_u64_to_u64(access.block_number.to_owned())?);
            let hash: B256 = ssz_h256_to_rb256(&access.block_hash);
            accesses.insert(num, hash);
        }
        Ok(accesses)
    }

    fn state_root_pre_block(&self) -> Result<H256, StateError> {
        todo!()
    }

    fn state_root_post_block(self, _changes: HashMap<B160, Account> ) -> Result<H256, StateError> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use revm::primitives::B256;

    use super::*;

    #[test]
    fn test_block_proofs_basic_get_account_info() {
        let mut state = BlockProofsBasic {
            proofs: HashMap::default(),
            code: HashMap::default(),
            block_hashes: HashMap::default(),
        };
        let mut proof = EIP1186ProofResponse::default();
        let address = H160::from_str("0x0300000000000000000000000000000000000000").unwrap();
        proof.address = address;
        let balance = "0x0000000000000000000000000000000000000000000000000000000000000009";
        let nonce = 7u64;
        proof.balance = ethers::types::U256::from_str(balance).unwrap();
        proof.nonce = nonce.into();
        state.proofs.insert(address, proof);

        let retreived_account = state.get_account_info(&address.0.into()).unwrap();
        let expected_account = AccountInfo {
            balance: U256::from_str(balance).unwrap(),
            nonce,
            code_hash: B256::zero(),
            code: None,
        };
        assert_eq!(retreived_account, expected_account);
    }
}
