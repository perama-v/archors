//! Verifies an EIP-1186 style proof

use ethers::{
    types::{Bytes, EIP1186ProofResponse, H256, U256, U64},
    utils::keccak256,
};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::Deserialize;
use thiserror::Error;

use crate::{
    proof::{ProofError, Verifier},
    rlp::{rlp_decode_final_account_element, RlpError},
};

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
pub struct Account {
    pub nonce: U64,
    pub balance: U256,
    pub storage_hash: H256,
    pub code_hash: H256,
}

#[derive(Debug, Error)]
pub enum VerifyProofError {
    #[error("Proof not valid for account {account}, AccountError {source} ")]
    AccountError {
        source: AccountError,
        account: String,
    },
    #[error(
        "Proof not valid for account {account} storage key {storage_key}, StorageError {source}"
    )]
    StorageError {
        source: StorageError,
        account: String,
        storage_key: String,
    },
    #[error("Proof is empty")]
    EmptyProof,
}

#[derive(Debug, Error)]
pub enum AccountError {
    #[error("ProofError {0}")]
    ProofError(#[from] ProofError),
    #[error("Account in the proof did not match expected value")]
    IncorrectAccount,
    #[error("Proof is empty")]
    EmptyProof,
    #[error("RlPError {0}")]
    RlpError(#[from] RlpError),
}

#[derive(Debug, Error)]
pub enum StorageError {}

/// Verifies a single account proof with respect to a state roof. The
/// proof is of the form returned by eth_getProof.
pub fn verify_proof(
    block_state_root: &[u8],
    proof: EIP1186ProofResponse,
) -> Result<(), VerifyProofError> {
    let account =
    // Account
    verify_account_component(block_state_root, &proof)
        .map_err(|source| VerifyProofError::AccountError { source, account: hex::encode(proof.address) })?;

    // Storage proofs for this account
    for storage_proof in &proof.storage_proof {
        verify_account_storage_component(&proof.storage_hash.0, &storage_proof.proof).map_err(
            |source| VerifyProofError::StorageError {
                source,
                account: hex::encode(proof.address),
                storage_key: hex::encode(storage_proof.key),
            },
        )?;
    }
    Ok(())
}

pub fn verify_account_component(
    block_state_root: &[u8],
    proof: &EIP1186ProofResponse,
) -> Result<(), AccountError> {
    // Account proof
    let account_proof_final_level: &Bytes =
        proof.account_proof.last().ok_or(AccountError::EmptyProof)?;
    // Check account values correct.
    let derived_account: Account = rlp_decode_final_account_element(&account_proof_final_level.0)?;

    let claimed_account = Account {
        nonce: proof.nonce,
        balance: proof.balance,
        storage_hash: proof.storage_hash,
        code_hash: proof.code_hash,
    };
    if !derived_account.eq(&claimed_account) {
        // redundant, remove once checked in proof_single_path_check.
        return Err(AccountError::IncorrectAccount);
    }

    let root_hash = H256::from_slice(block_state_root);
    // Check account proof structure.
    let account_proof = Verifier::new_single_proof(
        proof.account_proof.clone(),
        root_hash.0,
        keccak256(proof.address.as_bytes()),
        rlp::encode(&claimed_account).into(),
    );
    account_proof.verify()?;

    // Storage proofs for this account
    for received_storage_proof in &proof.storage_proof {
        todo!()
    }
    Ok(())
}

fn verify_account_storage_component(
    block_state_root: &[u8],
    proof: &[Bytes],
) -> Result<(), StorageError> {
    todo!();
}

mod test {
    use super::*;
    use std::{fs::File, io::BufReader};

    fn load_proof(path: &str) -> EIP1186ProofResponse {
        let file = File::open(path).expect("no proof found");
        let reader = BufReader::new(&file);
        serde_json::from_reader(reader).expect("could not parse proof")
    }

    /// data src:
    /// https://github.com/ethereum/execution-apis/blob/main/tests/eth_getProof/get-account-proof-with-storage.io
    /// ```json
    /// {"jsonrpc":"2.0","id":1,"method":"eth_getProof","params":["0xaa00000000000000000000000000000000000000",["0x01"],"0x3"]}
    /// ```
    #[test]
    fn test_verify_inclusion_proof_of_zero_storage() {
        let account_proof = load_proof("data/test_proof_1.json");
        let state_root =
            hex::decode("61effbbcca94f0d3e02e5bd22e986ad57142acabf0cb3d129a6ad8d0f8752e94")
                .unwrap();
        verify_proof(&state_root, account_proof).expect("could not verify proof");
    }

    /// data src: https://github.com/gakonst/ethers-rs/blob/master/ethers-core/testdata/proof.json
    #[test]
    fn test_verify_exclusion_proof_for_zero_key() {
        let account_proof = load_proof("data/test_proof_2.json");
        let state_root =
            hex::decode("57e6e864257daf9d96aaca31edd0cfe4e3892f09061e727c57ab56197dd59287")
                .unwrap();
        verify_proof(&state_root, account_proof).expect("could not verify proof");
    }
}
