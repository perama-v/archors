//! For verifying a Merkle Patricia Multi Proof for arbitrary proof values.
//! E.g., Account, storage ...

use std::collections::HashMap;

use ethers::{types::{Bytes, H256}, utils::keccak256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::utils::hex_encode;


#[derive(Debug, Error)]
pub enum ProofError {
    #[error("Single proof root hash {computed} doesn't match multiproof root {expected}")]
    ProofRootMismatch{expected: String, computed: String},
}


/// A representation of a Merkle PATRICIA Trie Multi Proof.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MultiProof {
    /// node_hash -> node_rlp
    data: HashMap<H256, Bytes>,
    /// Root hash of the proof. Used as the entry point to follow a path in the trie.
    /// Updated when data is modified.
    root: H256
}

impl MultiProof {
    /// Create new multiproof with a known root.
    pub fn init(root: H256) -> Self {
        MultiProof { data: HashMap::default(), root }
    }
    /// Add a new single proof to the multiproof.
    pub fn insert(&mut self, proof: Vec<Bytes>) -> Result<(), ProofError> {
        for (index, node) in proof.into_iter().enumerate() {
            let hash: H256 = keccak256(&node).into();
            if index == 0 && hash != self.root{
                return Err(ProofError::ProofRootMismatch{expected: hex_encode(self.root), computed: hex_encode(hash)})
            }
            else {
                self.data.insert(hash, node);
            }
        }
        Ok(())

    }
}