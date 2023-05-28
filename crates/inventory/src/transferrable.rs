//! For representing critical state data while minimising duplication (intra-block and inter-block). State data is to be transmitted between untrusted parties.
//!
//! ## Encoding
//!
//! The data is SSZ encoded for consistency between implementations.
//!
//! ## Contents
//!
//! Large data items (contract code and merkle trie nodes) may be repeated within a block or
//! between blocks.
//! - Contract is called in different transactions/blocks without changes to its bytecode.
//! - Merkle trie nodes where state is accessed in the leafy-end of the proof. Such as very
//! populated accounts and storage items.
//!
//! Such an item can be referred to by the position in a separate list.

use ssz_rs::prelude::*;
use thiserror::Error;

use crate::ssz::{
    constants::{
        MAX_ACCOUNT_NODES_PER_BLOCK, MAX_ACCOUNT_PROOFS_PER_BLOCK, MAX_BYTES_PER_CONTRACT,
        MAX_BYTES_PER_NODE, MAX_CONTRACTS_PER_BLOCK, MAX_NODES_PER_PROOF,
        MAX_STORAGE_NODES_PER_BLOCK, MAX_STORAGE_PROOFS_PER_ACCOUNT,
    },
    types::{SszH160, SszH256, SszU256, SszU64},
};

#[derive(Debug, Error)]
pub enum TransferrableError {
    #[error("TODO")]
    Todo,
}

/// State that has items referred to by their hash. This store represents the minimum
/// set of information that a peer should send to enable a block holder (eth_getBlockByNumber)
/// to trace the block.
///
/// Consists of:
/// - A collection of EIP-1186 style proofs with intermediate nodes referred to in a separate list.
/// EIP-1186 proofs consist of:
///     - address, balance, codehash, nonce, storagehash, accountproofnodehashes, storageproofs
///         - storageproofs: key, value, storageproofnodehashes
/// - contract code referred to by codehash.
/// - account trie node referred to by nodehash
/// - storage trie node referred to by nodehash
#[derive(PartialEq, Eq, Debug, Default, SimpleSerialize)]
pub struct SlimBlockStateProof {
    slim_eip1186_proof: List<SlimEip1186Proof, MAX_ACCOUNT_PROOFS_PER_BLOCK>,
    contracts: List<Contract, MAX_CONTRACTS_PER_BLOCK>,
    account_nodes: List<TrieNode, MAX_ACCOUNT_NODES_PER_BLOCK>,
    storage_nodes: List<TrieNode, MAX_STORAGE_NODES_PER_BLOCK>,
}

impl SlimBlockStateProof {
    fn create() -> Result<Self, TransferrableError> {
        

        Ok(SlimBlockStateProof {
            slim_eip1186_proof: todo!(),
            contracts: todo!(),
            account_nodes: todo!(),
            storage_nodes: todo!(),
        })
    }
}

/// RLP-encoded Merkle PATRICIA Trie node.
#[derive(PartialEq, Eq, Debug, Default, SimpleSerialize)]
pub struct TrieNode {
    node: List<u8, MAX_BYTES_PER_NODE>,
}

/// Contract bytecode.
#[derive(PartialEq, Eq, Debug, Default, SimpleSerialize)]
pub struct Contract {
    node: List<u8, MAX_BYTES_PER_CONTRACT>,
}

/// An EIP-1186 style proof with the trie nodes replaced by their keccak hashes.
#[derive(PartialEq, Eq, Debug, Default, SimpleSerialize)]
pub struct SlimEip1186Proof {
    pub address: SszH160,
    pub balance: SszU256,
    pub code_hash: SszH256,
    pub nonce: SszU64,
    pub storage_hash: SszH256,
    pub account_proof: NodeIndices,
    pub storage_proof: List<SlimStorageProof, MAX_STORAGE_PROOFS_PER_ACCOUNT>,
}

/// An EIP-1186 style proof with the trie nodes replaced by their keccak hashes.
#[derive(PartialEq, Eq, Debug, Default, SimpleSerialize)]
pub struct SlimStorageProof {
    pub key: SszH160,
    pub value: SszU256,
    pub proof: NodeIndices,
}

/// An ordered list of indices that point to specific
/// trie nodes in a different ordered list.
///
/// The purpose is deduplication as some nodes appear in different proofs within
/// the same block.
pub type NodeIndices = List<u16, MAX_NODES_PER_PROOF>;
