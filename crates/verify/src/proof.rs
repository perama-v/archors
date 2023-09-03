//! For verifying a Merkle Patricia Proof for arbitrary proof values.
//! E.g., Account, storage ...
use ethers::{types::Bytes, utils::keccak256};
use hex::FromHexError;
use rlp;
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::Deserialize;
use thiserror::Error;

use crate::{
    eip1186::Account,
    node::{NodeError, NodeKind},
    path::{NibblePath, PathError},
    utils::{hex_encode, UtilsError},
};

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("Branch does not have enough items")]
    BranchItemMissing,
    #[error("Branch node (non-terminal) has value, expected none")]
    BranchNodeHasValue,
    #[error("Parent nodes (rlp: {parent}) do not contain hash of rlp(child) (hash: {child}")]
    ChildNotFound { parent: String, child: String },
    #[error("RLP decode error {0}")]
    DecodeError(#[from] rlp::DecoderError),
    #[error("Proof is empty")]
    EmptyProof,
    #[error("The final node in the proof should have been detected and assessed")]
    FailedToHandleFinalNode,
    #[error("RLP decode error {0}")]
    FromHexError(#[from] FromHexError),
    #[error(
        "Hash of node {computed} does not match the expected hash in the parent node {expected}"
    )]
    IncorrectHash { computed: String, expected: String },
    #[error(
        "The claimed proof value ({claimed}) is different from the value in the proof ({expected})"
    )]
    IncorrectLeafValue { claimed: String, expected: String },
    #[error("Merkle Patricia Node to have max 17 (16 + 1) items, got {0}")]
    InvalidNodeItemCount(usize),
    #[error("Node (index = {node_index} error {source}")]
    NodeError {
        source: NodeError,
        node_index: usize,
    },
    #[error("Account proof node has no value. RLP: {0}")]
    NoNodeAccountValue(String),
    #[error("Storage proof node has no value. RLP: {0}")]
    NoNodeStorageValue(String),
    #[error("Path error {source} for node (index = {node_index} ")]
    PathError {
        source: PathError,
        node_index: usize,
    },
    #[error("UtilsError {0}")]
    UtilsError(#[from] UtilsError),
    #[error("VerificationError {0}")]
    VerificationError(String),
}

/// A proof for some data in a Merkle Patricia Tree, such as an account, or a storage value.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SingleProofPath {
    /// Merkle PATRICIA trie proof for a key/value.
    pub proof: Vec<Bytes>,
    /// Trusted root that the proof anchors to.
    pub root: [u8; 32],
    /// Anticipated trie path to traverse for the proof.
    pub path: [u8; 32],
    /// Claimed value to be proven. E.g., RLP(account), or RLP(storage_value)
    pub claimed_value: Vec<u8>,
}

impl SingleProofPath {
    pub fn verify(&self) -> Result<Verified, ProofError> {
        if self.proof.is_empty() {
            return Err(ProofError::EmptyProof);
        }
        let mut traversal = NibblePath::init(&self.path);
        let mut parent_hash = self.root;

        for (node_index, rlp_node) in self.proof.iter().enumerate() {
            node_hash_correct(&rlp_node.0, parent_hash)?;

            let node: Vec<Vec<u8>> = rlp::decode_list(&rlp_node.0);

            let proof_type = NodeKind::deduce(&node)
                .map_err(|source| ProofError::NodeError { source, node_index })?
                .traverse_node(node, &mut traversal, &mut parent_hash)
                .map_err(|source| ProofError::NodeError { source, node_index })?;

            let verification = proof_type.get_verification_of_value(&self.claimed_value)?;

            if let Some(verified) = verification {
                return Ok(verified);
            }
        }
        // If end up with a value ensure it equals self.value
        Err(ProofError::FailedToHandleFinalNode)
    }
}

/// The verification kind is returned to the caller.
///
/// An exclusion proof for a key does not contain information about the value
/// of that key. The caller can make an assessment if the value for an
/// exclusion proof is valid, depending on the context (storage or account).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    Inclusion,
    Exclusion,
}

/// Checks that the hash of one node is correct.
fn node_hash_correct(rlp_node: &[u8], parent_hash: [u8; 32]) -> Result<(), ProofError> {
    let computed_hash = keccak256(rlp_node);
    if !computed_hash.eq(&parent_hash) {
        let computed = hex_encode(computed_hash);
        let expected = hex_encode(parent_hash);
        return Err(ProofError::IncorrectHash { computed, expected });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofType {
    /// Inclusion proof with leaf RLP bytes from the proof.
    Inclusion(Vec<u8>),
    /// Exclusion proof consisting of a terminal branch node.
    BranchExclusion,
    /// Exclusion proof consisting of a terminal extension node.
    ExtensionExclusion,
    /// Exclusion proof consisting of a terminal leaf node.
    LeafExclusion,
    /// Not yet finished processing the proof.
    Pending,
}

impl ProofType {
    /// For proofs that have been checked to the terminal node, checks that the proof
    /// supports the claimed value.
    ///
    /// ## Inclusion proof
    /// The claimed value must match the proof leaf value.
    /// The value could be anything, including the zero value. For example:
    /// - Storage proof: rlp(0x1), rlp(0xabcd...1234), rlp(0x0)
    /// - Account proof: rlp(arbitrary_EOA), rlp(arbitrary_contract), rlp(account_selfdestructed), rlp(account_uninitialized_but_nonzero_balance) etc.
    ///
    /// ## Exclusion proof
    /// An exclusion proof is a claim that the key does not exist in the trie.
    /// The claimed value therefore must be the 'untouched value'. For example:
    /// - Storage proof: rlp(0x0)
    /// - Account proof: rlp(untouched_account_with_default_values)
    ///
    /// The value for this non-existent key is not in the proof, and so the claimed
    /// value must be evaluated by the caller.
    fn get_verification_of_value(
        &self,
        claimed_rlp_value: &[u8],
    ) -> Result<Option<Verified>, ProofError> {
        match self {
            ProofType::Inclusion(proof_leaf_rlp_bytes) => {
                match claimed_rlp_value == proof_leaf_rlp_bytes {
                    true => Ok(Some(Verified::Inclusion)),
                    false => Err(ProofError::IncorrectLeafValue {
                        claimed: hex_encode(claimed_rlp_value),
                        expected: hex_encode(proof_leaf_rlp_bytes),
                    }),
                }
            }
            ProofType::BranchExclusion
            | ProofType::ExtensionExclusion
            | ProofType::LeafExclusion => Ok(Some(Verified::Exclusion)),
            ProofType::Pending => Ok(None),
        }
    }
}

/// A merkle patricia trie node at any level/height of an account proof.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
struct Node {
    items: Vec<Item>,
}

/// A merkle patricia trie node at any level/height of an account proof.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
struct NodeAccount {
    items: Vec<String>,
    value: Account,
}

/// A merkle patricia trie node at any level/height of an account proof.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
struct NodeStorage {
    items: Vec<Item>,
    data: Vec<u8>,
    value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
struct RlpItem(String);

impl From<[u8; 32]> for RlpItem {
    fn from(value: [u8; 32]) -> Self {
        let item = format!("0x{}", hex::encode(value));
        Self(item)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
struct Item(Vec<u8>);

impl From<[u8; 32]> for Item {
    fn from(value: [u8; 32]) -> Self {
        Self(value.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::BufReader};

    use ethers::types::{EIP1186ProofResponse, H256};

    use super::*;

    // A 2-item merkle patricia trie node. RLP structure: list[integer, list[account]]
    const ACCOUNT_LEAF: &str = "f8669d33269ec9b8f075a4723d27c611ac1c52a464f3516b25e0105a0d1c2210b846f8440180a03836d7e3afb674e5180b7564e096f6f3e30308878a443fe59012ced093544b7fa02cfdfbdd943ec0153ed07b97f03eb765dc11cc79c6f750effcc2d126f93c4b31";

    fn load_proof() -> EIP1186ProofResponse {
        // data src: https://github.com/gakonst/ethers-rs/blob/master/ethers-core/testdata/proof.json
        let file = File::open("data/test_proof_2.json").expect("no proof found");
        let reader = BufReader::new(&file);
        serde_json::from_reader(reader).expect("could not parse proof")
    }

    /// Checks that the merkle proof consists of hashes linking every level to the one above.
    ///
    /// A proof consists of a list of RLP-encoded data: (A, B, ... C)
    /// - A (Top of trie / near root). `hash(A) == trie_root`
    /// - B (Lower in trie), `hash(B)` will be present in A.
    /// - ...
    /// - C (Bottom of trie / near branches), `hash(C)` will be present in B
    ///     - `hash(storage_value)` will be present in C.
    fn verify_parents_contain_children(nodes: &[Bytes]) -> Result<(), ProofError> {
        let lowest = nodes.last().ok_or(ProofError::EmptyProof)?;
        let mut hash_to_check: [u8; 32] = keccak256(&lowest.0);
        // Walk from leaves to root.
        for node_bytes in nodes.iter().rev().skip(1) {
            let node: Vec<Vec<u8>> = rlp::decode_list(&node_bytes.0);
            if node.len() > 17 {
                return Err(ProofError::InvalidNodeItemCount(node.len()));
            }
            if !node.contains(&hash_to_check.into()) {
                return {
                    let child = hex::encode(hash_to_check);
                    let parent = hex::encode(&node_bytes.0);
                    Err(ProofError::ChildNotFound { child, parent })
                };
            }
            // Remember the hash of the current node RLP for the next level up.
            hash_to_check = keccak256(&node_bytes.0)
        }
        Ok(())
    }

    #[test]
    fn test_storage_proof_parents_contain_children() {
        let proof = load_proof();
        let storage_proof = proof.storage_proof.first().unwrap();
        verify_parents_contain_children(&storage_proof.proof).unwrap();
    }

    #[test]
    fn test_account_proof_parents_contain_children() {
        let proof = load_proof();
        let account_proof = proof.account_proof;
        verify_parents_contain_children(&account_proof).unwrap();
    }

    #[test]
    fn test_node_hash() {
        // RLP-encoded account leaf
        let node_rlp = hex::decode(ACCOUNT_LEAF).unwrap();
        let hash = hex::decode("de4a8735f0afe745a73341f09b2641b136c4c6ceb33a4c04f868b8c0ae0c572d")
            .unwrap();
        let expected_hash = H256::from_slice(&hash).0;
        node_hash_correct(&node_rlp, expected_hash).unwrap();
    }

    #[test]
    fn keccak() {
        let hex_input = "";
        let bytes = hex::decode(hex_input).unwrap();
        let hash = hex::encode(keccak256(bytes));
        assert_eq!(
            hash,
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );

        let hex_input = "00";
        let bytes = hex::decode(hex_input).unwrap();
        let hash = hex::encode(keccak256(bytes));
        assert_eq!(
            hash,
            "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a"
        );

        let hex_input = "01";
        let bytes = hex::decode(hex_input).unwrap();
        let hash = hex::encode(keccak256(bytes));
        assert_eq!(
            hash,
            "5fe7f977e71dba2ea1a68e21057beebb9be2ac30c6410aa38d4f3fbe41dcffd2"
        );
    }
}
