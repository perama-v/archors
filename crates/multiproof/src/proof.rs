//! For verifying a Merkle Patricia Multi Proof for arbitrary proof values.
//! E.g., Account, storage ...

use std::collections::HashMap;

use archors_verify::path::{
    NibblePath, PathError,
    PathNature::{FullPathDiverges, FullPathMatches, SubPathDiverges, SubPathMatches},
    PrefixEncoding,
};
use ethers::{
    types::{Bytes, H256},
    utils::keccak256,
};
use rlp::Encodable;
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::utils::hex_encode;

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("Branch does not have enough items")]
    BranchItemMissing,
    #[error("Extension node has no items")]
    ExtensionHasNoItems,
    #[error("Extension node has no next node")]
    ExtensionHasNoNextNode,
    #[error("Single proof root hash {computed} doesn't match multiproof root {expected}")]
    ProofRootMismatch { expected: String, computed: String },
    #[error("Node has no items")]
    NodeEmpty,
    #[error("Node item has no encoding")]
    NoEncoding,
    #[error("Unable to retrieve node using node hash")]
    NoNodeForHash,
    #[error("PathError {0}")]
    PathError(#[from] PathError),
    #[error("Node has invalid item count")]
    NodeHasInvalidItemCount,
    #[error("Leaf node has no final path to traverse")]
    LeafHasNoFinalPath,
    #[error("An inclusion proof was required, but found an exclusion proof")]
    InclusionRequired,
    #[error("An exclusion proof was required, but found an inclusion proof")]
    ExclusionRequired,
    #[error("The leaf path was expected to be complete")]
    LeafPathIncomplete,
    #[error("An extension node is was present as the final node in the path")]
    FinalExtension,
    #[error("The leaf node has no data")]
    LeafHasNoData,
    #[error("The leaf data does not match the expected data")]
    IncorrectLeafData,
    #[error("ModifyError {0}")]
    ModifyError(#[from] ModifyError),
}

#[derive(Debug, Error)]
pub enum ModifyError {
    #[error("Leaf node has no final path")]
    LeafHasNoFinalPath,
    #[error("The visited nodes list is empty")]
    NoVisitedNodes,
    #[error("Unable to retrieve node using node hash")]
    NoNodeForHash,
    #[error("Extension node has no final path")]
    ExtensionHasNoPath,
    #[error("Branch node does not have enough items")]
    NoItemInBranch,
}
/// A representation of a Merkle PATRICIA Trie Multi Proof.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MultiProof {
    /// node_hash -> node_rlp
    data: HashMap<H256, Vec<u8>>,
    /// Root hash of the proof. Used as the entry point to follow a path in the trie.
    /// Updated when data is modified.
    pub root: H256,
}

impl MultiProof {
    /// Create new multiproof with a known root.
    pub fn init(root: H256) -> Self {
        MultiProof {
            data: HashMap::default(),
            root,
        }
    }
    /// Add a new single proof to the multiproof.
    pub fn insert(&mut self, proof: Vec<Bytes>) -> Result<(), ProofError> {
        for (index, node) in proof.into_iter().enumerate() {
            let hash: H256 = keccak256(&node).into();
            if index == 0 && hash != self.root {
                return Err(ProofError::ProofRootMismatch {
                    expected: hex_encode(self.root),
                    computed: hex_encode(hash),
                });
            } else {
                self.data.insert(hash, node.to_vec());
            }
        }
        Ok(())
    }
    /// Traverse a path in the multiproof.
    ///
    /// May either be to update the value or to verify.
    pub fn traverse(&mut self, path: H256, intent: &Intent) -> Result<(), ProofError> {
        let mut traversal = NibblePath::init(path.as_bytes());
        let mut next_node_hash = self.root;
        let mut visited_nodes: Vec<VisitedNode> = vec![];
        // Start near root, follow path toward leaves.
        loop {
            let next_node_rlp = self
                .data
                .get(&next_node_hash)
                .ok_or(ProofError::NoNodeForHash)?;
            let next_node: Vec<Vec<u8>> = rlp::decode_list(&next_node_rlp);

            match NodeKind::deduce(&next_node)? {
                kind @ NodeKind::Branch => {
                    let traversal_record = traversal.clone();
                    let item_index = traversal.visit_path_nibble()? as usize;
                    let item = next_node
                        .get(item_index)
                        .ok_or(ProofError::BranchItemMissing)?;
                    visited_nodes.push(VisitedNode {
                        kind,
                        node_hash: next_node_hash,
                        item_index: item_index,
                        traversal_record,
                    });
                    let is_exclusion_proof = item.is_empty();
                    match (is_exclusion_proof, intent) {
                        (true, Intent::Modify(_)) => {
                            self.apply_changes(Change::BranchExclusionToInclusion, &visited_nodes)?;
                        }
                        (true, Intent::Remove) => {
                            // Key already not in trie.
                            return Ok(());
                        }
                        (true, Intent::VerifyExclusion) => return Ok(()),
                        (true, Intent::VerifyInclusion(_)) => {
                            return Err(ProofError::InclusionRequired)
                        }
                        (false, _) => {
                            // Continue traversing
                            next_node_hash = H256::from_slice(&item);
                        }
                    }
                }
                kind @ NodeKind::Extension => {
                    let traversal_record = traversal.clone();
                    let extension = next_node.get(0).ok_or(ProofError::ExtensionHasNoItems)?;
                    visited_nodes.push(VisitedNode {
                        kind,
                        node_hash: next_node_hash,
                        item_index: 1,
                        traversal_record,
                    });
                    match (traversal.match_or_mismatch(extension)?, intent) {
                        (SubPathMatches, _) => {
                            let item =
                                next_node.get(1).ok_or(ProofError::ExtensionHasNoNextNode)?;
                            next_node_hash = H256::from_slice(&item);
                            todo!("need to update traversal here");
                        }
                        (SubPathDiverges, Intent::Modify(_)) => {
                            self.apply_changes(
                                Change::ExtensionExclusionToInclusion,
                                &visited_nodes,
                            )?;
                        }
                        (SubPathDiverges, Intent::Remove) => {
                            // Key already not in trie
                            return Ok(());
                        }
                        (SubPathDiverges, Intent::VerifyExclusion) => return Ok(()),
                        (SubPathDiverges, Intent::VerifyInclusion(_)) => {
                            return Err(ProofError::InclusionRequired)
                        }
                        (FullPathMatches | FullPathDiverges, _) => {
                            return Err(ProofError::FinalExtension)
                        }
                    };
                }
                kind @ NodeKind::Leaf => {
                    let traversal_record = traversal.clone();
                    let final_subpath = next_node.get(0).ok_or(ProofError::LeafHasNoFinalPath)?;

                    visited_nodes.push(VisitedNode {
                        kind,
                        node_hash: next_node_hash,
                        item_index: 1,
                        traversal_record,
                    });
                    match (traversal.match_or_mismatch(final_subpath)?, intent) {
                        (SubPathMatches | SubPathDiverges, _) => {
                            return Err(ProofError::LeafPathIncomplete)
                        }
                        (FullPathMatches, Intent::Modify(new_value)) => {
                            self.apply_changes(
                                Change::LeafInclusionModify(new_value.to_owned()),
                                &visited_nodes,
                            )?;
                            return Ok(());
                        }
                        (FullPathMatches, Intent::VerifyExclusion) => {
                            return Err(ProofError::ExclusionRequired)
                        }
                        (FullPathMatches, Intent::Remove) => {
                            self.apply_changes(Change::LeafInclusionToExclusion, &visited_nodes)?;
                            return Ok(());
                        }
                        (FullPathMatches, Intent::VerifyInclusion(expected_rlp_data)) => {
                            let leaf_rlp_data =
                                next_node.get(1).ok_or(ProofError::LeafHasNoData)?;
                            if leaf_rlp_data != expected_rlp_data {
                                return Err(ProofError::IncorrectLeafData);
                            }
                            return Ok(());
                        }
                        (FullPathDiverges, Intent::Modify(_)) => {
                            self.apply_changes(Change::LeafExclusionToInclusion, &visited_nodes)?;
                            return Ok(());
                        }
                        (FullPathDiverges, Intent::Remove) => {
                            // Key already not in trie
                            return Ok(());
                        }
                        (FullPathDiverges, Intent::VerifyExclusion) => return Ok(()),
                        (FullPathDiverges, Intent::VerifyInclusion(_)) => {
                            return Err(ProofError::InclusionRequired)
                        }
                    }
                }
            }
        }
    }
    fn apply_changes(
        &mut self,
        change: Change,
        visited: &[VisitedNode],
    ) -> Result<(), ModifyError> {
        // Change leafmost value
        // Add any nodes required
        // Redo hashes back to root.
        let last_visited = visited.last().ok_or(ModifyError::NoVisitedNodes)?;
        let old_terminal_hash = last_visited.node_hash;
        // Get the terminal node by removing it from the proof.
        let old_node_rlp = self
            .data
            .remove(&old_terminal_hash.into())
            .ok_or(ModifyError::NoNodeForHash)?;
        let old_node: Vec<Vec<u8>> = rlp::decode_list(&old_node_rlp);

        match change {
            Change::BranchExclusionToInclusion => {
                // Main concept: Add leaf to the previously terminal branch.
                // As an exclusion proof there is no other key that overlaps this path part,
                // so no extension node is needed.

                // Leaf: [remaining_path, value]

                todo!();
            }
            Change::ExtensionExclusionToInclusion => {
                todo!("Alter: Exclusion proof to inclusion proof by shortening extension to common path, then adding branch node, and leaf for new value and then bubbling changes.")
            }
            Change::LeafExclusionToInclusion => {
                todo!("Alter: Exclusion proof to inclusion proof by adding extension node and branch node and one leaf node, moving the current leaf node to the branch node too.")
            }
            Change::LeafInclusionModify(new_data) => {
                let path = old_node.first().ok_or(ModifyError::LeafHasNoFinalPath)?;
                let new_leaf_data = Node(vec![Item(path.to_owned()), Item(new_data)]);
                let new_leaf_rlp = new_leaf_data.rlp_bytes().to_vec();
                let mut updated_hash = keccak256(&new_leaf_rlp);

                // Add the new leaf.
                self.data.insert(updated_hash.into(), new_leaf_rlp);

                // Update the rest
                for outdated in visited.iter().rev().skip(1) {
                    updated_hash = self.update_node_with_child_hash(outdated, &updated_hash)?;
                }
                self.root = updated_hash.into();
            }
            Change::LeafInclusionToExclusion => {
                todo!("Remove leaf, then possibly remove extension/branch nodes as required, bubble up changes.")
            }
        }
        Ok(())
    }
    /// Updates a node that was visited during traversal, but which now has an outdated hash because
    /// one of its children has changed.
    ///
    /// The updates applied start near the leaf end of the tree. The child hash needs to be inserted
    /// at the correct position in the node. The old node is removed and the new node is added and
    /// its hash returned, ready fo the parent node to use for it's update.
    fn update_node_with_child_hash(
        &mut self,
        visited: &VisitedNode,
        child_hash: &[u8; 32],
    ) -> Result<[u8; 32], ModifyError> {
        let outdated_rlp = self
            .data
            .remove(&visited.node_hash)
            .ok_or(ModifyError::NoNodeForHash)?;
        let outdated_node: Vec<Vec<u8>> = rlp::decode_list(&outdated_rlp);
        let updated_node: Node = match visited.kind {
            NodeKind::Branch => {
                // [next_node_0, ..., next_node_16, value]
                let mut updated = Node::default();
                for (index, item) in outdated_node.into_iter().enumerate() {
                    if index == visited.item_index {
                        updated.0.push(Item(child_hash.to_vec()));
                    } else {
                        updated.0.push(Item(item));
                    }
                }
                updated
            }
            NodeKind::Extension => {
                let path = outdated_node
                    .first()
                    .ok_or(ModifyError::ExtensionHasNoPath)?;
                // [path, next_node]
                Node(vec![Item(path.to_owned()), Item(child_hash.to_vec())])
            }
            NodeKind::Leaf => todo!(),
        };
        let updated_rlp = updated_node.rlp_bytes().to_vec();
        let updated_hash = keccak256(&updated_rlp);
        self.data.insert(updated_hash.into(), updated_rlp);
        Ok(updated_hash)
    }
}

/// A merkle patricia trie node at any level/height of an account proof.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
struct Node(Vec<Item>);

/// A merkle patricia trie node item at any level/height of an account proof.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
struct Item(Vec<u8>);

/// A modification to the multiproof that is required.
pub enum Change {
    BranchExclusionToInclusion,
    ExtensionExclusionToInclusion,
    LeafExclusionToInclusion,
    LeafInclusionModify(Vec<u8>),
    LeafInclusionToExclusion,
}

/// A cache of the nodes visited. If the trie is modified, then
/// this can be used to update hashes back to the root.
struct VisitedNode {
    kind: NodeKind,
    node_hash: H256,
    /// Item within the node that was followed to get to the next node.
    item_index: usize,
    /// The path that was followed to get to the node.
    ///
    /// This allows new nodes to be added/removed as needed during proof modification.
    traversal_record: NibblePath,
}

/// The action to take when traversing a proof path.
pub enum Intent {
    /// Change the value at the end of the path.
    Modify(Vec<u8>),
    /// Remove the key from the trie.
    Remove,
    /// Check that the value at the end of the path is as expected.
    VerifyInclusion(Vec<u8>),
    /// Check that key is not in the tree. The caller can check if the value
    /// represents the absent kind (null account / null storage)
    VerifyExclusion,
}

pub enum NodeKind {
    Branch,
    Extension,
    Leaf,
}

impl NodeKind {
    fn deduce(node: &[Vec<u8>]) -> Result<NodeKind, ProofError> {
        match node.len() {
            17 => Ok(NodeKind::Branch),
            2 => {
                // Leaf or extension
                let partial_path = node.get(0).ok_or(ProofError::NodeEmpty)?;
                let encoding = partial_path.get(0).ok_or(ProofError::NoEncoding)?;
                Ok(match PrefixEncoding::try_from(encoding)? {
                    PrefixEncoding::ExtensionEven | PrefixEncoding::ExtensionOdd(_) => {
                        NodeKind::Extension
                    }
                    PrefixEncoding::LeafEven | PrefixEncoding::LeafOdd(_) => NodeKind::Leaf,
                })
            }
            _ => Err(ProofError::NodeHasInvalidItemCount),
        }
    }
}
