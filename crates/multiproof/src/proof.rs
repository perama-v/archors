//! For verifying a Merkle Patricia Multi Proof for arbitrary proof values.
//! E.g., Account, storage ...

use std::collections::HashMap;

use archors_verify::path::{
    nibbles_to_prefixed_bytes, prefixed_bytes_to_nibbles, NibblePath, PathError,
    PathNature::{FullPathDiverges, FullPathMatches, SubPathDiverges, SubPathMatches},
    PrefixEncoding, TargetNodeEncoding,
};
use ethers::{
    prelude::k256::sha2::digest::typenum::Mod,
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
    #[error("Unable to find only child in branch requiring deletion")]
    AbsentOnlyChild,
    #[error("Branch node to few items")]
    BranchTooShort,
    #[error("Leaf node has no final path")]
    LeafHasNoFinalPath,
    #[error("The visited nodes list is empty")]
    NoVisitedNodes,
    #[error("The visited node in question is absent")]
    NoVisitedNode,
    #[error("Unable to retrieve node using node hash")]
    NoNodeForHash,
    #[error("Extension node has no final path")]
    ExtensionHasNoPath,
    #[error("Node has no items")]
    NodeHasNoItems,
    #[error("Branch node does not have enough items")]
    NoItemInBranch,
    #[error("PathError {0}")]
    PathError(#[from] PathError),
    #[error("Branch node path was not long enough")]
    PathEndedAtBranch,
    #[error("Node path was not long enough to split")]
    NodePathTooShort,
    #[error("Branch item indicies must not exceed 15")]
    TooManyBranchItems,
    #[error("Branch item (0-15) must be 32 bytes")]
    BranchItemInvalidLength,
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
            let next_node: Vec<Vec<u8>> = rlp::decode_list(next_node_rlp);

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
                        item_index,
                        traversal_record,
                    });
                    let is_exclusion_proof = item.is_empty();
                    match (is_exclusion_proof, intent) {
                        (true, Intent::Modify(new_rlp_value)) => {
                            self.apply_changes(
                                Change::BranchExclusionToInclusion(new_rlp_value.clone()),
                                &visited_nodes,
                            )?;
                            return Ok(());
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
                            next_node_hash = H256::from_slice(item);
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
                            next_node_hash = H256::from_slice(item);
                            traversal.skip_extension_node_nibbles(extension)?;
                        }
                        (SubPathDiverges(divergent_nibble_index), Intent::Modify(new_value)) => {
                            self.apply_changes(
                                Change::ExtensionExclusionToInclusion {
                                    new_value: new_value.clone(),
                                    divergent_nibble_index,
                                },
                                &visited_nodes,
                            )?;
                            return Ok(());
                        }
                        (SubPathDiverges(_), Intent::Remove) => {
                            // Key already not in trie
                            return Ok(());
                        }
                        (SubPathDiverges(_), Intent::VerifyExclusion) => return Ok(()),
                        (SubPathDiverges(_), Intent::VerifyInclusion(_)) => {
                            return Err(ProofError::InclusionRequired)
                        }
                        (FullPathMatches | FullPathDiverges(_), _) => {
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
                        (SubPathMatches | SubPathDiverges(_), _) => {
                            return Err(ProofError::LeafPathIncomplete)
                        }
                        (FullPathMatches, Intent::Modify(new_value)) => {
                            self.apply_changes(
                                Change::LeafInclusionModify(new_value.clone()),
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
                        (
                            FullPathDiverges(divergent_nibble_index),
                            Intent::Modify(new_rlp_value),
                        ) => {
                            self.apply_changes(
                                Change::LeafExclusionToInclusion {
                                    new_value: new_rlp_value.clone(),
                                    divergent_nibble_index,
                                },
                                &visited_nodes,
                            )?;
                            return Ok(());
                        }
                        (FullPathDiverges(_), Intent::Remove) => {
                            // Key already not in trie
                            return Ok(());
                        }
                        (FullPathDiverges(_), Intent::VerifyExclusion) => return Ok(()),
                        (FullPathDiverges(_), Intent::VerifyInclusion(_)) => {
                            return Err(ProofError::InclusionRequired)
                        }
                    }
                }
            }
        }
    }
    /// Updates the multiproof and modifies the proof structure if needed.
    ///
    /// May involve changing between inclusion and exclusion proofs for a
    /// value, and associated removal or addition of nodes.
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
            .remove(&old_terminal_hash)
            .ok_or(ModifyError::NoNodeForHash)?;
        let mut old_node: Vec<Vec<u8>> = rlp::decode_list(&old_node_rlp);

        match change {
            Change::BranchExclusionToInclusion(new_leaf_rlp_value) => {
                // Main concept: Add leaf to the previously terminal branch.
                // As an exclusion proof there is no other key that overlaps this path part,
                // so no extension node is needed.

                // Leaf: [remaining_path, value]
                let traversal = &last_visited.traversal_record;
                let branch_item_index = traversal.visiting_index() + 1;
                // Remaining path is for the leaf.
                let leaf_path_start = traversal.visiting_index() + 1;
                let leaf_path = last_visited.traversal_record.get_encoded_path(
                    TargetNodeEncoding::Leaf,
                    leaf_path_start,
                    63,
                )?;
                let leaf_node = Node::from(vec![leaf_path, new_leaf_rlp_value]);
                let leaf_node_rlp = leaf_node.rlp_bytes();
                let leaf_node_hash = keccak256(&leaf_node_rlp);
                // Store leaf node
                self.data
                    .insert(leaf_node_hash.into(), leaf_node_rlp.into());
                // Store updated branch node
                let leaf_parent = old_node
                    .get_mut(branch_item_index)
                    .ok_or(ModifyError::BranchTooShort)?;
                *leaf_parent = leaf_node_hash.to_vec();
                let updated_branch_node: Node = Node::from(old_node);

                // Update the rest (starting from parents of the branch, ending at the root)
                let mut updated_hash = keccak256(&updated_branch_node.rlp_bytes());
                for outdated in visited.iter().rev().skip(1) {
                    updated_hash = self.update_node_with_child_hash(outdated, &updated_hash)?;
                }
                self.root = updated_hash.into();
            }
            Change::ExtensionExclusionToInclusion {
                new_value,
                divergent_nibble_index,
            } => {
                // Main concept: Exclusion proof to inclusion proof by adding a leaf.
                // An extension is required if the extension has something
                // in common with the new leaf path.

                // - traversal ...
                //   - new common extension (if required)
                //     - new branch
                //       - new leaf
                //       - modified extension
                //         - original branch

                let mut updated_hash = self.add_branch_for_new_leaf(
                    old_node,
                    last_visited,
                    divergent_nibble_index,
                    TargetNodeEncoding::Extension,
                    new_value,
                )?;

                // Update the rest
                for outdated in visited.iter().rev().skip(1) {
                    updated_hash = self.update_node_with_child_hash(outdated, &updated_hash)?;
                }
                self.root = updated_hash.into();
            }
            Change::LeafExclusionToInclusion {
                new_value,
                divergent_nibble_index,
            } => {
                // Main concept: Add an extension node then a branch node and move old leaf to it.
                // Then add new leaf node. An extension is required if
                // the old and new leaves have multiple nibbles in common.

                // - traversal ...
                //   - new common extension (if required)
                //     - new branch
                //       - new leaf
                //       - old leaf

                let mut updated_hash = self.add_branch_for_new_leaf(
                    old_node,
                    last_visited,
                    divergent_nibble_index,
                    TargetNodeEncoding::Leaf,
                    new_value,
                )?;

                // Update the rest
                for outdated in visited.iter().rev().skip(1) {
                    updated_hash = self.update_node_with_child_hash(outdated, &updated_hash)?;
                }
                self.root = updated_hash.into();
            }
            Change::LeafInclusionModify(new_leaf_rlp_value) => {
                let path = old_node.first().ok_or(ModifyError::LeafHasNoFinalPath)?;
                let new_leaf_data = Node::from(vec![path.to_owned(), new_leaf_rlp_value]);
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
                // 1. Whenever there is branch with 2 items and one is removed,
                // the branch must be removed.
                // 2. Look at the parent of the (now deleted) branch
                //   - If extension, remove that
                //   - If branch, go to 1.

                // Perform updates requiring structural changes to the trie.
                let (highest_hash, nodes_processed) =
                    self.process_child_removal(visited, visited.len() - 1)?;

                // Now just perform simple hash updates.
                let mut updated_hash = highest_hash;
                for outdated in visited.iter().rev().skip(nodes_processed) {
                    updated_hash = self.update_node_with_child_hash(outdated, &updated_hash)?;
                }
                self.root = updated_hash.into();
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
                let mut child_count = 0;
                for (index, item) in outdated_node.into_iter().enumerate() {
                    if index == visited.item_index {
                        updated.0.push(Item(child_hash.to_vec()));
                        child_count += 1;
                    } else {
                        if !item.is_empty() {
                            child_count += 1;
                        }
                        updated.0.push(Item(item));
                    }
                }
                // Branch cannot be removed if there is an only-child sibling extension awaiting
                // an update in a later EVM operation. In this case the child hash is passed as
                // an empty array.
                let can_remove_branch = child_hash != &[0u8; 32];
                if child_count == 1 && can_remove_branch {
                    // This node must be removed because it has one child.
                    // It was not updated earlier because it was waiting on this child hash.

                    todo!("Remove the node, modify the child +/- its parent")
                    // Use the child (an extension node) hash to get the child.
                }
                updated
            }
            NodeKind::Extension => {
                let path = outdated_node
                    .first()
                    .ok_or(ModifyError::ExtensionHasNoPath)?;
                // [path, next_node]
                Node::from(vec![path.to_owned(), child_hash.to_vec()])
            }
            NodeKind::Leaf => todo!(),
        };
        let updated_rlp = updated_node.rlp_bytes().to_vec();
        let updated_hash = keccak256(&updated_rlp);
        self.data.insert(updated_hash.into(), updated_rlp);
        Ok(updated_hash)
    }
    /// Adds a new leaf where there is curently an extension exclusion proof or leaf
    /// exclusion proof.
    ///
    /// This will turn the exclusion proof in to an inclusion proof.
    /// If the new leaf has some common path, an extension is added.
    ///
    /// Before:
    /// - traversal ...
    ///   - node (extension or leaf)
    ///       - original branch (if parent is extension)
    ///
    /// After:
    /// - traversal ...
    ///   - new common extension (if required)
    ///     - new branch
    ///       - new leaf
    ///       - modified node (extension or leaf)
    ///         - original branch (if parent is extension)
    ///
    /// Returns the most proximal newly created node hash.
    fn add_branch_for_new_leaf(
        &mut self,
        old_node: Vec<Vec<u8>>,
        last_visited: &VisitedNode,
        divergent_nibble_index: usize,
        old_node_kind: TargetNodeEncoding,
        new_leaf_value: Vec<u8>,
    ) -> Result<[u8; 32], ModifyError> {
        let mut old_node = old_node;
        // Make new leaf.
        let traversal = &last_visited.traversal_record;
        let new_leaf_path = traversal.get_encoded_path(
            TargetNodeEncoding::Leaf,
            divergent_nibble_index + 1, // leave a nibble (+1) for the branch
            63,
        )?;
        let leaf = Node::from(vec![new_leaf_path, new_leaf_value]);
        let leaf_rlp = leaf.rlp_bytes();
        let leaf_hash = keccak256(&leaf_rlp);
        self.data.insert(leaf_hash.into(), leaf_rlp.into());

        // Modify old node to start after the new branch.
        let num_common = divergent_nibble_index - traversal.visiting_index();
        let old_node_path = old_node.get_mut(0).ok_or(ModifyError::NodeHasNoItems)?;
        let old_node_nibbles = prefixed_bytes_to_nibbles(old_node_path)?;

        let (common_nibbles, divergent_nibbles) = old_node_nibbles.split_at(num_common);
        let (updated_node_index_in_branch, updated_node_nibbles) = divergent_nibbles
            .split_first()
            .ok_or(ModifyError::NodePathTooShort)?;

        // Update old node and store
        *old_node_path = nibbles_to_prefixed_bytes(updated_node_nibbles, old_node_kind)?;
        let updated_node_rlp = Node::from(old_node).rlp_bytes();
        let updated_node_hash = keccak256(&updated_node_rlp);
        self.data
            .insert(updated_node_hash.into(), updated_node_rlp.into());

        // Make new branch and add children (modified node and new leaf).
        let mut node_items: Vec<Vec<u8>> = (0..=17).map(|_| vec![]).collect();
        *node_items
            .get_mut(*updated_node_index_in_branch as usize)
            .ok_or(ModifyError::BranchTooShort)? = updated_node_hash.into();
        let leaf_index = traversal.nibble_at_index(divergent_nibble_index)?;
        *node_items
            .get_mut(leaf_index as usize)
            .ok_or(ModifyError::BranchTooShort)? = leaf_hash.into();
        let branch_rlp = Node::from(node_items).rlp_bytes();
        let branch_hash = keccak256(&branch_rlp);
        self.data.insert(branch_hash.into(), branch_rlp.into());

        if common_nibbles.is_empty() {
            // Paths have something in common
            // - traversal ...
            //   - new branch
            //     - new leaf
            //     - modified node (extension or leaf)
            //       - original branch (if parent is extension)
            return Ok(branch_hash);
        } else {
            // Paths have something in common
            // - traversal ...
            //   - new common extension (if required)
            //     - new branch
            //       - new leaf
            //       - modified node (extension or leaf)
            //         - original branch (if parent is extension)
            let common_extension_path =
                nibbles_to_prefixed_bytes(common_nibbles, TargetNodeEncoding::Extension)?;
            let common_extension =
                Node::from(vec![common_extension_path, branch_hash.into()]).rlp_bytes();
            let common_extension_hash = keccak256(&common_extension);
            self.data
                .insert(common_extension_hash.into(), common_extension.into());
            return Ok(common_extension_hash);
        }
    }
    /// Modifies a (parent) node with a removed child. Returns the hash of the
    /// modified node and it's position in the traversal.
    ///
    /// The terms grandparent, parent and sibling all are iwth respect to the removed child.
    ///
    /// Visited refers to nodes traversed (root to leaf) and visiting refers to the index
    /// of the node that is the parent.
    fn process_child_removal(
        &mut self,
        visit_record: &[VisitedNode],
        visit_index: usize,
    ) -> Result<([u8; 32], usize), ModifyError> {
        let mut node_index = visit_index;
        if node_index == 0 {
            todo!("handle modification when no grandparent exists");
        }

        // Perform removal of elements as long as necessary.
        loop {
            let visited = visit_record
                .get(node_index)
                .ok_or(ModifyError::NoVisitedNode)?;
            let outdated_rlp = self
                .data
                .remove(&visited.node_hash)
                .ok_or(ModifyError::NoNodeForHash)?;
            let outdated_node: Vec<Vec<u8>> = rlp::decode_list(&outdated_rlp);

            match visited.kind {
                NodeKind::Branch => {
                    // [next_node_0, ..., next_node_16, value]
                    let mut updated = Node::default();
                    let mut item_count = 0;
                    let mut non_empty_child_index = 0;
                    for (index, item) in outdated_node.into_iter().enumerate() {
                        if index == visited.item_index {
                            // Erase child
                            updated.0.push(Item(vec![]));
                        } else {
                            if !item.is_empty() {
                                item_count += 1;
                                non_empty_child_index = index;
                            }
                            updated.0.push(Item(item));
                        }
                    }

                    match item_count {
                        0 => todo!("error, not possible"),
                        1 => {
                            // Branch node for deletion.
                            // Need to attach this single item at some point.

                            let visited_grandparent = visit_record
                                .get(node_index - 1)
                                .ok_or(ModifyError::NoVisitedNode)?;

                            let only_child_nibble: u8 = non_empty_child_index
                                .try_into()
                                .map_err(|_| ModifyError::TooManyBranchItems)?;

                            let non_empty_child_hash = updated
                                .0
                                .get(non_empty_child_index)
                                .ok_or(ModifyError::AbsentOnlyChild)?;

                            self.resolve_child_and_grandparent_paths(
                                &non_empty_child_hash.0,
                                only_child_nibble,
                                &visited_grandparent.node_hash.0,
                            )?;

                            // May still need to delete parents, so this leaf
                            // path may get longer.
                            todo!()
                        }
                        _ => {
                            let updated_rlp = updated.rlp_bytes().to_vec();
                            let updated_node_hash = keccak256(&updated_rlp);
                            self.data.insert(updated_node_hash.into(), updated_rlp);
                            // No further deletions required.
                            return Ok((updated_node_hash, node_index));
                        }
                    }
                }
                NodeKind::Extension => {
                    // This is an extension node, with a deleted child (branch).

                    let path = outdated_node
                        .first()
                        .ok_or(ModifyError::ExtensionHasNoPath)?;
                    // [path, next_node]
                    // Node::from(vec![path.to_owned(), child_hash.to_vec()]);

                    todo!()
                }
                NodeKind::Leaf => todo!(),
            };
            node_index += 1;
        }
        unreachable!()
    }
    /// When the trie is altered and a parent is removed, the nodes above (grandparent) and
    /// below (only child) are modified to have a correct path.
    ///
    /// The nodes are created and updated and the hash of the node closest to the root is
    /// returned.
    ///
    /// The child was previously on a branch with a specific nibble.
    fn resolve_child_and_grandparent_paths(
        &mut self,
        only_child_hash: &[u8],
        only_child_nibble: u8,
        grandparent_hash: &[u8; 32],
    ) -> Result<[u8; 32], ModifyError> {
        // Deduce the node kind for the child and grandparent

        // For each combination, compute the new paths / nodes

        let grandparent_rlp = self
            .data
            .get(&grandparent_hash.into())
            .ok_or(ModifyError::NoNodeForHash)?;
        let grandparent_node: Vec<Vec<u8>> = rlp::decode_list(&grandparent_rlp);

        let hash: H256 = H256::from_slice(only_child_hash);
        let only_child_rlp: Vec<u8> = match self.data.get(&hash){
            Some(node) => {
                // Not likely - this is data outside the path of this key.
                todo!();
            },
            None => {

                todo!("sibling fetching here")
            },
        };
        let only_child_node: Vec<Vec<u8>> = rlp::decode_list(&only_child_rlp);

        let child: NodeKind = todo!();
        let grandparent: NodeKind = todo!();

        match (child, grandparent) {
            (NodeKind::Branch, NodeKind::Branch) => {
                // Add an extension above the sibling. Make the sibling branch index the extension path.
                todo!()
            }
            (NodeKind::Branch, NodeKind::Extension) => {
                // Add sibling branch index to grandparent extension.
                todo!()
            }
            (NodeKind::Extension, NodeKind::Branch) => {
                // Add sibling branch index to sibling extension. Requires knowledge of sibling node.
                todo!()
            }
            (NodeKind::Extension, NodeKind::Extension) => {
                // Remove grandparent extension. Add sibling branch index and grandparent extension to sibling extension. Requires knowledge of sibling node.
                todo!()
            }
            (NodeKind::Leaf, NodeKind::Branch) => {
                // Add sibling branch index to sibling leaf path. Requires knowledge of sibling node.
                todo!()
            }
            (NodeKind::Leaf, NodeKind::Extension) => {
                // Remove grandparent extension, add sibling branch index and grandparent extension path to sibling leaf path. Requires knowledge of sibling node.
                todo!()
            }
            (_, NodeKind::Leaf) => todo!("error, grandparent cannot be leaf"),
        }
    }
}

/// A merkle patricia trie node at any level/height of an account proof.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
struct Node(Vec<Item>);

impl From<Vec<Vec<u8>>> for Node {
    fn from(value: Vec<Vec<u8>>) -> Self {
        Self(value.into_iter().map(Item::from).collect())
    }
}

/// A merkle patricia trie node item at any level/height of an account proof.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
struct Item(Vec<u8>);

impl From<Vec<u8>> for Item {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

/// A modification to the multiproof that is required.
///
/// - The new rlp encoded value is required in some variants.
/// - The new index of the nibble (range 0-63) that the excluded key shared
/// with the existing trie is required in some exclusion proofs.
pub enum Change {
    BranchExclusionToInclusion(Vec<u8>),
    ExtensionExclusionToInclusion {
        new_value: Vec<u8>,
        divergent_nibble_index: usize,
    },
    LeafExclusionToInclusion {
        new_value: Vec<u8>,
        divergent_nibble_index: usize,
    },
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
                let partial_path = node.first().ok_or(ProofError::NodeEmpty)?;
                let encoding = partial_path.first().ok_or(ProofError::NoEncoding)?;
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
