//! For verifying a Merkle Patricia Multi Proof for arbitrary proof values.
//! E.g., Account, storage ...

use std::collections::HashMap;

use archors_types::{oracle::TrieNodeOracle, proof::DisplayProof};
use archors_verify::{
    eip1186::Account,
    path::{
        nibbles_to_prefixed_bytes, prefixed_bytes_to_nibbles, NibblePath, PathError, PathNature,
        TargetNodeEncoding,
    },
};
use ethers::{
    types::{Bytes, H256, U256},
    utils::keccak256,
};
use log::{debug};
use rlp::{Encodable, RlpStream};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use PathNature::*;

use crate::{
    node::{NodeError, NodeKind, VisitedNode},
    oracle::OracleTask,
    utils::hex_encode,
};

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("Branch does not have enough items")]
    BranchItemMissing,
    #[error("Expected branch path to match while inserting oracle data.")]
    BadBranchInOracleTask,
    #[error("Expected extension path to match while inserting oracle data.")]
    BadExtensionInOracleTask,
    #[error("Extension node has no items")]
    ExtensionHasNoItems,
    #[error("Extension node has no next node")]
    ExtensionHasNoNextNode,
    #[error("Oracle lookup response was empty")]
    EmptyOracleResponse,
    #[error("Unable to insert single proof with root {computed} into multiproof with root {expected} (node {node})")]
    ProofRootMismatch {
        expected: String,
        computed: String,
        node: Bytes,
    },
    #[error("Unable to retrieve oracle node using node hash {0}")]
    NoOracleNodeForHash(String),
    #[error("Unable to retrieve proof node using node hash {0}")]
    NoProofNodeForHash(String),
    #[error("Unable to retrieve view node using node hash {0}")]
    NoViewNodeForHash(String),
    #[error("Traversal has no history")]
    NoTraversalHistory,
    #[error("PathError {0}")]
    PathError(#[from] PathError),
    #[error("Unable to traverse and confirm key exclusion proof after oracle update: {0}")]
    PostOracleTraversalFailed(String),
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
    #[error("Unexpected leaf when traversing proof to insert oracle data")]
    LeafInOracleTask,
    #[error("The leaf data does not match the expected data")]
    IncorrectLeafData,
    #[error("ModifyError {0}")]
    ModifyError(#[from] ModifyError),
    #[error("NodeError {0}")]
    NodeError(#[from] NodeError),
    #[error("NoNodeInOracle: The oracle was expected to have a node for task {task} ")]
    NoNodeInOracle { task: String },
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
    #[error("NodeError {0}")]
    NodeError(#[from] NodeError),
}
/// A representation of a Merkle PATRICIA Trie Multi Proof.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MultiProof {
    /// node_hash -> node_rlp
    data: HashMap<H256, Vec<u8>>,
    /// Root hash of the proof. Used as the entry point to follow a path in the trie.
    /// Updated when data is modified.
    pub root: H256,
    /// Traversal index that requires information from an oracle in order to update the proof.
    pub traversal_index_for_oracle_task: Option<usize>,
}

pub enum ProofOutcome {
    Root(H256),
    IndexForOracle(usize),
}

impl MultiProof {
    /// Create new multiproof with a known root.
    pub fn init(root: H256) -> Self {
        MultiProof {
            data: HashMap::default(),
            root,
            traversal_index_for_oracle_task: None,
        }
    }
    /// Add a new single proof to the multiproof.
    ///
    /// If the multiproof has no root, the root is obtained from the proof.
    pub fn insert_proof(&mut self, proof: Vec<Bytes>) -> Result<(), ProofError> {
        for (index, node) in proof.into_iter().enumerate() {
            let hash: H256 = keccak256(&node).into();
            if index == 0 && self.root == H256::default() {
                self.root = hash;
            }
            if index == 0 && hash != self.root {
                return Err(ProofError::ProofRootMismatch {
                    expected: hex_encode(self.root),
                    computed: hex_encode(hash),
                    node,
                });
            } else {
                self.data.insert(hash, node.to_vec());
            }
        }
        Ok(())
    }
    /// Get the node for the given node hash.
    pub fn get_node(&self, hash: &H256) -> Result<&[u8], ProofError> {
        Ok(self.data
            .get(hash)
            .ok_or_else(|| ProofError::NoProofNodeForHash(hex_encode(hash)))?)
    }
    /// Traverse a path in the multiproof.
    ///
    /// May either be to update the value or to verify. A task may be returned if information
    /// form an oracle is required.
    pub fn traverse(
        &mut self,
        path: H256,
        intent: &Intent,
    ) -> Result<Vec<VisitedNode>, ProofError> {
        let mut traversal = NibblePath::init(path.as_bytes());
        let mut next_node_hash = self.root;
        let mut visited_nodes: Vec<VisitedNode> = vec![];
        // Start near root, follow path toward leaves.
        loop {
            let next_node_rlp = self
                .data
                .get(&next_node_hash)
                .ok_or(ProofError::NoProofNodeForHash(hex_encode(next_node_hash)))?;
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
                            return Ok(visited_nodes);
                        }
                        (true, Intent::Remove) => {
                            // Key already not in trie.
                            return Ok(visited_nodes);
                        }
                        (true, Intent::VerifyExclusion) => return Ok(visited_nodes),
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
                            return Ok(visited_nodes);
                        }
                        (SubPathDiverges(_), Intent::Remove) => {
                            // Key already not in trie
                            return Ok(visited_nodes);
                        }
                        (SubPathDiverges(_), Intent::VerifyExclusion) => return Ok(visited_nodes),
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
                    let traversal_status = traversal.match_or_mismatch(final_subpath)?;
                    match (traversal_status, intent) {
                        (SubPathMatches | SubPathDiverges(_), _) => {
                            return Err(ProofError::LeafPathIncomplete)
                        }
                        (FullPathMatches, Intent::Modify(new_value)) => {
                            self.apply_changes(
                                Change::LeafInclusionModify(new_value.clone()),
                                &visited_nodes,
                            )?;
                            return Ok(visited_nodes);
                        }
                        (FullPathMatches, Intent::VerifyExclusion) => {
                            return Err(ProofError::ExclusionRequired)
                        }
                        (FullPathMatches, Intent::Remove) => {
                            self.apply_changes(Change::LeafInclusionToExclusion, &visited_nodes)?;
                            return Ok(visited_nodes);
                        }
                        (FullPathMatches, Intent::VerifyInclusion(expected_rlp_data)) => {
                            let leaf_rlp_data =
                                next_node.get(1).ok_or(ProofError::LeafHasNoData)?;
                            if leaf_rlp_data != expected_rlp_data {
                                return Err(ProofError::IncorrectLeafData);
                            }
                            return Ok(visited_nodes);
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
                            return Ok(visited_nodes);
                        }
                        (FullPathDiverges(_), Intent::Remove) => {
                            // Key already not in trie
                            return Ok(visited_nodes);
                        }
                        (FullPathDiverges(_), Intent::VerifyExclusion) => return Ok(visited_nodes),
                        (FullPathDiverges(_), Intent::VerifyInclusion(_)) => {
                            return Err(ProofError::InclusionRequired)
                        }
                    }
                }
            }
        }
    }

    /// Traverse a path with the goal of updating a specific node along the way.
    ///
    /// Changes are then made all they way to the root.
    /// This is only used when applying an oracle based updated.
    ///
    /// ## Algorithm
    /// - Get the node from the oracle.
    /// - Traverse the path in the (as yet not updated) proof to the required index.
    /// - Insert the new node
    /// - In the parent of the node being updated, update the hash to the oracle-based hash
    /// (self.update_node_with_child_hash)
    /// - Cascade remaining changes to the root
    /// - Then traverse the entire path and confirm that it is a valid exclusion proof.
    ///
    /// During future traversals, this oracle-based node would then be traversed. However, this
    /// will not arise because the oracle updates are applied deepest-first.
    pub fn traverse_oracle_update(
        &mut self,
        task: OracleTask,
        oracle: &TrieNodeOracle,
    ) -> Result<(), ProofError> {
        // Traverse the proof. Once the oracle-requiring node is reached, replace and cascade changes.
        let path: H256 = keccak256(&task.key).into();
        let mut traversal = NibblePath::init(path.as_bytes());
        let mut visited_nodes: Vec<VisitedNode> = vec![];
        let mut next_node_hash = self.root;
        // Gather the list of nodes that require updating.
        loop {
            let next_node_rlp = self
                .data
                .get(&next_node_hash)
                .ok_or(ProofError::NoOracleNodeForHash(hex_encode(next_node_hash)))?;
            let next_node: Vec<Vec<u8>> = rlp::decode_list(next_node_rlp);

            match NodeKind::deduce(&next_node)? {
                NodeKind::Branch => {
                    let traversal_record = traversal.clone();
                    let item_index = traversal.visit_path_nibble()? as usize;
                    let item = next_node
                        .get(item_index)
                        .ok_or(ProofError::BranchItemMissing)?;
                    visited_nodes.push(VisitedNode {
                        kind: NodeKind::Branch,
                        node_hash: next_node_hash,
                        item_index,
                        traversal_record,
                    });
                    let is_exclusion_proof = item.is_empty();
                    match is_exclusion_proof {
                        true => return Err(ProofError::BadBranchInOracleTask),
                        false => {
                            // Continue traversing
                            next_node_hash = H256::from_slice(item);
                        }
                    }
                }
                NodeKind::Extension => {
                    let traversal_record = traversal.clone();
                    let extension = next_node.get(0).ok_or(ProofError::ExtensionHasNoItems)?;
                    visited_nodes.push(VisitedNode {
                        kind: NodeKind::Extension,
                        node_hash: next_node_hash,
                        item_index: 1,
                        traversal_record,
                    });
                    match traversal.match_or_mismatch(extension)? {
                        SubPathMatches => {
                            let item =
                                next_node.get(1).ok_or(ProofError::ExtensionHasNoNextNode)?;
                            next_node_hash = H256::from_slice(item);
                            traversal.skip_extension_node_nibbles(extension)?;
                        }
                        _ => return Err(ProofError::BadExtensionInOracleTask),
                    }
                }
                NodeKind::Leaf => return Err(ProofError::LeafInOracleTask),
            }
            if traversal.visiting_index() >= task.traversal_index {
                // Traversal has reached the node to be replaced.
                break;
            }
        }
        // Consult the oracle.
        let traversal_for_oracle = traversal
            .history_with_next()
            .map_err(|_| ProofError::NoTraversalHistory)?;

        let oracle_nodes: Vec<Vec<u8>> = oracle
            .lookup(task.address, traversal_for_oracle.to_owned())
            .ok_or_else(|| ProofError::NoNodeInOracle {
                task: task.to_string(),
            })?;
        let oracle_node = oracle_nodes
            .first()
            .ok_or_else(|| ProofError::EmptyOracleResponse)?;
        let oracle_node_hash = keccak256(oracle_node);

        // The first update is to a node whose child is now the oracle-based node.
        let mut updated_hash = oracle_node_hash;
        // Update all the nodes that were traversed to get to the updated node.
        for outdated in visited_nodes.iter().rev() {
            updated_hash = self.update_node_with_child_hash(outdated, &updated_hash)?;
        }
        // Update the storage root.
        debug!(
            "storage root updated via oracle to {}",
            hex_encode(updated_hash)
        );
        self.root = updated_hash.into();

        // Add nodes to the proof map.
        for node in oracle_nodes.into_iter() {
            let hash = keccak256(&node);
            self.data.insert(H256::from(hash), node);
        }
        // Finally finish the traversal, demonstrating that the key is removed from the trie.
        // The traversal should now have enough information now that the oracle update is complete.
        self.traverse(path, &Intent::VerifyExclusion)
            .map_err(|e| ProofError::PostOracleTraversalFailed(e.to_string()))?;
        Ok(())
    }

    /// Updates the multiproof and modifies the proof structure if needed.
    /// The traversal has finished and starting from the leaf/branch end, the
    /// nodes are changed, all the way up to the root.
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
            .get(&old_terminal_hash)
            .ok_or(ModifyError::NoNodeForHash)?;
        let mut old_node: Vec<Vec<u8>> = rlp::decode_list(&old_node_rlp);
        match change {
            Change::BranchExclusionToInclusion(new_leaf_rlp_value) => {
                // Main concept: Add leaf to the previously terminal branch.
                // As an exclusion proof there is no other key that overlaps this path part,
                // so no extension node is needed.

                // Leaf: [remaining_path, value]
                let traversal = &last_visited.traversal_record;
                let branch_item_index =
                    traversal.nibble_at_index(traversal.visiting_index())? as usize;
                // Remaining path is for the leaf.
                let leaf_path_start = traversal.visiting_index() + 1;
                let leaf_path = last_visited.traversal_record.get_encoded_path(
                    TargetNodeEncoding::Leaf,
                    leaf_path_start,
                    63,
                )?;
                let leaf_node = Node::try_from(vec![leaf_path, new_leaf_rlp_value])?;
                let leaf_node_rlp = leaf_node.to_rlp_list();
                let leaf_node_hash = keccak256(&leaf_node_rlp);
                // Store leaf node
                self.data
                    .insert(leaf_node_hash.into(), leaf_node_rlp.into());
                // Store updated branch node
                let leaf_parent = old_node
                    .get_mut(branch_item_index)
                    .ok_or(ModifyError::BranchTooShort)?;
                *leaf_parent = leaf_node_hash.to_vec();
                let updated_branch_node: Node = Node::try_from(old_node)?;
                let updated_rlp_node = updated_branch_node.to_rlp_list();
                let mut updated_hash = keccak256(&updated_rlp_node);
                self.data.insert(H256::from(updated_hash), updated_rlp_node);

                // Update the rest (starting from parents of the branch, ending at the root)

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
                let new_leaf_node = Node::try_from(vec![path.to_owned(), new_leaf_rlp_value])?;
                let new_leaf_rlp = new_leaf_node.to_rlp_list();
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

                // Modify the parent (and higher ancestors if needed).
                let (highest_hash, nodes_processed) = self.process_leaf_child_removal(visited)?;

                // Now just perform simple hash updates.
                let mut updated_hash = highest_hash;
                for outdated in visited.iter().rev().skip(nodes_processed) {
                    updated_hash = self.update_node_with_child_hash(outdated, &updated_hash)?;
                    self.root = updated_hash.into();
                }
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
                Node::try_from(vec![path.to_owned(), child_hash.to_vec()])?
            }
            NodeKind::Leaf => todo!(),
        };
        let updated_rlp = updated_node.to_rlp_list();
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
        let leaf = Node::try_from(vec![new_leaf_path, new_leaf_value])?;
        let leaf_rlp = leaf.to_rlp_list();
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
        let updated_node_rlp = Node::try_from(old_node)?.to_rlp_list();
        let updated_node_hash = keccak256(&updated_node_rlp);
        self.data
            .insert(updated_node_hash.into(), updated_node_rlp.into());

        // Make new branch and add children (modified node and new leaf).
        let mut node_items: Vec<Vec<u8>> = (0..17).map(|_| vec![]).collect();
        *node_items
            .get_mut(*updated_node_index_in_branch as usize)
            .ok_or(ModifyError::BranchTooShort)? = updated_node_hash.into();
        let leaf_index = traversal.nibble_at_index(divergent_nibble_index)?;
        *node_items
            .get_mut(leaf_index as usize)
            .ok_or(ModifyError::BranchTooShort)? = leaf_hash.into();
        let branch_rlp = Node::try_from(node_items)?.to_rlp_list();
        let branch_hash = keccak256(&branch_rlp);
        self.data.insert(branch_hash.into(), branch_rlp.into());

        if common_nibbles.is_empty() {
            // Paths have something in common
            // - traversal ...
            //   - new branch
            //     - new leaf
            //     - modified node (extension or leaf)
            //       - original branch (if parent is extension)
            Ok(branch_hash)
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
                Node::try_from(vec![common_extension_path, branch_hash.into()])?.to_rlp_list();
            let common_extension_hash = keccak256(&common_extension);
            self.data
                .insert(common_extension_hash.into(), common_extension.into());
            Ok(common_extension_hash)
        }
    }
    /// Modifies a (parent) node with a removed child. Accepts a list of nodes visted in the
    /// traversal, where the final element is the leaf. Returns the hash of the
    /// modified node and the number of nodes in the visit record that do not need to be modified
    /// any more.
    ///
    /// The terms grandparent, parent and sibling all are with respect to the removed child.
    ///
    /// Visited refers to nodes traversed (root to leaf).
    fn process_leaf_child_removal(
        &mut self,
        visit_record: &[VisitedNode],
    ) -> Result<([u8; 32], usize), ModifyError> {
        if visit_record.len() == 1 {
            todo!("handle modification when no grandparent exists");
        }
        // Visit_record
        let leaf_visit_record_index = visit_record.len() - 1;
        let parent_visit_record_index = leaf_visit_record_index - 1;
        let grandparent_visit_record_index = parent_visit_record_index - 1;

        let parent = visit_record
            .get(parent_visit_record_index)
            .ok_or(ModifyError::NoVisitedNode)?;
        let outdated_rlp = self
            .data
            .get(&parent.node_hash)
            .ok_or(ModifyError::NoNodeForHash)?;
        let outdated_node: Vec<Vec<u8>> = rlp::decode_list(&outdated_rlp);
        debug!(
            "Parent branch node has deleted child. rlp is {}",
            hex_encode(outdated_rlp)
        );

        if parent.kind != NodeKind::Branch {
            todo!("Error: Remove leaf child called on non-branch node.")
        }

        // [next_node_0, ..., next_node_16, value]
        let mut updated = Node::default();
        let mut item_count = 0;
        // Find where the orphaned sibling leaf belongs in the branch.
        for (index, item) in outdated_node.into_iter().enumerate() {
            if index == parent.item_index {
                // Erase child
                updated.0.push(Item(vec![]));
            } else {
                if !item.is_empty() {
                    item_count += 1;
                }
                updated.0.push(Item(item));
            }
        }

        match item_count {
            0 => todo!("error, not possible"), // Branch should have at least one item.
            1 => {
                // The parent is a branch node for deletion (too few items).
                // This may require oracle knowledge, so it is returned as a task.

                // Need to attach this single item at some point.
                let visited_grandparent = visit_record
                    .get(grandparent_visit_record_index)
                    .ok_or(ModifyError::NoVisitedNode)?;

                self.traversal_index_for_oracle_task =
                    Some(visited_grandparent.traversal_record.visiting_index());

                debug!(
                    "Creating oracle task {:?}. parent nibble at {}, grandparent nibble at {}",
                    self.traversal_index_for_oracle_task,
                    parent.traversal_record.visiting_index(),
                    visited_grandparent.traversal_record.visiting_index()
                );
                // This node will be updated after the rest of the proof has been updated.
                let unchanged_hash = visited_grandparent.node_hash;
                // No changes to the trie can be made yet, so all nodes in the proof are said
                // be taken care of (to be done later as an oracle task.)
                return Ok((unchanged_hash.into(), visit_record.len()));
            }
            _ => {
                // No special action as the branch does not contain an orphan.
                let updated_rlp = updated.to_rlp_list();
                let updated_node_hash = keccak256(&updated_rlp);
                self.data.insert(updated_node_hash.into(), updated_rlp);
                // No further deletions required.
                // Leaf + parent = 3 nodes taken care of.
                return Ok((updated_node_hash, 2));
            }
        }
    }

    /**
    When the trie is altered and a parent is removed, the nodes above (grandparent) and
    below (only child) are modified to have a correct path.
    On entering this function the situation is:
    - Grandparent (may be leaf, extension or branch)
      - Parent (2-item branch, removed)
        - Child (leaf, removed)
        - Orphaned sibling (may be leaf, extension or branch)

    The outcome depends on the kind of node that the grandparent and orphaned sibling are:

    In a trio (grandparent-parent-sibling):
    - **E & **L: Additional sibling node RLP required to make updates.
        - EBE -> E
        - EBL -> L
        - BBE -> BE
        - BBL -> BL
    - **B: Additional sibling node RLP required only to differentiate from above cases.
        - EBB -> EB
        - BBB -> BEB

    Where additional data is required, the reason is as follows:
    - The deleted parent took up 1 nibble in the now-orphaned sibling.
    - The nibble must still appear in the traversal to that node.
    - To add the nibble to the node, the node must be known.
    - Only the hash is known because there is not necessarily a proof for the sibling
    - The sibling node must be obtained from a special cache created for this purpose.

    The nodes are created and updated and the hash of the node closest to the root is
    returned.
    */
    fn resolve_child_and_grandparent_paths(
        &mut self,
        only_child_hash: &[u8],
        only_child_nibble: u8,
        grandparent_hash: &[u8; 32],
    ) -> Result<[u8; 32], ModifyError> {
        println!(
            "Parent branch node removed. Grandparent node ({}). Only child node ({}).",
            hex_encode(grandparent_hash),
            hex_encode(only_child_hash)
        );

        // Deduce the node kind for the child and grandparent

        // For each combination, compute the new paths / nodes

        let grandparent_rlp = self
            .data
            .get(&grandparent_hash.into())
            .ok_or(ModifyError::NoNodeForHash)?;
        let grandparent_node: Vec<Vec<u8>> = rlp::decode_list(&grandparent_rlp);

        let hash: H256 = H256::from_slice(only_child_hash);
        let only_child_rlp: Vec<u8> = match self.data.get(&hash) {
            Some(node) => {
                // Not likely - this is data outside the path of this key.
                todo!();
            }
            None => {
                todo!("sibling fetching here")
            }
        };
        let only_child_node: Vec<Vec<u8>> = rlp::decode_list(&only_child_rlp);

        let child: NodeKind = todo!();
        let grandparent: NodeKind = NodeKind::deduce(&grandparent_node)?;

        match (grandparent, child) {
            (NodeKind::Branch, NodeKind::Branch) => {
                // BBB -> BEB. No sibling change required.

                // Add an extension above the sibling. Make the sibling branch index the extension path.
                todo!()
            }
            (NodeKind::Branch, NodeKind::Extension) => {
                // BBE -> BE. Additional sibling node RLP required.

                // Add sibling branch index to sibling extension.
                todo!()
            }
            (NodeKind::Branch, NodeKind::Leaf) => {
                // BBL -> BL. Additional sibling node RLP required.

                // Add sibling branch index to sibling leaf path.
                todo!()
            }
            (NodeKind::Extension, NodeKind::Branch) => {
                // EBB -> EB. No sibling change required.

                // Add sibling branch index to grandparent extension.
                todo!()
            }
            (NodeKind::Extension, NodeKind::Extension) => {
                // EBE -> E. Additional sibling node RLP required.

                // Remove grandparent extension. Add sibling branch index and grandparent extension to sibling extension.
                todo!()
            }
            (NodeKind::Extension, NodeKind::Leaf) => {
                // EBL -> L. Additional sibling node RLP required.

                // Remove grandparent extension, add sibling branch index and grandparent extension path to sibling leaf path.
                todo!()
            }
            (NodeKind::Leaf, _) => todo!("error, grandparent cannot be leaf"),
        }
    }
    /// View a single proof (follow one path in the multiproof).
    pub fn view(&self, path: H256) -> Result<DisplayProof, ProofError> {
        let mut traversal = NibblePath::init(path.as_bytes());
        let mut next_node_hash = self.root;
        let mut visited_nodes: Vec<Vec<u8>> = vec![];
        // Start near root, follow path toward leaves.
        loop {
            let next_node_rlp = self
                .data
                .get(&next_node_hash)
                .ok_or(ProofError::NoViewNodeForHash(hex_encode(next_node_hash)))?;
            visited_nodes.push(next_node_rlp.to_vec());
            let next_node: Vec<Vec<u8>> = rlp::decode_list(next_node_rlp);

            match NodeKind::deduce(&next_node)? {
                NodeKind::Branch => {
                    let item_index = traversal.visit_path_nibble()? as usize;
                    let item = next_node
                        .get(item_index)
                        .ok_or(ProofError::BranchItemMissing)?;

                    let is_exclusion_proof = item.is_empty();
                    match is_exclusion_proof {
                        true => break,
                        false => {
                            // Continue traversing
                            next_node_hash = H256::from_slice(item);
                        }
                    }
                }
                NodeKind::Extension => {
                    let extension = next_node.get(0).ok_or(ProofError::ExtensionHasNoItems)?;
                    match traversal.match_or_mismatch(extension)? {
                        SubPathMatches => {
                            let item =
                                next_node.get(1).ok_or(ProofError::ExtensionHasNoNextNode)?;
                            next_node_hash = H256::from_slice(item);
                            traversal.skip_extension_node_nibbles(extension)?;
                        }
                        SubPathDiverges(_) => continue,
                        FullPathMatches => break,
                        FullPathDiverges(_) => break,
                    }
                }
                NodeKind::Leaf => break,
            }
        }
        Ok(DisplayProof::init(visited_nodes))
    }
    /// Gets the proof node at a particular index along a traversal.
    pub(crate) fn get_proof_node(&self, key: H256, traversal_index: usize) -> Node {
        // compute path from key.

        // traverse until index is reached.

        // return that node.
        todo!()
    }
}

/// A merkle patricia trie node at any level/height of an account proof.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Node(Vec<Item>);

impl TryFrom<Vec<Vec<u8>>> for Node {
    type Error = ModifyError;

    fn try_from(value: Vec<Vec<u8>>) -> Result<Self, Self::Error> {
        if value.len() > 17 {
            return Err(ModifyError::TooManyBranchItems);
        }
        Ok(Self(value.into_iter().map(Item::from).collect()))
    }
}

impl Node {
    /// Converts the node into an RLP list.
    ///
    /// The items in the node are assumed to already be RLP-encoded if required.
    /// For example, a leaf node consists of two items: [path, rlp_value], where
    /// the rlp_value is already encoded.
    pub fn to_rlp_list(self) -> Vec<u8> {
        let len = self.0.len();
        let mut rlp = RlpStream::new_list(len);
        for item in self.0 {
            rlp.append(&item.0);
        }
        rlp.out().to_vec()
    }
}

/// A merkle patricia trie node item at any level/height of an account proof.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
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
#[derive(Debug)]
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

/// The action to take when traversing a proof path.
#[derive(Debug)]
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

/// Detects if an RLP encoded value is for an empty storage value or account.
///
/// This is useful to ensure that an exclusion proof has not been requested to update to this
/// new value.
fn is_empty_value(rlp_value: &[u8]) -> bool {
    if rlp_value == Account::default().rlp_bytes().as_ref() {
        return true;
    }
    if rlp_value == rlp::encode(&U256::default()).as_ref() {
        return true;
    }
    false
}

#[cfg(test)]
mod test {

    use std::str::FromStr;

    use crate::utils::hex_decode;

    use super::*;

    static PROOF_KEY_0A6D: [&str; 4] =
        [
        "0xf90211a0cc028bd8812137068b45dfdc090a3abd156d2decac5495a3623788b1845e80b7a090b710438062a8e3a864785dfad204e5c50ecc4dfb2317757de25a09ffb73467a0c8c2d6c55f93516737e62c21dc039dd8151a513894c9a4d2e29af1d82553b983a003bd937ca0d981eb1586a11ea2a9b5bea49ee9ccf25bbd562528e70ca5e209b5a0b202456017a653baee9c37aba08d9346f8ba0b59ff663240c58311e682ba21f0a05f218834277b0459e94c78c7f7a6aa42147bd3315256282fc24753b3502f864da020e4b50caafec552a2f512c8b8865d35a976c9d99888632cd09e9cdd9468adf4a0ffedf4b1107a30c5faa5d4d7441fb66e78d4f36d7902530aa1ba5bc2763ddfd6a0c26a1b99f93e2e2927c0502653dfa446604cd5caccfe123c4b651e9ad102064ba097bdc481d5aef9e4e47f3a137faf494ab75b125badddb9baa9ffe93478f94d34a00019c14eebafc64ef916948d4cbba254de0f68aa18496bf043bca22c356d73a5a0bf8aed067e6171212cc9966b572b5918d77653813dd9668611c91ad6c198728ca0569aa9641f9cc68c757ce07b7c8b4568bfd7c8082ce6435e9fce8facf32ac43da0544eda187304fd8377641149edcd83acc147b595615dcac12ce40aa9f57bf8aba000783d065fddfe12af22ad0f842f7c3b5a23304cba04b66a0d0e6d22b7e97168a0378240ecfa2b580ce56cf85903d8c3c6cb87d372c0350791b62bc9ec269ff1da80",
        "0xf9015180a0b6ff53997cdd0c1f088a13f81afb42724cfcea9a07f14a74bb7d1bf4991e1fe2808080a0830370b134144289bda9480169139c6b8f25ee03be7ed111b337c582778cb0e9a097d0df63fab694add277023d143b0e0514d72d8b39954c3e69c622dd0be1be27a05a18babcf477be08eaab47baaa7653f20bd1b736cb7a2c87a112fbcaf9d2f265a0a21b0e909676a0eaf650780fda8a442fa96c1cb75a148d0fdfb9605fba7d448ea0e0d9927be4ab098d9b51e1f2e5cf4526c28ef586b0d462a864772c344b632899a0f9578cbf15296164371c8deb5ccc2269029f5c10add7b9a3130ec836ee3eea99a0429142fd545a0147432a3a60ed59e7254d356b5eff9a8fb99e1bf38a8f11cf178080a06f9f472ad4ca9d97072e42c9c8cb6234d7135e7707f2404692bc3ccf928ca783a0ecc1f356e3335979ab17257d5e69368b64ac0cbd64a18024f128e017c0c0d53880",
        "0xf85180808080a0ef8c6373b2a3a53385ca6ebccb07682964a9a21b5830ce40c8a61e03cc1e2a37808080808080a01b8c4d7f49a0954432045cfbbf2a7d4f1ab809f91cedb3e55cd071085a3b6ca38080808080",
        "0xf8429f3cbb29e9e040ea0451a17e489cd2b1b66a862b497352538b80d4240421919da1a00231b85f09f42594f8310b9593937193da5a365e7de2b810e816e686e38db723"
        ]
    ;

    fn proof_str_to_vec(proof: Vec<&str>) -> Vec<Bytes> {
        proof
            .into_iter()
            .map(|node| Bytes::from(hex_decode(node).unwrap()))
            .collect()
    }

    /**
    A child with one sibling is removed. The parent branch is not needed and must be removed.
    This tests that the grandparent now holds the hash of the orphaned sibling.

    This case does not require additional knowledge (node hash preimages) to reshape the trie.

    - block: 17190873. Value of key is changed to zero.
    - address: 0x0a6dd5d5a00d6cb0678a4af507ba79a517d5eb64
    - key: 0x0381163500ec1bb2a711ed278aa3caac8cd61ce95bc6c4ce50958a5e1a83494b
    - value pre: 0x231b85f09f42594f8310b9593937193da5a365e7de2b810e816e686e38db723
    - value post: 0x0
    - proof: see PROOF_KEY_0A6D

    Traversal is a...9...4...
    - At the second branch node the item at index 9 is the grandparent.
       - Initially it is e0d9927be4ab098d9b51e1f2e5cf4526c28ef586b0d462a864772c344b632899
       - Post-block it is 3a297ff8508794992a9face497a7b51cc8f191bab147402429e6cd637ed972ee
    - The third branch has
        - Initially has the hash of the sibling node
        - Post-block it is removed and only exists as a leaf. However the hash of the leaf is different
        from the initial sibling hash. So the sibling has changed. The problem is that there is
        no way to know, starting with the initial sibling hash, how to get to the updated sibling hash.
        One cannot even know the key for that sibling, only the path. Ultimately, the grandparent
        cannot be updated through computation or verification, and it does not appear that the root
        can be computed. The only approach would be to say: "for exclusion proofs, we pull in the
        answer to the trie update and follow the path to confirm it does not exist in post-state".
    */
    #[test]
    fn test_orphaned_child_moves_to_grandparent() {
        let mut multi = MultiProof::init(
            H256::from_str("0x8791994f88cd3fbd74ac304f488e6c836df640825921f7e5a969c1dafbda8955")
                .unwrap(),
        );
        let only_child_hash =
            H256::from_str("0x1b8c4d7f49a0954432045cfbbf2a7d4f1ab809f91cedb3e55cd071085a3b6ca3")
                .unwrap();

        let grandparent_hash =
            H256::from_str("0019c14eebafc64ef916948d4cbba254de0f68aa18496bf043bca22c356d73a5")
                .unwrap();

        multi
            .insert_proof(proof_str_to_vec(PROOF_KEY_0A6D.to_vec()))
            .unwrap();
        let _highest_updated = multi.resolve_child_and_grandparent_paths(
            only_child_hash.as_fixed_bytes(),
            0xb,
            grandparent_hash.as_fixed_bytes(),
        );
        todo!("use fn traverse_oracle_update()");
    }

    static PROOF_KEY_8C87_PRE: [&str; 4] =
    [
        "0xf90211a061b95f74e88a171cd470c32a1c1f2a723292a15c04d91ed9b27bc6473b9c1beba04b41952a97299bcb6667f45689d72e506e7290c81d8a73ea154ba56f8be5c207a056c6e0aa27b0f3b3a7a8ea23a27526c786682d216d037aab443f8039ba8a0f73a0ba82a7f8a864d68c6e090fd42c6b03b6d4c25e2dc7d1d12a4d5e0fa37f406062a0d9ca24080b9a78d0618472c533cde1dd4bc467d70a92e0bcc5cdcb71bcf2dd5da0c0fd53f72879ce33b99336ed5863f381d852f2f6ef14e9727b846c258081202fa0d9c87ad05946e255582a2620696b17aaecda65cd8cf15be2982ce0d3ddb07d82a0eb9fe9345b77d3af379fd5f45ac7b37074ea66a3a4b761f8d39c7f84e7c0352fa0992f4d5ae3f444fecfc52e179956f82be75376ff563afbf7c0fa1d3156730346a000d7c7ec2c6ad564dcc0693e7c7b18f2a33024a59302c2803046767edc52fcdaa0efbb487dea8a86251cf0259c8b81c98981fe8ff1e31e98ae29893f8168de0078a01d5088e406c2df8c5b629cc32919f0c521be6b3cc5f3f086596c59b8f85bdf7ba0a2bb53977bc20be5a6d571c865d0846c94a3de5db3804125d4dcf694ae677767a0bcc74f699c325ce0f9a580f787290ee7a1a16fc334734de58a73de3cced7c0f4a03d89391fdf4cc5f9a7a7a90bad3422f0b9126f66324d033135a17175e58f3680a0fc8caa919403b2962cfe28a84cd830160dbd0c414dd338037ca12e3946ff4c0980",
        "0xf90211a0738ce9c28f00698eeb324b622ace83c0f5157b34331f4ccc3caf7368530ed87ca0740f14103c4bb55e34cd699dea2b5565d6bc72ff1f66a35fa5a466d73c0d75faa08e8ad60b03e2da01f1cc27170336f994db2d77c96a6ed07fa3f284a5a137b5caa074e1be987f1392874ddfd99454a87d101d2ab890d8be46be3db17ed9660df7ffa0a88f7503c16e3e4327e0748375dc90897af7c681f3ca1ba25d229c46e485aae6a07debc490cfccaacd7651d1752e297ac9fcfcce09fcd77d10b33f22841892c572a0664de45f91da00b578293a43ff5bb882d06ae5f5a84eab5cace89e4e6cf23683a0018186462a7d382b47f063973fe5238a22a15a777c46f7f9c80e5228588a09a2a018518917214346c1e2138433cd5b5d65b83525122502ce11ff16282593ff8c17a0e495b5f4d2c3be73a104d43f1326fc07ec83b72826ec7f6e1982f2ba7ce611e6a0bee8ea82fe02304cb44cf1c354870228d6cc8251e7ac4ff4933c9ad8ded8f7b2a00efc2af10ce53094fc7a111380d95192d4e2adcc76e61ac64b4468dd2963391da070632fe3f4a3fc3f4633bdee9ce209df73f136d6cf262e8f0b9e5f28921b743ca006512107683c334ce74640e546e73b4d84d75b5d8212e77aeac0d763953d8da8a0f936e45905483b24b502cbdb9a42f8b2817a1b8b7237a8c62d026d25518bd40aa06319f952f0ce0bdfc4850b68795f0de1139e968db278d99dfb1e4a3c79af0e4b80",
        "0xf90211a02ce227da6bdb2f4d3d2f8f4491cc92cfc259cbe30dc9f0302fb791b70665ae1ca052b6079dc0f5ac2a24dbeb50e90b521ba7272e4b8c62c2f3dbd0986c5a62c646a0cedabc9c11e9bb383644066c1bce10ec60118a36147fe4250ccc9493c68f8612a04266168ab7da43c8613367ba2b84112b3c287a55bb5dd78aadacb2ac3228d2cfa0d4910a86f9ed5a783ed7c313206efa470613a2f76c16c116f9f3e3b67b914585a079f12a7571f4b1b75ede3d518ab1ffff2d3be4bb32962966c5f67a9dbe30739ea08e1c57a61598a589113decd18f0ca84cabaeaa8274a436b43811e277c5822341a08f1eecdee2ac58b5df6ffe31e311db12e97190a63a268a6fa0bd21435572188aa06e0d779f481588a8c9e75a3686d0f24ba5bf49bda89aa1d0a515eda7285f688ba02b152134643b2d257193195f5fce84540e5122b8ee75be365951a2833cc2168aa0043b9865033ebef57721f81b776c5ff168aa90f80983484a12e28b58d7848e70a0306fb08df78b483f9f29bd491285042b926b1c9448f5cd74e73afb8f73dda8c3a0a56b890db44461e66dff505c15995e67ecaebcd6dd101ba5c8ae1daf187c1b09a07f497959215f6c0af86c696d81b468edb8b399c8204ff7085dca06c9b48753b9a0d10f909334725d2d2e402106d3fd9cac388700692bde978c4b671d377ee840e6a0c58d1d5734fd3038f055b83b631db9db1f6417270b7493697ad8536b1cae081280",
        "0xe213a0943acc702fab5b3792bfef36fc8a12302339d56e1a7ad659a9cdf6c354129eb4"
      ]
    ;

    static PROOF_KEY_8C87_POST: [&str; 5] =
    [
        "0xf90211a061b95f74e88a171cd470c32a1c1f2a723292a15c04d91ed9b27bc6473b9c1beba04b41952a97299bcb6667f45689d72e506e7290c81d8a73ea154ba56f8be5c207a056c6e0aa27b0f3b3a7a8ea23a27526c786682d216d037aab443f8039ba8a0f73a0ba82a7f8a864d68c6e090fd42c6b03b6d4c25e2dc7d1d12a4d5e0fa37f406062a0d9ca24080b9a78d0618472c533cde1dd4bc467d70a92e0bcc5cdcb71bcf2dd5da0c0fd53f72879ce33b99336ed5863f381d852f2f6ef14e9727b846c258081202fa0d9c87ad05946e255582a2620696b17aaecda65cd8cf15be2982ce0d3ddb07d82a0d483f6c92632f36339fb353ad7217ab6f6fcabc1e091a1a842292e1a70b5bf44a0992f4d5ae3f444fecfc52e179956f82be75376ff563afbf7c0fa1d3156730346a000d7c7ec2c6ad564dcc0693e7c7b18f2a33024a59302c2803046767edc52fcdaa0efbb487dea8a86251cf0259c8b81c98981fe8ff1e31e98ae29893f8168de0078a01d5088e406c2df8c5b629cc32919f0c521be6b3cc5f3f086596c59b8f85bdf7ba0a2bb53977bc20be5a6d571c865d0846c94a3de5db3804125d4dcf694ae677767a0bcc74f699c325ce0f9a580f787290ee7a1a16fc334734de58a73de3cced7c0f4a03d89391fdf4cc5f9a7a7a90bad3422f0b9126f66324d033135a17175e58f3680a0fc8caa919403b2962cfe28a84cd830160dbd0c414dd338037ca12e3946ff4c0980",
        "0xf90211a0738ce9c28f00698eeb324b622ace83c0f5157b34331f4ccc3caf7368530ed87ca0740f14103c4bb55e34cd699dea2b5565d6bc72ff1f66a35fa5a466d73c0d75faa08e8ad60b03e2da01f1cc27170336f994db2d77c96a6ed07fa3f284a5a137b5caa074e1be987f1392874ddfd99454a87d101d2ab890d8be46be3db17ed9660df7ffa0a88f7503c16e3e4327e0748375dc90897af7c681f3ca1ba25d229c46e485aae6a07debc490cfccaacd7651d1752e297ac9fcfcce09fcd77d10b33f22841892c572a0664de45f91da00b578293a43ff5bb882d06ae5f5a84eab5cace89e4e6cf23683a0018186462a7d382b47f063973fe5238a22a15a777c46f7f9c80e5228588a09a2a018518917214346c1e2138433cd5b5d65b83525122502ce11ff16282593ff8c17a0e495b5f4d2c3be73a104d43f1326fc07ec83b72826ec7f6e1982f2ba7ce611e6a0bee8ea82fe02304cb44cf1c354870228d6cc8251e7ac4ff4933c9ad8ded8f7b2a06e8fe182e1401b5ce6b9563f850ff976af7a7316db59e1f6978527b90a3a676ba070632fe3f4a3fc3f4633bdee9ce209df73f136d6cf262e8f0b9e5f28921b743ca006512107683c334ce74640e546e73b4d84d75b5d8212e77aeac0d763953d8da8a0f936e45905483b24b502cbdb9a42f8b2817a1b8b7237a8c62d026d25518bd40aa06319f952f0ce0bdfc4850b68795f0de1139e968db278d99dfb1e4a3c79af0e4b80",
        "0xf90211a02ce227da6bdb2f4d3d2f8f4491cc92cfc259cbe30dc9f0302fb791b70665ae1ca052b6079dc0f5ac2a24dbeb50e90b521ba7272e4b8c62c2f3dbd0986c5a62c646a0cedabc9c11e9bb383644066c1bce10ec60118a36147fe4250ccc9493c68f8612a04266168ab7da43c8613367ba2b84112b3c287a55bb5dd78aadacb2ac3228d2cfa0d4910a86f9ed5a783ed7c313206efa470613a2f76c16c116f9f3e3b67b914585a079f12a7571f4b1b75ede3d518ab1ffff2d3be4bb32962966c5f67a9dbe30739ea08e1c57a61598a589113decd18f0ca84cabaeaa8274a436b43811e277c5822341a08f1eecdee2ac58b5df6ffe31e311db12e97190a63a268a6fa0bd21435572188aa06e0d779f481588a8c9e75a3686d0f24ba5bf49bda89aa1d0a515eda7285f688ba02b152134643b2d257193195f5fce84540e5122b8ee75be365951a2833cc2168aa039c5b17ff7fee5cb7ab0dbda184e92253336be1b6a258ec241a365e14c24b1f3a0306fb08df78b483f9f29bd491285042b926b1c9448f5cd74e73afb8f73dda8c3a0a56b890db44461e66dff505c15995e67ecaebcd6dd101ba5c8ae1daf187c1b09a07f497959215f6c0af86c696d81b468edb8b399c8204ff7085dca06c9b48753b9a0d10f909334725d2d2e402106d3fd9cac388700692bde978c4b671d377ee840e6a0c58d1d5734fd3038f055b83b631db9db1f6417270b7493697ad8536b1cae081280",
        "0xf851808080a0943acc702fab5b3792bfef36fc8a12302339d56e1a7ad659a9cdf6c354129eb4808080808080a053b8d1768dc6dfbff1f19817218fc969895a0fd559890d45aa0241bca7d07cdf808080808080",
        "0xe69f202d0e9af17e2f97d1441d0988705b11a227aca5f716ffe2d914461a4eff2f858464544dd7"
      ]
    ;
    /**
    This checks that leaf can be added to a proof that terminates with an extension
    node (an exclusion proof). This involves the addition of one node. No oracle
    is required because the extension only has one nibble in it.

    Address: 0xecbee2fae67709f718426ddc3bf770b26b95ed20
    Key: 0x8c874ac9f7bd5ae2f2c60e6a4f1760c4c54770f4781c666f7ae305e1e70add32
    Path: 0x7baa2d0e9af17e2f97d1441d0988705b11a227aca5f716ffe2d914461a4eff2f
    Val: 0x0 pre, 0x64544dd7 post

    Note: In the post-proof, the proofs structure has been manually computed, as the
    actual block has more changes to the proof than appear here (below)

    Final proof:
    new root: ee76a42a55cb9e1b3f54c5dbf382c683b9edaf7ee98886d81e5ecca3cfccea90

    node index=3 (extension hash is now in branch at index 0x3, the new leaf is at index 0xa):
    0xf851808080a0943acc702fab5b3792bfef36fc8a12302339d56e1a7ad659a9cdf6c354129eb4808080808080a053b8d1768dc6dfbff1f19817218fc969895a0fd559890d45aa0241bca7d07cdf808080808080

    0xe69f202d0e9af17e2f97d1441d0988705b11a227aca5f716ffe2d914461a4eff2f858464544dd7
    */
    #[test]
    fn test_extension_exclusion_proof_to_inclusion() {
        let mut multi = MultiProof::init(
            H256::from_str("0x6b93962316b2fbd616359d59b41a6ca880f97f99bf631aeaab740b8927691654")
                .unwrap(),
        );
        multi
            .insert_proof(proof_str_to_vec(PROOF_KEY_8C87_PRE.to_vec()))
            .unwrap();
        let path: H256 = keccak256(
            H256::from_str("0x8c874ac9f7bd5ae2f2c60e6a4f1760c4c54770f4781c666f7ae305e1e70add32")
                .unwrap(),
        )
        .into();
        // Proof starts with 4 nodes.
        let pre = multi.view(path).unwrap();
        assert_eq!(pre.inner().len(), 4);
        let new_val = slot_rlp_from_value(ru256::from_str("0x64544dd7").unwrap());

        // Proof starts as valid exclusion proof.
        multi.traverse(path, &Intent::VerifyExclusion).unwrap();
        // Update the proof to a new value.
        multi
            .traverse(path, &Intent::Modify(new_val.to_owned()))
            .unwrap();
        // Proof ends as valid inclusion proof.
        multi
            .traverse(path, &Intent::VerifyInclusion(new_val))
            .unwrap();
        let post = multi.view(path).unwrap();
        // Proof now has 5 nodes
        assert_eq!(post.inner().len(), 5);
        let mut expected_multi = MultiProof::init(
            H256::from_str("0xee76a42a55cb9e1b3f54c5dbf382c683b9edaf7ee98886d81e5ecca3cfccea90")
                .unwrap(),
        );
        expected_multi
            .insert_proof(proof_str_to_vec(PROOF_KEY_8C87_POST.to_vec()))
            .unwrap();
        let expected_post = expected_multi.view(path).unwrap();
        if post != expected_post {
            println!("Expected{}\nGot{}", expected_post, post);
            panic!("Expected post proof != Post proof")
        };
    }
}
