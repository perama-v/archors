//! For verifying a Merkle Patricia Multi Proof for arbitrary proof values.
//! E.g., Account, storage ...

use std::{collections::HashMap, fmt::Display};

use archors_types::{
    oracle::{OracleTarget, TrieNodeOracle},
    proof::DisplayProof,
};
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
use log::debug;
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
    #[error("PathError {0}")]
    PathError(#[from] PathError),
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
    #[error(
        "NoNodeInOracle: The oracle was expected to have a node for address {address} key {key}"
    )]
    NoNodeInOracle { address: String, key: String },
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
    /// Node updates that need an oracle to be completed.
    pub oracle_task: Option<OracleTask>,
}

pub enum ProofOutcome {
    Root(H256),
    Task(OracleTask),
}

impl MultiProof {
    /// Create new multiproof with a known root.
    pub fn init(root: H256) -> Self {
        MultiProof {
            data: HashMap::default(),
            root,
            oracle_task: None,
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
    /// Traverse a path in the multiproof.
    ///
    /// May either be to update the value or to verify. A task may be returned if information
    /// form an oracle is required.
    ///
    /// The path preimage is passed so that when a node oracle is required, the oracle task
    /// can be made. This applies to storage proofs only, which can be removed from the trie.
    pub fn traverse(
        &mut self,
        path: H256,
        oracle_target: Option<OracleTarget>,
        intent: &Intent,
    ) -> Result<(), ProofError> {
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
                                None,
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
                                None,
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
                    let traversal_status = traversal.match_or_mismatch(final_subpath)?;
                    match (traversal_status, intent) {
                        (SubPathMatches | SubPathDiverges(_), _) => {
                            return Err(ProofError::LeafPathIncomplete)
                        }
                        (FullPathMatches, Intent::Modify(new_value)) => {
                            self.apply_changes(
                                None,
                                Change::LeafInclusionModify(new_value.clone()),
                                &visited_nodes,
                            )?;
                            return Ok(());
                        }
                        (FullPathMatches, Intent::VerifyExclusion) => {
                            return Err(ProofError::ExclusionRequired)
                        }
                        (FullPathMatches, Intent::Remove) => {
                            self.apply_changes(
                                oracle_target,
                                Change::LeafInclusionToExclusion,
                                &visited_nodes,
                            )?;
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
                                None,
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
                    let item_index = traversal.visit_path_nibble()? as usize;
                    let item = next_node
                        .get(item_index)
                        .ok_or(ProofError::BranchItemMissing)?;
                    let traversal_record = traversal.clone();
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
        // Traverse the oracle. Start near root, follow path toward leaves.
        let oracle_node = oracle.lookup_node(task.address, task.key).ok_or_else(|| {
            ProofError::NoNodeInOracle {
                address: hex_encode(task.address),
                key: hex_encode(task.key),
            }
        })?;
        let oracle_node_hash = keccak256(oracle_node);

        // The first update is to a node whose child is now the oracle-based node.
        let mut updated_hash = oracle_node_hash;
        // Update all the nodes that were traversed to get to the updated node.
        for outdated in visited_nodes.iter().rev() {
            updated_hash = self.update_node_with_child_hash(outdated, &updated_hash)?;
        }
        // Update the storage root.
        debug!("storage root updated via oracle to {}", hex_encode(updated_hash));
        self.root = updated_hash.into();
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
        oracle_target: Option<OracleTarget>,
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
                let (highest_hash, nodes_processed) =
                    self.process_leaf_child_removal(oracle_target, visited)?;

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
        oracle_target: Option<OracleTarget>,
        visit_record: &[VisitedNode],
    ) -> Result<([u8; 32], usize), ModifyError> {
        if visit_record.len() == 1 {
            todo!("handle modification when no grandparent exists");
        }
        let target = match oracle_target {
            Some(t) => t,
            None => todo!("return error: Must have passed a storage key that is being removed."),
        };

        let leaf_index = visit_record.len() - 1;
        let parent_index = leaf_index - 1;
        let grandparent_index = parent_index - 1;

        let parent = visit_record
            .get(parent_index)
            .ok_or(ModifyError::NoVisitedNode)?;
        let outdated_rlp = self
            .data
            .get(&parent.node_hash)
            .ok_or(ModifyError::NoNodeForHash)?;
        let outdated_node: Vec<Vec<u8>> = rlp::decode_list(&outdated_rlp);

        if parent.kind != NodeKind::Branch {
            todo!("Error: Remove leaf child called on non-branch node.")
        }

        // [next_node_0, ..., next_node_16, value]
        let mut updated = Node::default();
        let mut item_count = 0;
        let mut non_empty_child_index = 0;
        // Find where the orphaned sibling leaf belongs in the branch.
        for (index, item) in outdated_node.into_iter().enumerate() {
            if index == parent.item_index {
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
            0 => todo!("error, not possible"), // Branch should have at least one item.
            1 => {
                // The parent is a branch node for deletion (too few items).
                // This may require oracle knowledge, so it is returned as a task.

                // Need to attach this single item at some point.
                let visited_grandparent = visit_record
                    .get(grandparent_index)
                    .ok_or(ModifyError::NoVisitedNode)?;

                self.oracle_task = Some(OracleTask::new(
                    target.address,
                    target.key,
                    visited_grandparent,
                ));
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
}
