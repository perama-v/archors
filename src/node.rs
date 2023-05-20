//! For processing a node in a Merkle PATRICIA Trie proof.
use ethers::types::H256;
use thiserror::Error;

use crate::{
    path::{NibblePath, PathError},
    proof::ProofType,
};

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("Branch node (non-terminal) has value, expected none")]
    BranchNodeHasValue,
    #[error("Branch node item expected to be 32 bytes")]
    BranchNodeItemInvalidLength,
    #[error("Terminal extension/leaf node is exclusion proof, but has a non-empty final item")]
    ExclusionProofNodeHasValue,
    #[error("Extension node (non-terminal) has no path extension")]
    ExtensionNodeHasValue,
    #[error("Extension node item expected to be 32 bytes")]
    ExtensionNextNodeInvalidLength,
    #[error("Merkle Patricia Node to have max 17 (16 + 1) items, got {0}")]
    InvalidNodeItemCount(usize),
    #[error("Unable to traverse next node in path, none present")]
    NoNodeToTraverse,
    #[error("Proof key does not contain data for a traversal path")]
    NoPath,
    #[error("Trie path error {0}")]
    PathError(#[from] PathError),
    #[error("Path expected to be 32 bytes")]
    PathTooLong,
    #[error("Terminal branch node expected to have an empty final value, found none")]
    TerminalBranchNodeHasNoValue,
    #[error("Branch node (terminal) has value, expected none")]
    TerminalBranchNodeHasValue,
    #[error("Terminal extension or leaf node has no first item")]
    TerminalExtensionOrLeafHasNoItem,
    #[error("Terminal extension/leaf node expected to have a final path, found none")]
    TerminalExtensionOrLeafHasNoPath,
    #[error("VerificationError {0}")]
    VerificationError(String),
}

/// Description of node in a merkle proof.
pub enum NodeKind {
    // 17 items, not at end
    Branch,
    // 2 items, not at end
    Extension,
    // 17 items and is at end
    TerminalBranch,
    // 2 items, and is at end
    TerminalExtensionOrLeaf,
}

impl NodeKind {
    /// For a merkle patricia proof consisting of nodes, determines the nature
    /// of the node at a particular index.
    pub fn deduce(
        node_index: usize,
        node_total: usize,
        items_in_node: usize,
    ) -> Result<Self, NodeError> {
        let terminal = node_index == node_total - 1;
        let kind = match (terminal, items_in_node) {
            (true, 2) => NodeKind::TerminalExtensionOrLeaf,
            (false, 2) => NodeKind::Extension,
            (true, 17) => NodeKind::TerminalBranch,
            (false, 17) => NodeKind::Branch,
            (_, count @ _) => return Err(NodeError::InvalidNodeItemCount(count)),
        };
        Ok(kind)
    }
    /// Checks that a particular item of a node is valid.
    ///
    /// If an intermediate node, returns the hash that is now the parent for the next node.
    pub fn check_contents(
        &self,
        node: Vec<Vec<u8>>,
        item_index: usize,
        traversal: &mut NibblePath,
        parent_root: &mut [u8; 32],
    ) -> Result<ProofType, NodeError> {
        match self {
            NodeKind::Branch => {
                // Assert value item is None (not terminal).
                if node.get(17).is_some() {
                    return Err(NodeError::BranchNodeHasValue);
                }
                // Send back a new parent node
                let item = node
                    .get(item_index)
                    .ok_or_else(|| NodeError::NoNodeToTraverse)?;
                if item.len() != 32 {
                    return Err(NodeError::BranchNodeItemInvalidLength);
                }
                let next_root: [u8; 32] = H256::from_slice(&item).into();
                *parent_root = next_root;
                Ok(ProofType::Pending)
            }
            NodeKind::Extension => {
                let extension = match node.get(0) {
                    Some(path) => {
                        if path.len() == 32 {
                            return Err(NodeError::PathTooLong);
                        }
                        path
                    }
                    None => return Err(NodeError::ExtensionNodeHasValue),
                };
                traversal.skip_extension_node_nibbles(extension)?;

                // Send back a new parent node
                let item = node.get(1).ok_or_else(|| NodeError::NoNodeToTraverse)?;
                if item.len() != 32 {
                    return Err(NodeError::ExtensionNextNodeInvalidLength);
                }
                let next_root: [u8; 32] = H256::from_slice(&item).into();
                *parent_root = next_root;
                Ok(ProofType::Pending)
            }
            NodeKind::TerminalBranch => {
                // An exclusion proof

                // Assert value item is Some(empty_list) (terminal).
                let value = node
                    .get(17)
                    .ok_or_else(|| NodeError::TerminalBranchNodeHasNoValue)?;
                if value.is_empty() {
                    return Ok(ProofType::Exclusion);
                }
                return Err(NodeError::TerminalBranchNodeHasValue);
            }
            NodeKind::TerminalExtensionOrLeaf => {
                // Decode the nibble and get the type.
                let first_item = node
                    .get(0)
                    .ok_or_else(|| NodeError::TerminalExtensionOrLeafHasNoPath)?;

                let second_item = node
                    .get(1)
                    .ok_or_else(|| NodeError::TerminalExtensionOrLeafHasNoItem)?;
                match traversal.is_inclusion_proof(first_item) {
                    true => Ok(ProofType::Inclusion(second_item.to_vec())),
                    false => {
                        if second_item.is_empty() {
                            return Ok(ProofType::Exclusion);
                        }
                        return Err(NodeError::ExclusionProofNodeHasValue);
                    }
                }
            }
        }
    }
}
