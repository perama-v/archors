//! For processing a node in a Merkle PATRICIA Trie proof.
use ethers::types::H256;
use thiserror::Error;

use crate::{
    path::{NibblePath, PathError, PathNature, PrefixEncoding},
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
    #[error("Terminal extension node has no next node")]
    TerminalExtensionHasNoNextNode,
    #[error("Terminal extension node expected to have a final path, found none")]
    TerminalExtensionHasNoPath,
    #[error("Terminal extension node completes the 32 byte path, only leaf can do this")]
    TerminalExtensionHasFullPath,
    #[error("Terminal extension/leaf node expected to have a final path, found none")]
    TerminalExtensionOrLeafHasNoPath,
    #[error("Terminal leaf node has no value")]
    TerminalLeafHasNoValue,
    #[error("Terminal leaf node expected to have a final path, found none")]
    TerminalLeafHasNoPath,
    #[error("Terminal leaf node must complete the 32 byte path")]
    TerminalLeafHasIncompletePath,
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
    // 2 items, and is at end, path encoding indicates extension
    TerminalExtension,
    // 2 items, and is at end, path encoding indicates leaf
    Leaf,
}

impl NodeKind {
    /// For a merkle patricia proof consisting of nodes, determines the nature
    /// of the node at a particular index.
    pub fn deduce(
        node_index: usize,
        node_total: usize,
        items_in_node: usize,
        node: &[Vec<u8>],
    ) -> Result<Self, NodeError> {
        let terminal = node_index == node_total - 1;
        let kind = match (terminal, items_in_node) {
            (true, 2) => {
                let path: &[u8] = node
                    .get(0)
                    .ok_or_else(|| NodeError::TerminalExtensionOrLeafHasNoPath)?;
                let encoding = PrefixEncoding::try_from(path)?;
                match encoding {
                    PrefixEncoding::ExtensionEven | PrefixEncoding::ExtensionOdd(_) => {
                        NodeKind::TerminalExtension
                    }
                    PrefixEncoding::LeafEven | PrefixEncoding::LeafOdd(_) => NodeKind::Leaf,
                }
            }
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
    /// A node is a vector of items (bytes representing one of path/hash/rlp_value)
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
            NodeKind::TerminalExtension => {
                let first_item = node
                    .get(0)
                    .ok_or_else(|| NodeError::TerminalExtensionHasNoPath)?;
                let second_item = node
                    .get(1)
                    .ok_or_else(|| NodeError::TerminalExtensionHasNoNextNode)?;
                match traversal.match_or_mismatch(first_item)? {
                    PathNature::SubPathMatches => {
                        // exclusion proof. key shares some path with this node but diverges later so this is the latest relevant node
                        if second_item.is_empty() {
                            todo!("Even in an exclusion proof, shouldn't there be a next node?")
                            // return Err(NodeError::ExclusionProofNodeHasNoNextNode);
                        }
                        Ok(ProofType::Exclusion)
                    }
                    PathNature::SubPathDivergent => {
                        if second_item.is_empty() {
                            todo!("Even in an exclusion proof, shouldn't there be a next node?")
                            // return Err(NodeError::ExclusionProofNodeHasNoNextNode);
                        }
                        Ok(ProofType::Exclusion)
                    }
                    PathNature::FullPathMatches | PathNature::FullPathDivergent => {
                        return Err(NodeError::TerminalExtensionHasFullPath)
                    }
                }
            }
            NodeKind::Leaf => {
                let first_item = node
                    .get(0)
                    .ok_or_else(|| NodeError::TerminalLeafHasNoPath)?;
                let second_item = node
                    .get(1)
                    .ok_or_else(|| NodeError::TerminalLeafHasNoValue)?;
                match traversal.match_or_mismatch(first_item)? {
                    PathNature::SubPathMatches | PathNature::SubPathDivergent => {
                        Err(NodeError::TerminalLeafHasIncompletePath)
                    }
                    PathNature::FullPathMatches => {
                        if second_item.is_empty() {
                            todo!("an inclusion proof cannot have empty leaf value")
                        }
                        Ok(ProofType::Inclusion(second_item.to_vec()))
                    }
                    PathNature::FullPathDivergent => {
                        todo!("Err, this is an inclusion proof for different key")
                    }
                }
            }
        }
    }
}

mod test {
    #[test]
    fn test_inclusion_leaf_for_nonzero_value() {
        todo!()
    }
    #[test]
    fn test_inclusion_leaf_for_zero_value() {
        todo!()
    }
    #[test]
    fn test_inclusion_leaf_for_nonzero_key() {
        todo!()
    }
    #[test]
    fn test_inclusion_leaf_for_zero_key() {
        todo!()
    }
    #[test]
    fn test_exclusion_branch_for_nonzero_key() {
        todo!()
    }
    #[test]
    fn test_exclusion_branch_for_zero_key() {
        todo!()
    }
    #[test]
    fn test_exclusion_extension_for_nonzero_key() {
        todo!()
    }
    #[test]
    fn test_exclusion_extension_for_zero_key() {
        todo!()
    }
}
