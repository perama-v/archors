//! For processing a node in a Merkle PATRICIA Trie proof.
use ethers::types::H256;
use thiserror::Error;

use crate::{
    path::{NibblePath, PathError, PathNature, PrefixEncoding},
    proof::ProofType,
};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum NodeError {
    #[error("Branch node (non-terminal) expected to be empty")]
    BranchNodeHasValue,
    #[error("Branch node (non-terminal) has less than 17 items")]
    BranchNodeHasNoValue,
    #[error("Branch node item expected to be 32 bytes")]
    BranchNodeItemInvalidLength,
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
    #[error("Leaf node has no value")]
    LeafHasNoValue,
    #[error("Leaf node expected to have a final path, found none")]
    LeafHasNoPath,
    #[error("Leaf node must complete the 32 byte path")]
    LeafHasIncompletePath,
    #[error("VerificationError {0}")]
    VerificationError(String),
}

/// Description of node in a merkle proof.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    /// Visits the relevant part of a node and checks values are as expected.
    ///
    /// This may involve progressing the path traversal or making a determination about
    /// the proof kind if the final node is reached.
    ///
    /// If an intermediate node, returns the hash that is now the parent for the next node.
    /// A node is a vector of items (bytes representing one of path/hash/rlp_value)
    pub fn traverse_node(
        &self,
        node: Vec<Vec<u8>>,
        traversal: &mut NibblePath,
        parent_root_to_update: &mut [u8; 32],
    ) -> Result<ProofType, NodeError> {
        match self {
            NodeKind::Branch => {
                // Assert value item is empty (not terminal).
                let final_item = node
                    .get(16)
                    .ok_or_else(|| NodeError::BranchNodeHasNoValue)?;

                if !final_item.is_empty() {
                    return Err(NodeError::BranchNodeHasValue);
                }
                // Send back a new parent node
                let path_nibble = traversal
                    .visit_path_nibble()
                    .map_err(NodeError::PathError)?;

                let item = node
                    .get(path_nibble as usize)
                    .ok_or_else(|| NodeError::NoNodeToTraverse)?;
                if item.len() != 32 {
                    return Err(NodeError::BranchNodeItemInvalidLength);
                }
                let next_root: [u8; 32] = H256::from_slice(&item).into();
                *parent_root_to_update = next_root;
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
                *parent_root_to_update = next_root;
                Ok(ProofType::Pending)
            }
            NodeKind::TerminalBranch => {
                // An exclusion proof

                // Assert value item is Some(empty_list) (terminal).
                let value = node
                    .get(16)
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
                    PathNature::SubPathDiverges => {
                        if second_item.is_empty() {
                            todo!("Even in an exclusion proof, shouldn't there be a next node?")
                            // return Err(NodeError::ExclusionProofNodeHasNoNextNode);
                        }
                        Ok(ProofType::Exclusion)
                    }
                    PathNature::FullPathMatches | PathNature::FullPathDiverges => {
                        return Err(NodeError::TerminalExtensionHasFullPath)
                    }
                }
            }
            NodeKind::Leaf => {
                let first_item = node.get(0).ok_or_else(|| NodeError::LeafHasNoPath)?;
                let second_item = node.get(1).ok_or_else(|| NodeError::LeafHasNoValue)?;
                match traversal.match_or_mismatch(first_item)? {
                    PathNature::SubPathMatches | PathNature::SubPathDiverges => {
                        Err(NodeError::LeafHasIncompletePath)
                    }
                    PathNature::FullPathMatches => {
                        if second_item.is_empty() {
                            todo!("an inclusion proof cannot have empty leaf value")
                        }
                        Ok(ProofType::Inclusion(second_item.to_vec()))
                    }
                    PathNature::FullPathDiverges => {
                        todo!("Err, this is an inclusion proof for different key")
                    }
                }
            }
        }
    }
}

mod test {
    use crate::utils::{hex_decode, hex_encode};

    use super::*;

    fn rlp_decode_node(node: &str) -> Vec<Vec<u8>> {
        let bytes = hex_decode(node).unwrap();
        rlp::decode_list(&bytes)
    }

    /// Checks the final node in an account inclusion proof.
    /// - src: account proof from ./data/test_proof_1.json
    /// - account address: 0xaa00000000000000000000000000000000000000
    /// - path (keccak(address)): 0x735649db80be637d281db0cc5896b0ff9869d08379a80fdc38dd073bba633949
    ///
    /// Two nodes:
    /// - First node is extension node, item index 7 is traversed.
    /// - Second node is leaf node with remaining full path, hence inclusion proof.
    #[test]
    fn test_inclusion_leaf_for_nonzero_value() {
        let node = rlp_decode_node("0xf869a0335649db80be637d281db0cc5896b0ff9869d08379a80fdc38dd073bba633949b846f8440101a08afc95b7d18a226944b9c2070b6bda1c3a36afcc3730429d47579c94b9fe5850a0ce92c756baff35fa740c3557c1a971fd24d2d35b7c8e067880d50cd86bb0bc99");
        let node_kind = NodeKind::deduce(1, 2, 2, &node).unwrap();
        assert_eq!(node_kind, NodeKind::Leaf);

        let mut traversal = NibblePath::init(
            &hex_decode("0x735649db80be637d281db0cc5896b0ff9869d08379a80fdc38dd073bba633949")
                .unwrap(),
        );
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x7);
        let mut parent_root_to_update = [0u8; 32];
        node_kind
            .traverse_node(node, &mut traversal, &mut parent_root_to_update)
            .unwrap();
    }
    #[test]
    fn test_inclusion_leaf_for_zero_value() {
        todo!()
    }
    /// Storage proof, data from block 17190873.
    /// - account 0x0b09dea16768f0799065c475be02919503cb2a35
    /// - Storage key: 0x495035048c903d5331ae820b52f7c4dc5ce81ee403640178e77c00a916ba54ab
    /// - path (keccak(key)): 0xcf1652a03292400cdc9040b230c7c8b9584f9903c1f4e2809fca09daa8670c8f
    ///
    /// four nodes:
    /// - branch, follow item 0xc
    /// - branch, follow item 0xf
    /// - branch, follow item 0x1
    /// - leaf node
    #[test]
    fn test_inclusion_leaf_for_nonzero_key() {
        let node = rlp_decode_node("0xf8429f3652a03292400cdc9040b230c7c8b9584f9903c1f4e2809fca09daa8670c8fa1a004996c0f7e6d68f87940591181285a446222c413f8800d35d36f298b64544dd7");
        let node_kind = NodeKind::deduce(3, 4, 2, &node).unwrap();
        assert_eq!(node_kind, NodeKind::Leaf);

        let mut traversal = NibblePath::init(
            &hex_decode("0xcf1652a03292400cdc9040b230c7c8b9584f9903c1f4e2809fca09daa8670c8f")
                .unwrap(),
        );
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xc);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xf);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x1);
        let mut parent_root_to_update = [0u8; 32];
        node_kind
            .traverse_node(node, &mut traversal, &mut parent_root_to_update)
            .unwrap();
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
