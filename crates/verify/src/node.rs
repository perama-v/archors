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
    #[error("Extension node has no next node")]
    ExtensionNodeNoNextNode,
    #[error("Extension node item expected to be 32 bytes")]
    ExtensionNextNodeInvalidLength,
    #[error("Merkle Patricia Node to have max 17 (16 + 1) items, got {0}")]
    InvalidNodeItemCount(usize),
    #[error("Unable to traverse next node in path, none present")]
    NoNodeToTraverse,
    #[error("Node has no items")]
    NodeEmpty,
    #[error("Node item has no encoding")]
    NoEncoding,
    #[error("Proof key does not contain data for a traversal path")]
    NoPath,
    #[error("Node has invalid item count")]
    NodeHasInvalidItemCount,
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
    #[error("Full 32 byte traversal should not end with an extension node")]
    TraversalEndsAtExtension,
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
    Branch,
    Extension,
    Leaf,
}

impl NodeKind {
    pub fn deduce(node: &[Vec<u8>]) -> Result<NodeKind, NodeError> {
        match node.len() {
            17 => Ok(NodeKind::Branch),
            2 => {
                // Leaf or extension
                let partial_path = node.first().ok_or(NodeError::NodeEmpty)?;
                let encoding = partial_path.first().ok_or(NodeError::NoEncoding)?;
                Ok(match PrefixEncoding::try_from(encoding)? {
                    PrefixEncoding::ExtensionEven | PrefixEncoding::ExtensionOdd(_) => {
                        NodeKind::Extension
                    }
                    PrefixEncoding::LeafEven | PrefixEncoding::LeafOdd(_) => NodeKind::Leaf,
                })
            }
            _ => Err(NodeError::NodeHasInvalidItemCount),
        }
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
                let final_item = node.get(16).ok_or(NodeError::BranchNodeHasNoValue)?;

                if !final_item.is_empty() {
                    return Err(NodeError::BranchNodeHasValue);
                }
                // Send back a new parent node
                let path_nibble = traversal
                    .visit_path_nibble()
                    .map_err(NodeError::PathError)?;

                let item = node
                    .get(path_nibble as usize)
                    .ok_or(NodeError::NoNodeToTraverse)?;
                if item.is_empty() {
                    return Ok(ProofType::BranchExclusion);
                }
                if item.len() != 32 {
                    return Err(NodeError::BranchNodeItemInvalidLength);
                }
                let next_root: [u8; 32] = H256::from_slice(item).into();
                *parent_root_to_update = next_root;
                Ok(ProofType::Pending)
            }
            NodeKind::Extension => {
                let extension = node.get(0).ok_or(NodeError::TerminalExtensionHasNoPath)?;
                let next_node = node
                    .get(1)
                    .ok_or(NodeError::TerminalExtensionHasNoNextNode)?;
                match traversal.match_or_mismatch(extension)? {
                    PathNature::SubPathMatches => {
                        // internal node
                        if next_node.is_empty() {
                            return Err(NodeError::ExtensionNodeNoNextNode);
                        }
                        traversal.skip_extension_node_nibbles(extension)?;
                        if next_node.len() != 32 {
                            return Err(NodeError::ExtensionNextNodeInvalidLength);
                        }
                        let next_root: [u8; 32] = H256::from_slice(next_node).into();
                        *parent_root_to_update = next_root;
                        Ok(ProofType::Pending)
                    }
                    PathNature::SubPathDiverges | PathNature::FullPathDiverges => {
                        Ok(ProofType::ExtensionExclusion)
                    }
                    PathNature::FullPathMatches => Err(NodeError::TraversalEndsAtExtension),
                }
            }
            NodeKind::Leaf => {
                let path = node.get(0).ok_or(NodeError::LeafHasNoPath)?;
                let value = node.get(1).ok_or(NodeError::LeafHasNoValue)?;
                match traversal.match_or_mismatch(path)? {
                    PathNature::SubPathMatches => Err(NodeError::LeafHasIncompletePath),
                    PathNature::FullPathMatches => Ok(ProofType::Inclusion(value.to_vec())),
                    PathNature::FullPathDiverges | PathNature::SubPathDiverges => {
                        // The node is a leaf, but not the leaf that matches the key.
                        // This means the trie cannot contain the key, otherwise this
                        // node would be a branch or extension. Hence it is an exclusion
                        // proof.
                        Ok(ProofType::LeafExclusion)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use ethers::types::U256;

    use crate::utils::hex_decode;

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
        let node_kind = NodeKind::deduce(&node).unwrap();
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

    // Not possible, when a slot value is set to zero, the key is removed.
    // Hence the proof will be an exclusion proof.
    #[test]
    fn test_placeholder_inclusion_leaf_for_zero_value() {}

    /// Storage proof, data from block 17190873 (./data/blocks/17190873/block_state_proofs.json).
    /// - account 0x0b09dea16768f0799065c475be02919503cb2a35
    /// - storage key: 0x495035048c903d5331ae820b52f7c4dc5ce81ee403640178e77c00a916ba54ab
    /// - path (keccak(key)): 0xcf1652a03292400cdc9040b230c7c8b9584f9903c1f4e2809fca09daa8670c8f
    /// - value: 0x4996c0f7e6d68f87940591181285a446222c413f8800d35d36f298b64544dd7
    ///
    /// four nodes:
    /// - branch, follow item 0xc
    /// - branch, follow item 0xf
    /// - branch, follow item 0x1
    /// - leaf node
    #[test]
    fn test_inclusion_leaf_for_nonzero_key() {
        let node = rlp_decode_node("0xf8429f3652a03292400cdc9040b230c7c8b9584f9903c1f4e2809fca09daa8670c8fa1a004996c0f7e6d68f87940591181285a446222c413f8800d35d36f298b64544dd7");
        let node_kind = NodeKind::deduce(&node).unwrap();
        assert_eq!(node_kind, NodeKind::Leaf);

        let mut traversal = NibblePath::init(
            &hex_decode("0xcf1652a03292400cdc9040b230c7c8b9584f9903c1f4e2809fca09daa8670c8f")
                .unwrap(),
        );
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xc);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xf);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x1);
        let mut parent_root_to_update = [0u8; 32];
        let leaf_rlp_bytes = node.last().unwrap().clone();
        let leaf_value: U256 = rlp::decode(&leaf_rlp_bytes).unwrap();
        let expected_leaf = U256::from_big_endian(
            &hex_decode("0x04996c0f7e6d68f87940591181285a446222c413f8800d35d36f298b64544dd7")
                .unwrap(),
        );
        assert_eq!(leaf_value, expected_leaf);
        let proof_type = node_kind
            .traverse_node(node, &mut traversal, &mut parent_root_to_update)
            .unwrap();
        assert_eq!(proof_type, ProofType::Inclusion(leaf_rlp_bytes));
    }

    /// Storage proof, data from block 17190873 (./data/blocks/17190873/block_state_proofs.json).
    /// - account 0xd1d1d4e36117ab794ec5d4c78cbd3a8904e691d0
    /// - Storage key: 0x0000000000000000000000000000000000000000000000000000000000000000
    /// - path (keccak(key)): 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
    ///
    /// three nodes:
    /// - branch, follow item 0x2
    /// - branch, follow item 0x9
    /// - leaf node
    #[test]
    fn test_inclusion_leaf_for_zero_key() {
        let node = rlp_decode_node("0xf7a0200decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594d9db270c1b5e3bd161e8c8503c55ceabee709552");
        let node_kind = NodeKind::deduce(&node).unwrap();
        assert_eq!(node_kind, NodeKind::Leaf);

        let mut traversal = NibblePath::init(
            &hex_decode("0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563")
                .unwrap(),
        );
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x2);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x9);
        let mut parent_root_to_update = [0u8; 32];
        let leaf_rlp_bytes = node.last().unwrap().clone();
        let leaf_value: U256 = rlp::decode(&leaf_rlp_bytes).unwrap();
        let expected_leaf = U256::from_big_endian(
            &hex_decode("0xd9db270c1b5e3bd161e8c8503c55ceabee709552").unwrap(),
        );
        assert_eq!(leaf_value, expected_leaf);
        let proof_type = node_kind
            .traverse_node(node, &mut traversal, &mut parent_root_to_update)
            .unwrap();
        assert_eq!(proof_type, ProofType::Inclusion(leaf_rlp_bytes));
    }

    /// Storage proof, data from block 17190873 (./data/blocks/17190873/block_state_proofs.json).
    /// - account 0x2d7c6b69175c2939173f2fd470538835336df92b
    /// - Storage key: 0xbbca5b315e4cd362c7283dfcb09024ec2929d27b75662a398e5013a2368ad895
    /// - path (keccak(key)): 0x3cb0e7d0c9bc2b22094c3207040a4579513a0ed633e3019949f14610d67e15f5
    ///
    /// four nodes:
    /// - 1 branch, follow item 0x3
    /// - 1 terminal branch, hence exclusion proof.
    #[test]
    fn test_exclusion_branch_for_nonzero_key() {
        let node = rlp_decode_node("0xf891a097d37274c14dc79a9874f3387ef34e7dbfbbed0fb3caf668d57323f7fb152f79808080808080a0e05bb037e849d9733f2b57d5132f96c57eb2eca763a5ebbb53f52f88c4cd7abb8080808080a0f9dd0c1cfce2ce11694839a45f4beb3d5ac9af39ddd9949075c6be1223373a0ca0c7219989da6535f0fbaf34d9633adde100c81c6f3efd0b9a423fa4886245fa8c8080");
        let node_kind = NodeKind::deduce(&node).unwrap();
        assert_eq!(node_kind, NodeKind::Branch);

        let mut traversal = NibblePath::init(
            &hex_decode("0x3cb0e7d0c9bc2b22094c3207040a4579513a0ed633e3019949f14610d67e15f5")
                .unwrap(),
        );
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x3);
        let mut parent_root_to_update = [0u8; 32];
        assert_eq!(
            node_kind
                .traverse_node(node, &mut traversal, &mut parent_root_to_update)
                .unwrap(),
            ProofType::BranchExclusion
        );
    }

    /// Storage proof, data from block 17190873 (./data/blocks/17190873/block_state_proofs.json).
    /// - account: 0x479d94c2957ffc16cb710fd2f5adbbde999e46bd
    /// - Storage key: 0x0000000000000000000000000000000000000000000000000000000000000000
    /// - path (keccak(key)): 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
    /// - value: 0x0
    ///
    /// four nodes:
    /// - 1 branch, follow item 0x2
    /// - 1 terminal branch, hence exclusion proof.
    #[test]
    fn test_exclusion_branch_for_zero_key() {
        let node = rlp_decode_node("0xf901118080808080a00b1cd5a23994bc2aea49ae88d628bdfe9b4efb2b87a823094a83ed0e0fa013bc80a01b220b26c51916acd02c2e8492d76003c4f2d74b5575714846605cbe357155d68080a0162982546a8dcdc8b71661334851a2079867db4ac1bb2ec791921f8d16fa0a99a00113760f61a3340446e68233b923cc182d5584458f94217d68dde49e2d139dcaa0807b72d3c3a055ecb79ccf06c3234e6c17160bc96434dc5db4e8e1407c73e1aaa0340143d8c4052b29a57a409dcfce54ee187249048d5187a8ed8d79fb89cccce1a09809d25b91a2d1af6ff54188188bc056f9cf37ff28ed3d48ddd3fcc2c13a90d2a0dbba79570a67cf63a829507cf3cb03ead958cb4df306c12807001387b29e227c80");
        let node_kind = NodeKind::deduce(&node).unwrap();
        assert_eq!(node_kind, NodeKind::Branch);

        let mut traversal = NibblePath::init(
            &hex_decode("0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563")
                .unwrap(),
        );
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x2);
        let mut parent_root_to_update = [0u8; 32];
        assert_eq!(
            node_kind
                .traverse_node(node, &mut traversal, &mut parent_root_to_update)
                .unwrap(),
            ProofType::BranchExclusion
        );
    }
    /// Storage proof, data from block 17190873 (./data/blocks/17190873/block_state_proofs.json).
    /// - account: 0x8025d6c18807c4ff46f316c1942462b907119c7e
    /// - Storage key: 0x69b38bc029784d7648153a84fe06a4d9b6af2633f64c92edf3acad38a490e394
    /// - path (keccak(key)): 0x1d3fa00abc7274427888892f57a97452e67990a28f3235a5e1b84087ca40feca
    /// - value: 0x0
    ///
    /// 3 nodes:
    /// - 1 branch node, follow item: 0x1
    /// - 1 branch node, follow item: 0xd
    /// - 1 terminal extension node, hence exclusion proof.
    #[test]
    fn test_exclusion_extension_for_nonzero_key() {
        let node = rlp_decode_node(
            "0xe210a0c01ed7b75d88d88add6ef9744c598fff626eac250bc209e6b4d11069e93aefb8",
        );
        let node_kind = NodeKind::deduce(&node).unwrap();
        assert_eq!(node_kind, NodeKind::Extension);

        let mut traversal = NibblePath::init(
            &hex_decode("0x1d3fa00abc7274427888892f57a97452e67990a28f3235a5e1b84087ca40feca")
                .unwrap(),
        );
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x1);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xd);
        let mut parent_root_to_update = [0u8; 32];
        assert_eq!(
            node_kind
                .traverse_node(node, &mut traversal, &mut parent_root_to_update)
                .unwrap(),
            ProofType::ExtensionExclusion
        );
    }

    /// Storage proof, data from block 17190873 (./data/blocks/17190873/block_state_proofs.json).
    /// - account 0x31c8eacbffdd875c74b94b077895bd78cf1e64a3
    /// - Storage key: 0xfdf207d061b788649c2be9e4947993c2dbda042b15d4b3787a83f8c953f184ad
    /// - path (keccak(key)): 0x471575b583caee1d6f3b74e138773e8c0c9f6eed2de061ddd7e6002245c15102
    ///
    /// four nodes:
    /// - 4 branches, follow items 0x- 4, 7, 1, 5
    /// - leaf node with items:
    ///     - 0: even leaf with path b489b5172060021855f062689a1668509fb781aaf0baad0a7c3a6f413f36
    ///         - Completely different path (next nibble should be 0x7)
    ///     - 1: value 0x880de0b6b3a7640000
    ///         - Completely different value (claimed value accompanying proof is 0x0)
    #[test]
    fn test_exclusion_leaf_for_nonzero_key() {
        let node = rlp_decode_node("0xea9f20b489b5172060021855f062689a1668509fb781aaf0baad0a7c3a6f413f3689880de0b6b3a7640000");
        let node_kind = NodeKind::deduce(&node).unwrap();
        assert_eq!(node_kind, NodeKind::Leaf);

        let mut traversal = NibblePath::init(
            &hex_decode("0x471575b583caee1d6f3b74e138773e8c0c9f6eed2de061ddd7e6002245c15102")
                .unwrap(),
        );
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x4);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x7);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x1);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x5);
        let mut parent_root_to_update = [0u8; 32];
        assert_eq!(
            node_kind
                .traverse_node(node, &mut traversal, &mut parent_root_to_update)
                .unwrap(),
            ProofType::LeafExclusion
        );
    }

    /// Storage proof, data from block 17190873 (./data/blocks/17190873/block_state_proofs.json).
    /// - account: 0xe01eaa990bedc239c2adf5a48352112f6a305bc0
    /// - Storage key: 0x0000000000000000000000000000000000000000000000000000000000000000
    /// - path (keccak(key)): 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
    /// - value: 0x0
    ///
    /// 2 nodes:
    /// - 2 branches, follow item 0x2 then item 0x9
    /// - leaf node with items:
    ///     - 0: even leaf with path 0x9c4f2ccf4dc398566b26d9d52e0b3f485b3554f10e0aa29c4491e7fdd99584
    ///         - Completely different path (next nibble should be 0x0)
    ///     - 1: value 0x8401064fbe
    ///         - Completely different value (claimed value accompanying proof is 0x0)
    #[test]
    fn test_exclusion_leaf_for_zero_key() {
        let node = rlp_decode_node(
            "0xe7a0209c4f2ccf4dc398566b26d9d52e0b3f485b3554f10e0aa29c4491e7fdd99584858401064fbe",
        );
        let node_kind = NodeKind::deduce(&node).unwrap();
        assert_eq!(node_kind, NodeKind::Leaf);

        let mut traversal = NibblePath::init(
            &hex_decode("0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563")
                .unwrap(),
        );
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x2);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0x9);
        let mut parent_root_to_update = [0u8; 32];
        assert_eq!(
            node_kind
                .traverse_node(node, &mut traversal, &mut parent_root_to_update)
                .unwrap(),
            ProofType::LeafExclusion
        );
    }
}
