use std::fmt::Display;

use archors_verify::path::{PathError, PrefixEncoding, NibblePath};
use ethers::types::H256;
use thiserror::Error;

use crate::utils::hex_encode;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("Node has no items")]
    NodeEmpty,
    #[error("Node item has no encoding")]
    NoEncoding,
    #[error("PathError {0}")]
    PathError(#[from] PathError),
    #[error("Node has invalid item count {0}")]
    NodeHasInvalidItemCount(usize),
}

#[derive(Debug, PartialEq)]
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
            num @ _ => Err(NodeError::NodeHasInvalidItemCount(num)),
        }
    }
}


/// A cache of the nodes visited. If the trie is modified, then
/// this can be used to update hashes back to the root.
#[derive(Debug)]
pub struct VisitedNode {
    pub kind: NodeKind,
    pub node_hash: H256,
    /// Item within the node that was followed to get to the next node.
    pub item_index: usize,
    /// The path that was followed to get to the node.
    ///
    /// This allows new nodes to be added/removed as needed during proof modification.
    pub traversal_record: NibblePath,
}

impl Display for VisitedNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Visited {:?} node (hash: {}), followed index {} in node",
            self.kind,
            hex_encode(self.node_hash),
            self.item_index
        )
    }
}
