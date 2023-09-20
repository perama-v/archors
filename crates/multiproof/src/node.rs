use archors_verify::path::{PathError, PrefixEncoding};
use thiserror::Error;

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

#[derive(Debug)]
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
