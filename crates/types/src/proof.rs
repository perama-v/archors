use std::fmt::Display;

use crate::utils::hex_encode;

/// A display helper type for proofs.
///
/// Proofs consists of a vector of nodes, where nodes are vectors of rlp-encoded bytes.
pub struct DisplayProof(Vec<Vec<u8>>);

impl DisplayProof {
    pub fn init(proof: Vec<Vec<u8>>) -> Self {
        Self(proof)
    }
}

impl Display for DisplayProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\n----begin proof----\n")?;
        for node in &self.0 {
            write!(f, "\n{}\n", hex_encode(&node))?;
        }
        write!(f, "\n----end proof----\n")?;
        Ok(())
    }
}
