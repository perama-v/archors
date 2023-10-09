use std::fmt::Display;

use crate::utils::hex_encode;

/// A display helper type for storage proofs. Contains of account proof that secures
/// the storage.
#[derive(Debug, Clone, PartialEq)]
pub struct DisplayStorageProof {
    pub account: DisplayProof,
    pub storage: DisplayProof,
}

impl Display for DisplayStorageProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Account proof:{}Storage proof:{}",
            self.account, self.storage
        )
    }
}

/// A display helper type for proofs.
///
/// Proofs consists of a vector of nodes, where nodes are vectors of rlp-encoded bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct DisplayProof(Vec<Vec<u8>>);

impl DisplayProof {
    pub fn init(proof: Vec<Vec<u8>>) -> Self {
        Self(proof)
    }
    /// Returns true if the proofs have a different final node.
    pub fn different_final_node(&self, second_proof: &DisplayProof) -> bool {
        self.0.last() != second_proof.0.last()
    }
    /// Returns the node index where two proofs differ. The root is checked last.
    pub fn divergence_point(&self, second_proof: &DisplayProof) -> Option<usize> {
        for i in (0..self.0.len()).rev() {
            if self.0.get(i) != second_proof.0.get(i) {
                return Some(i);
            }
        }
        None
    }
    /// Return the proof data.
    pub fn inner(&self) -> &[Vec<u8>] {
        &self.0
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
