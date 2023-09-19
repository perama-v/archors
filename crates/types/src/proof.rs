use std::fmt::Display;

use crate::utils::hex_encode;


/// A display helper type for storage proofs. Contains of account proof that secures
/// the storage.
#[derive(Debug, Clone, PartialEq)]
pub struct DisplayStorageProof{
    pub account: DisplayProof,
    pub storage: DisplayProof
}

impl Display for DisplayStorageProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Account proof:{}Storage proof:{}", self.account, self.storage)
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
