//! For representing state for an historical block.

use std::collections::HashMap;

use ethers::types::{EIP1186ProofResponse, H160};
use serde::{Deserialize, Serialize};

/// Properties that state representation must have.
///
/// This is useful if there is a more efficient way to represent
/// state compared to unmodified EIP-1186 response, which has duplicate
/// data.
trait BlockState {
    /// Get a value for a storage key.
    fn read_key() {}
    /// Modify a value for a storage key.
    fn write_key() {}
}

/// Helper for caching
#[derive(Deserialize, Serialize)]
pub struct BlockProofs {
    /// Map of account -> proof
    pub proofs: HashMap<H160, EIP1186ProofResponse>,
}

impl BlockState for BlockProofs {
    fn read_key() {}

    fn write_key() {}
}
