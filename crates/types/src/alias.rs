//! Useful Simple Serialize (SSZ) aliases

use ssz_rs::{List, Vector};

// Variable (uint)
/// U64 equivalent
pub type SszU64 = List<u8, 8>;
/// U256 equivalent
pub type SszU256 = List<u8, 32>;

// Fixed (hash, address)
/// H256 Equivalent
pub type SszH256 = Vector<u8, 32>;
/// H160 Equivalent
pub type SszH160 = Vector<u8, 20>;
