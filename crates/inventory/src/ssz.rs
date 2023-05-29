//! For Simple Serialize (SSZ) related convenience aliases and constants.

pub mod constants {

    /// Maximum number of intermediate nodes permitted for all account proofs.
    /// Proofs are for the execution of a single block. Set to 2**15.
    pub const MAX_ACCOUNT_NODES_PER_BLOCK: usize = 32768;

    /// Maximum number of bytes permitted for an RLP encoded trie node. Set to 2**15.
    pub const MAX_BYTES_PER_NODE: usize = 32768;

    /// Maximum number of bytes a contract bytecode is permitted to be. Set to 2**15.
    pub const MAX_BYTES_PER_CONTRACT: usize = 32768;

    /// Maximum number of contract that can be accessed in a block. Set to 2**11.
    pub const MAX_CONTRACTS_PER_BLOCK: usize = 2048;

    /// Maximum number of nodes permitted in a merkle patricia proof. Set to 2**6.
    pub const MAX_NODES_PER_PROOF: usize = 64;

    /// Maximum number of intermediate nodes permitted for all storage proofs.
    /// Proofs are for the execution of a single block. Set to 2**15.
    pub const MAX_STORAGE_NODES_PER_BLOCK: usize = 32768;

    /// Maximum number of account proofs permitted. Proofs are for the execution
    /// of a single block. Set to 2**13.
    pub const MAX_ACCOUNT_PROOFS_PER_BLOCK: usize = 8192;

    /// Maximum number of storage proofs permitted per account.
    /// Proofs are for the execution of a single block. Set to 2**13.
    pub const MAX_STORAGE_PROOFS_PER_ACCOUNT: usize = 8192;
}

pub mod types {
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
}
