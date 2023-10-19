//! Useful Simple Serialize (SSZ) constants


/// Number of prior blockhashes a block could access via the BLOCKHASH opcode.
pub const MAX_BLOCKHASH_READS_PER_BLOCK: usize = 256;

/// Maximum number of bytes permitted for an RLP encoded trie node. Set to 2**15.
pub const MAX_BYTES_PER_NODE: usize = 32768;

/// Maximum number of bytes a contract bytecode is permitted to be. Set to 2**15.
pub const MAX_BYTES_PER_CONTRACT: usize = 32768;

/// Maximum number of contract that can be accessed in a block. Set to 2**11.
pub const MAX_CONTRACTS_PER_BLOCK: usize = 2048;

/// Maximum number of nodes permitted in a merkle patricia proof. Set to 2**6.
pub const MAX_NODES_PER_PROOF: usize = 64;

/// Maximum number of intermediate nodes permitted for all proofs.
/// Proofs are for the execution of a single block. Set to 2**15.
pub const MAX_NODES_PER_BLOCK: usize = 32768;

/// Maximum number of account proofs permitted. Proofs are for the execution
/// of a single block. Set to 2**13.
pub const MAX_ACCOUNT_PROOFS_PER_BLOCK: usize = 8192;

/// Maximum number of storage proofs permitted per account.
/// Proofs are for the execution of a single block. Set to 2**13.
pub const MAX_STORAGE_PROOFS_PER_ACCOUNT: usize = 8192;
