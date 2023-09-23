use std::collections::HashMap;

use ethers::types::H256;

/// Behaviour that defines an oracle for post-state trie data. When a block updates state
/// in a way that removes nodes and reorganises the trie, more information may be required.
/// The oracle provides this information. The information is obtained and cached with the
/// block pre-state proofs so that post-state proofs can be computed.
#[derive(Debug, Default, Clone)]
pub struct TrieNodeOracle(HashMap<H256, Vec<u8>>);

impl TrieNodeOracle {
    pub fn new(data: HashMap<H256, Vec<u8>>) -> Self {
        Self(data)
    }
}
