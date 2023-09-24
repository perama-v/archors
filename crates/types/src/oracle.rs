use std::{collections::HashMap, ops::Deref};

use ethers::types::{H160, H256};

/// Behaviour that defines an oracle for post-state trie data. When a block updates state
/// in a way that removes nodes and reorganises the trie, more information may be required.
/// The oracle provides this information. The information is obtained and cached with the
/// block pre-state proofs so that post-state proofs can be computed.
#[derive(Debug, Default, Clone)]
pub struct TrieNodeOracle(HashMap<OracleTarget, Vec<u8>>);

impl TrieNodeOracle {
    /// Make an addition to the oracle.
    pub fn insert_node(&mut self, address: H160, key: H256, node: Vec<u8>) {
        self.0.insert(OracleTarget { address, key }, node);
    }
    /// Retrieve data from the oracle for a particular address and key.
    ///
    /// The node returned will be the specific node that requires the oracle. This
    /// will be the grandparent of a removed node.
    pub fn lookup_node(&self, address: H160, key: H256) -> Option<&[u8]> {
        self.0.get(&OracleTarget { address, key }).map(|x| x.deref())
    }
}

/// A particular trie node that the oracle can provide.
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct OracleTarget {
    pub address: H160,
    pub key: H256,
}
