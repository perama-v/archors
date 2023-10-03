use std::collections::HashMap;

use ethers::types::H160;

/// Behaviour that defines an oracle for post-state trie data. When a block updates state
/// in a way that removes nodes and reorganises the trie, more information may be required.
/// The oracle provides this information. The information is obtained and cached with the
/// block pre-state proofs so that post-state proofs can be computed.
///
/// The oracle stores for each key, the proof nodes at and below the traversal index.
#[derive(Debug, Default, Clone)]
pub struct TrieNodeOracle(HashMap<OracleTarget, Vec<Vec<u8>>>);

impl TrieNodeOracle {
    /// Make an addition to the oracle.
    pub fn insert(&mut self, address: H160, traversal_to_target: Vec<u8>, nodes: Vec<Vec<u8>>) {
        self.0.insert(
            OracleTarget {
                address,
                traversal_to_target,
            },
            nodes,
        );
    }
    /// Retrieve data from the oracle for a particular address and key.
    ///
    /// The node returned will be the specific node that requires the oracle. This
    /// will be the grandparent of a removed node.
    pub fn lookup(&self, address: H160, traversal_to_target: Vec<u8>) -> Option<Vec<Vec<u8>>> {
        self.0
            .get(&OracleTarget {
                address,
                traversal_to_target,
            })
            .map(|x| x.to_owned())
    }
}

/// The key used to look up items in the oracle. Two storage key lookups are permitted to
/// result in the same oracle result.
///
/// Different storage keys may have common paths, and can share oracle data. For example, their
/// traversals may both start with `[a,b,f]`. It may be that both are removed (e.g. they are the two
/// items in the branch being removed) and both require an oracle. The oracle target can then
/// be agnostic about which order the oracle updates occur in as both can be obtained by following
/// the path.
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
struct OracleTarget {
    address: H160,
    /// Traversal to the target node, as nibbles.
    ///
    /// E.g., If the path is 0xa4fcb... and the node at traversal index 2, then the traversal
    /// is [0xa, 0x4, 0xf].
    traversal_to_target: Vec<u8>,
}
