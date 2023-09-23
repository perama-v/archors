//! Module for resolving the situation where a storage value is set to zero by a block.
//!
//! When a value is set to zero, the key is removed from the trie. If the parent was a branch
//! with only two children, the branch now has one child and must be removed. To update the
//! grandparent, either the sibling RLP must be known (infeasible using eth_getProof), or the
//! grandparent can be obtained from an oracle. The oracle is constructed by selecting data from
//! proofs from the block-post state.
//!
//! The oracle contains a map of key -> (traversal path, grandparent post-state).
//!
//! There are two scenarios where the oracle is used:
//! - Whenever a parent branch needs to be deleted, the traversal path is noted and the grandparent
//! fetched from the oracle.
//! - Whenever a traversal is made along an already-oracle-fetched grandparent. The traversal
//! changes are assumed to be valid.
//!   - The changes could be validated by following the outdated grandparent and when all changes
//! in that subtree are made, check that they match the hash in the grandparent. This is currently
//! not implemented and so an EVM bug in these values is possible. This is likely a very small
//! number of storage values.
//!
//!
//! The scenario is also described in the multiproof crate readme.
//!
//! ### Algorithm
//! 1. When traversing and the need for the oracle arises, the grandparent that needs updating is
//! recorded, including the traversal within it that was affected (e.g., branch node item index 5).
//! 2. It is not immediately updated.
//! 3. The remaining storage changes are applied for the account.
//! 4. Then the grandparent is fetched.
//! 5. The members of the node that are not the affected item are checked against the existing
//! equivalent node.
//! 6. If they are the same, the new item is accepted and the changes updated to the storage root.

use std::collections::HashMap;

use archors_types::oracle::TrieNodeOracle;
use ethers::types::H256;
use serde::{Deserialize, Serialize};

use crate::{node::VisitedNode, proof::Node};


/// A node that has been flagged as requiring an oracle to be updated.
///
/// This is a consequence of a node restructuring following a node change from an inclusion
/// proof to exclusion proof and subsequent removal of a parent branch. An oracle task is generated
/// for the granparent.
///
/// Tasks are completed once all other possible storage updates have been applied. Tasks are then
/// fulfilled starting with the task with the highest traversal index.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OracleTask {
    /// Storage key involved
    pub key: H256,
    /// The index into the trie path that matches the node that needs to be looked up.
    pub traversal_index: usize,
}

impl OracleTask {
    /// Generate a new task.
    pub fn new(key: H256, node: &VisitedNode) -> Self {
        OracleTask { key, traversal_index: node.traversal_record.visiting_index() - 1 }
    }
    /// Gets the node from the oracle, performs checks and returns the node hash.
    ///
    /// Checks that the non-salient (not on the task path) items match the partially updated node
    /// items.
    pub fn complete_task(&self, partially_updated: Node, oracle: &TrieNodeOracle) -> H256 {
        todo!()
    }
    /// Returns the item index in the node that was the reason for needing an oracle.
    fn get_salient_item_index() -> usize {
        todo!()
    }
    /// Fetches the node from the oracle
    fn fetch_from_oracle(&self, oracle: TrieNodeOracle) -> Node {
        todo!()
    }
    /// Returns the path for the task
    fn path(&self) {
        todo!()
    }
}
