//! For aggregating trie nodes that are required for a post-state trie node oracle.
//!
//! The oracle provides nodes for scenarios where key deletion involves node removal and trie
//! rearrangements that are otherwise incomputable.

use std::{collections::HashMap, str::FromStr};

use ethers::types::H256;

use crate::{types::BlockProofs, utils::hex_decode};

const DEMO_KEY: &str = "0x0381163500ec1bb2a711ed278aa3caac8cd61ce95bc6c4ce50958a5e1a83494b";
const DEMO_NODE: &str = "0xf9015180a0b6ff53997cdd0c1f088a13f81afb42724cfcea9a07f14a74bb7d1bf4991e1fe2808080a0830370b134144289bda9480169139c6b8f25ee03be7ed111b337c582778cb0e9a097d0df63fab694add277023d143b0e0514d72d8b39954c3e69c622dd0be1be27a05a18babcf477be08eaab47baaa7653f20bd1b736cb7a2c87a112fbcaf9d2f265a0a21b0e909676a0eaf650780fda8a442fa96c1cb75a148d0fdfb9605fba7d448ea03a297ff8508794992a9face497a7b51cc8f191bab147402429e6cd637ed972eea0f9578cbf15296164371c8deb5ccc2269029f5c10add7b9a3130ec836ee3eea99a0429142fd545a0147432a3a60ed59e7254d356b5eff9a8fb99e1bf38a8f11cf178080a06f9f472ad4ca9d97072e42c9c8cb6234d7135e7707f2404692bc3ccf928ca783a05c69391c6bd1ff415dbeeb367634de47152d9a04182c1f051ab91b69c7b2c07680";

pub fn detect_removed_storage(_pre: BlockProofs, _post: BlockProofs) -> HashMap<H256, Vec<u8>> {
    // Look for storage keys that have value = 0x0 post-state.
    // let at_risk_keys = todo!(); // in post

    // Find at risk grandparent nodes. This is the node whose child is likely to be deleted
    // (branch node with two children - but could be more if many deletions occur.). So basically
    // the lowest node whose child is a branch node.
    // Find the traversal index of that node.
    // . let at_risk_keys_with_traversal_indices = todo!(); // in pre

    // Find the node in post-state that exists at that spot in the traversal.
    // in post
    
    let mut set = HashMap::new();
    let key = H256::from_str(DEMO_KEY).unwrap();
    let node = hex_decode(DEMO_NODE).unwrap();
    set.insert(key, node);
    set
}
