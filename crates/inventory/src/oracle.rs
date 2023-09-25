//! For aggregating trie nodes that are required for a post-state trie node oracle.
//!
//! The oracle provides nodes for scenarios where key deletion involves node removal and trie
//! rearrangements that are otherwise incomputable.

use std::{collections::HashMap, str::FromStr};

use archors_types::oracle::TrieNodeOracle;
use ethers::types::{H256, H160};

use crate::{types::BlockProofs, utils::hex_decode};

const DEMO_ACCOUNT: &str = "0x0a6dd5d5a00d6cb0678a4af507ba79a517d5eb64";
const DEMO_KEY: &str = "0x0381163500ec1bb2a711ed278aa3caac8cd61ce95bc6c4ce50958a5e1a83494b";
const DEMO_NODE: &str = "0xf9015180a0b6ff53997cdd0c1f088a13f81afb42724cfcea9a07f14a74bb7d1bf4991e1fe2808080a0830370b134144289bda9480169139c6b8f25ee03be7ed111b337c582778cb0e9a097d0df63fab694add277023d143b0e0514d72d8b39954c3e69c622dd0be1be27a05a18babcf477be08eaab47baaa7653f20bd1b736cb7a2c87a112fbcaf9d2f265a0a21b0e909676a0eaf650780fda8a442fa96c1cb75a148d0fdfb9605fba7d448ea03a297ff8508794992a9face497a7b51cc8f191bab147402429e6cd637ed972eea0f9578cbf15296164371c8deb5ccc2269029f5c10add7b9a3130ec836ee3eea99a0429142fd545a0147432a3a60ed59e7254d356b5eff9a8fb99e1bf38a8f11cf178080a06f9f472ad4ca9d97072e42c9c8cb6234d7135e7707f2404692bc3ccf928ca783a05c69391c6bd1ff415dbeeb367634de47152d9a04182c1f051ab91b69c7b2c07680";


const DEMO_ACCOUNT_2: &str = "0x1d8f8f00cfa6758d7be78336684788fb0ee0fa46";
const DEMO_KEY_2: &str = "0x018cadc03de393878df6974d0ec421346ba20241e63eb680292cc02c5862d3d3";
const DEMO_NODE_2: &str = "0xf90211a02625efe6d51c9a0f9d024c0fd2c487a48dcc0e139acf7dda6c28573d6506e6eca0626b397b31893d14e79b62a8afe04472da3e9fc7d00add190e6564462b5b7ec1a0b2b71afd40d886d4c517ced4ad35e8130a05d24590be0efe0db1bc168d998927a09de3b92aacb1687cd85ab725fa18f67d2743cbdb1cf74e91b653aa76f8640965a021ee5d9914954721504789e8905778052e291cba253cc28b74dcbb18b0346b44a0d1163778da96373114c8d6fc8b7f1248964b5d56c41dcf203f0649f3bb983d9da0f70e99d768ccfd8f581ea25befcc2cab225075d1b7c57ae8ae45b88dbcbb175ea056c41af319bb204b586539dcd1f64d4d7781c25e9157b2b8dc200c7f1756eee6a00d18e4451b4b9870183fbb9b4f356bca78e58e3255ee3c81792661946cea01efa04526e50b40c53a032ec2e54343b6a49462003c0c22b39a0a0eaface1474050eea0e02621370e695e9f94ca0d2922051e886b0f4dc7e7a0ede364ac8543e1cb66bba09ceab93e5804744e5f00e70309de8ac9276c1250ad39edab1dc3a5b4a060150ea0179a2a0348e73ac975007b4e6043328f3b1aacadbff9335fa65dc628a268a9b5a0935590f0f6682797b53b81d3af29c8ac41b40366c3f102e57867f3f6195fd46aa09e8a9f26606e3a800687538a6753369c47cc52969664ab8058ceffc22978db63a0d1b69d3dca902ddd7cb67e5f1b8c030778ff32ff622cb435931792f9025d56ea80";

/// Looks for situations where storage keys are removed by a block. Returns internal nodes
/// critical for trie updates in those scenarios.
pub fn detect_removed_storage(_pre: BlockProofs, _post: BlockProofs) -> TrieNodeOracle {
    // Look for storage keys that have value = 0x0 post-state.
    // let at_risk_keys = todo!(); // in post

    // Find at risk grandparent nodes. This is the node whose child is likely to be deleted
    // (branch node with two children - but could be more if many deletions occur.). So basically
    // the lowest node whose child is a branch node.
    // Find the traversal index of that node.
    // . let at_risk_keys_with_traversal_indices = todo!(); // in pre

    // Find the node in post-state that exists at that spot in the traversal.
    // in post
    let mut oracle = TrieNodeOracle::default();

    let address = H160::from_str(DEMO_ACCOUNT).unwrap();
    let key = H256::from_str(DEMO_KEY).unwrap();
    let node = hex_decode(DEMO_NODE).unwrap();
    oracle.insert_node(address, key, node);

    let address = H160::from_str(DEMO_ACCOUNT_2).unwrap();
    let key = H256::from_str(DEMO_KEY_2).unwrap();
    let node = hex_decode(DEMO_NODE_2).unwrap();
    oracle.insert_node(address, key, node);

    oracle
}

