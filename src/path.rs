//! For navigating a traversal path in a Merkle PATRICIA Trie proof.
//!
//! The path is defined as 32 bytes, defined as the hash of some key: keccak(key).
//!
//! Navigation is done in nibbles, with 16 choices at each level.
//! Extension nodes function as a skip a subset of the path nibbles.
//!
//! As extension nodes may have odd number of nibbles, an encoding may add padding.
//! This encoding also includes a flag for leaf vs extension.
//!
//! A proof traversal may result in a path that diverges from the expected path for
//! that key. This means that the key is not in the original tree. That is, the
//! key-value pair have never been created and the proof is an exclusion proof.
//!
//! If a key-value pair have been created and the value set to 0, the tree will
//! look different and the node will contain the path to the key. There will
//! be a node item with some hash of a null/zero value, depending on the RLP
//! encoding of the data type e.g., hash(rlp(0)).

use serde::Deserialize;
use thiserror::Error;

/// An error with the Merkle Patricia Trie path.
#[derive(Debug, Error)]
pub enum PathError {
    #[error("Branch node (non-terminal) has value, expected none")]
    BranchNodeHasValue,
    #[error("Extension path nibble did not match the expected path")]
    ExtensionNibbleMismatch,
    #[error("Extension node does not contain any path data")]
    ExtensionPathEmpty,
    #[error("Extension path in extension node longer than expected")]
    ExtensionPathLongerThanExpected,
    #[error("Unable to decode invalid hex compact trie path encoding prefix")]
    InvalidCompactPrefix,
    #[error("Nibble must be in the range 0-15, got {0}")]
    InvalidNibble(u8),
    #[error("Attempted traversal to next node in path but path has no remaining nibbles")]
    NextNodeNotInPath,
    #[error("Proof key does not contain data for a traversal path")]
    NoPath,
    #[error("Path expected to be 32 bytes")]
    PathTooLong,
}

/// A sequence of nibbles that represent a traversal from the root of a merkle patricia tree.
///
/// E.g., Path 5a1 Follow node indices in this order: [5, 10, 1]
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NibblePath {
    // Nibble (u4) represented as u8.
    path: Vec<u8>,
    // Index of nibble in path that is being viseted.
    visiting_index: usize,
}

impl NibblePath {
    /// Turn a byte array into a nibble array.
    pub fn init(path_bytes: &[u8]) -> Self {
        let path = path_bytes.into_iter().flat_map(byte_to_nibbles).collect();
        Self {
            path,
            visiting_index: 0,
        }
    }
    /// Adds a nibble to the record. E.g., append('1') to ['b', 'e'] -> ['b', 'e', '1']
    pub fn append_one(&mut self, nibble: u8) -> Result<&mut Self, PathError> {
        if nibble > 15 {
            return Err(PathError::InvalidNibble(nibble));
        }
        if self.path.len() == 64 {
            return Err(PathError::PathTooLong);
        }
        self.path.push(nibble);
        Ok(self)
    }
    /// Adds an extension node path to the nibble path. Accounts
    /// for a prefix.
    ///
    /// E.g., append([prefix, '8', 'a') to ['b', 'e'] -> ['b', 'e', '8', 'a']
    pub fn append_sequence(&mut self, extension_subpath: &[u8]) -> Result<&mut Self, PathError> {
        if self.path.len() == 64 {
            return Err(PathError::PathTooLong);
        }

        let first_byte = extension_subpath
            .get(0)
            .ok_or_else(|| PathError::ExtensionPathEmpty)?;

        let mut addition = vec![];
        match CompactEncoding::try_from(*first_byte)? {
            CompactEncoding::ExtensionEven | CompactEncoding::LeafEven => {
                // Do nothing. Whole first byte is encoding/padding.
            }
            CompactEncoding::ExtensionOdd(nibble) | CompactEncoding::LeafOdd(nibble) => {
                addition.push(nibble)
            }
        };
        extension_subpath
            .into_iter()
            .skip(1) // First byte is compact encoding.
            .flat_map(byte_to_nibbles)
            .for_each(|nibble| addition.push(nibble));

        self.path.append(&mut addition);
        Ok(self)
    }
    /// Visits the next nibble in the traversal and then increment.
    pub fn visit_path_nibble(&mut self) -> Result<u8, PathError> {
        let node_index = self
            .path
            .get(self.visiting_index)
            .ok_or_else(|| PathError::NextNodeNotInPath)?;
        self.visiting_index += 1;
        Ok(*node_index)
    }
    /// Skips nibbles that are encountered in an extension node.
    pub fn skip_extension_node_nibbles(&mut self, extension: &[u8]) -> Result<(), PathError> {
        let extension_nibbles: Vec<u8> = extension.into_iter().flat_map(byte_to_nibbles).collect();

        for skip_nibble in extension_nibbles {
            // Assert that the nibble matches the expected nibble
            let expected = self
                .path
                .get(self.visiting_index)
                .ok_or_else(|| PathError::ExtensionPathLongerThanExpected)?;
            if expected != &skip_nibble {
                return Err(PathError::ExtensionNibbleMismatch);
            }
            // Walk forward
            self.visiting_index += 1;
        }
        Ok(())
    }
    /// Checks if terminal extension/leaf node has a path that matches (inclusion proof) or
    /// doesn't match (exclusion proof).
    pub fn is_inclusion_proof(&mut self, final_subpath: &[u8]) -> bool {
        let mut temp_index = self.visiting_index;
        let subpath_nibbles: Vec<u8> = final_subpath
            .into_iter()
            .flat_map(byte_to_nibbles)
            .collect();

        for skip_nibble in subpath_nibbles {
            // Assert that the nibble matches the expected nibble
            let Some(expected) = self
                .path
                .get(temp_index)
                else {return false};
            if expected != &skip_nibble {
                return false;
            }
            // Walk forward
            temp_index += 1;
        }
        true
    }
}

/// Hex prefix encoding, used for paths in Merkle Patricia Tries. The Odd variants
/// contain a nibble of data, the even variants only contain a padding.
///
/// https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#specification
enum CompactEncoding {
    ExtensionEven,
    ExtensionOdd(u8),
    LeafEven,
    LeafOdd(u8),
}

impl TryFrom<u8> for CompactEncoding {
    type Error = PathError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let nibbles = byte_to_nibbles(&value);
        let encoding = match nibbles {
            [0, _] => CompactEncoding::ExtensionEven,
            [1, nibble @ _] => CompactEncoding::ExtensionOdd(nibble),
            [2, _] => CompactEncoding::LeafEven,
            [3, nibble @ _] => CompactEncoding::LeafOdd(nibble),
            [_, _] => return Err(PathError::InvalidCompactPrefix),
        };
        Ok(encoding)
    }
}

/// Represents byte as an array of nibbles: 0xbc -> [0xb, 0xc]
fn byte_to_nibbles(byte: &u8) -> [u8; 2] {
    // 0xbc -> 0xb
    let high = byte >> 4;
    // 0xbc -> 0xc
    let low = byte & 0xF;
    [high, low]
}

mod test {
    use super::*;

    /// Tests that adding an extension path to a partial traversal handles encoded hex prefix.
    #[test]
    fn test_compact_decode() {
        /*
        // src: https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#specification
        path -> nibble sequence
        '^' shows first nibble of data.
        '00 01 23 45' -> [ 0, 1, 2, 3, 4, 5] # Even Extension
            ^
        '11 23 45'    -> [ 1, 2, 3, 4, 5] # Odd Extension
        ^
        '20 0f 1c b8' -> [ 0, f, 1, c, b, 8] # Even Leaf
            ^
        '3f 1c b8'    -> [ f, 1, c, b, 8] # Odd Leaf
        ^
        */
        extension_correct("00012345", &[0x0, 0x1, 0x2, 0x3, 0x4, 0x5]);
        extension_correct("112345", &[0x1, 0x2, 0x3, 0x4, 0x5]);
        extension_correct("200f1cb8", &[0x0, 0xf, 0x1, 0xc, 0xb, 0x8]);
        extension_correct("3f1cb8", &[0xf, 0x1, 0xc, 0xb, 0x8]);
    }

    fn extension_correct(extension: &str, expected_nibbles: &[u8]) {
        let mut traversal = NibblePath::init(&hex::decode("abc987").unwrap());
        let mut expected_total = vec![0xa, 0xb, 0xc, 0x9, 0x8, 0x7];
        assert_eq!(traversal.path, expected_total);

        traversal
            .append_sequence(&hex::decode(extension).unwrap())
            .unwrap();
        expected_total.extend_from_slice(&expected_nibbles);
        assert_eq!(
            traversal.path, expected_total,
            "Failed to add {extension} extension"
        )
    }
}
