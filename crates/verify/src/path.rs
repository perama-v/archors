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
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PathError {
    #[error("Branch node (non-terminal) has value, expected none")]
    BranchNodeHasValue,
    #[error("Extension path nibble {extension_contained} did not match the expected nibble {expected} (index={visiting})")]
    ExtensionNibbleMismatch {
        visiting: usize,
        expected: u8,
        extension_contained: u8,
    },
    #[error("Extension node does not contain any path data")]
    ExtensionPathEmpty,
    #[error("Extension path in extension node longer than expected")]
    ExtensionPathLongerThanExpected,
    #[error("Attempted to determine inclusion/exclusion without looking past nibble {0}")]
    EvaluatedProofOnPartialPath(usize),
    #[error("Unable to decode invalid hex compact trie path encoding prefix")]
    InvalidPathPrefix,
    #[error("Nibble must be in the range 0-15, got {0}")]
    InvalidNibble(u8),
    #[error("Attempted traversal to next node in path but path has no remaining nibbles")]
    NextNodeNotInPath,
    #[error("Proof key does not contain data for a traversal path")]
    NoPath,
    #[error("Not enough nibbles to create encoded path")]
    NibblesEmpty,
    #[error("Encoded path does not contain a first byte")]
    PathEmpty,
    #[error("Path too long, expected to be 32 bytes")]
    PathTooLong,
    #[error("Path too short, expected to be 32 bytes")]
    PathTooShort,
    #[error("Must pass an even number of nibbles")]
    OddNumberOfNibbles,
    #[error("Unable to request nibble at index greater than 63")]
    InvalidIndex,
}

/// A sequence of nibbles that represent a traversal from the root of a merkle patricia tree.
///
/// E.g., Path 5a1 Follow node indices in this order: [5, 10, 1]
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NibblePath {
    // Nibble (u4) sequence represented as sequence of u8.
    path: Vec<u8>,
    // Index of nibble in path that is being visited.
    visiting_index: usize,
}

impl NibblePath {
    /// Turn a byte array into a nibble array.
    pub fn init(path_bytes: &[u8]) -> Self {
        let path = path_bytes.iter().flat_map(byte_to_nibbles).collect();
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
    pub fn append_prefixed_sequence(
        &mut self,
        extension_subpath: &[u8],
    ) -> Result<&mut Self, PathError> {
        if self.path.len() == 64 {
            return Err(PathError::PathTooLong);
        }
        let mut addition = prefixed_bytes_to_nibbles(extension_subpath)?;
        self.path.append(&mut addition);
        Ok(self)
    }
    /// Visits the next nibble in the traversal and then increment.
    pub fn visit_path_nibble(&mut self) -> Result<u8, PathError> {
        let node_index = self
            .path
            .get(self.visiting_index)
            .ok_or(PathError::NextNodeNotInPath)?;
        self.visiting_index += 1;
        Ok(*node_index)
    }
    /// Skips nibbles that are encountered in an extension node.
    pub fn skip_extension_node_nibbles(&mut self, extension: &[u8]) -> Result<(), PathError> {
        let extension_nibbles: Vec<u8> = prefixed_bytes_to_nibbles(extension)?;
        for skip_nibble in extension_nibbles {
            // Assert that the nibble matches the expected nibble
            let expected = self
                .path
                .get(self.visiting_index)
                .ok_or(PathError::ExtensionPathLongerThanExpected)?;
            if expected != &skip_nibble {
                return Err(PathError::ExtensionNibbleMismatch {
                    visiting: self.visiting_index,
                    expected: *expected,
                    extension_contained: skip_nibble,
                });
            }
            // Walk forward
            self.visiting_index += 1;
        }
        Ok(())
    }
    /// Checks if terminal extension/leaf node has a path that matches (inclusion proof) or
    /// doesn't match (exclusion proof).
    pub fn match_or_mismatch(&self, final_subpath: &[u8]) -> Result<PathNature, PathError> {
        let mut temp_index = self.visiting_index;
        let subpath_nibbles = prefixed_bytes_to_nibbles(final_subpath)?;
        let path_finished = temp_index + subpath_nibbles.len() == 64;

        for skip_nibble in &subpath_nibbles {
            // Assert that the nibble matches the expected nibble
            let expected = self
                .path
                .get(temp_index)
                // Extension is longer than path remaining.
                .ok_or(PathError::ExtensionPathLongerThanExpected)?;

            if expected != skip_nibble {
                // Extension diverges from the expected path for this key.
                // If this proof is valid, it will be an exclusion proof.
                if path_finished {
                    // full 32 bytes
                    return Ok(PathNature::FullPathDiverges(temp_index));
                }
                return Ok(PathNature::SubPathDiverges(temp_index));
            }
            // Walk forward
            temp_index += 1;
        }
        if temp_index == 64 {
            // A full path (32 bytes, 64 nibbles) must have been checked
            return Ok(PathNature::FullPathMatches);
        }
        Ok(PathNature::SubPathMatches)
    }
    /// Returns the nibbles that have not yet been traversed.
    ///
    /// Each nibble is represented as a byte.
    pub fn pending(&self) -> Result<Vec<u8>, PathError> {
        Ok(self.path[self.visiting_index..].to_vec())
    }
    /// Returns the nibbles that have been traversed.
    ///
    /// Each nibble is represented as a byte.
    pub fn history(&self) -> Result<Vec<u8>, PathError> {
        Ok(self.path[..self.visiting_index].to_vec())
    }
    /// Returns the nibbles that have been traversed plus the nibble to be visited next.
    ///
    /// Each nibble is represented as a byte.
    pub fn history_with_next(&self) -> Result<Vec<u8>, PathError> {
        Ok(self.path[..=self.visiting_index].to_vec())
    }
    /// Returns the prefix-encoded path including the nibbles at start and end indices.
    ///
    /// As the path (32 bytes) nibbles are represented as u8, the final nibble is at index 63.
    pub fn get_encoded_path(
        &self,
        target: TargetNodeEncoding,
        nibble_start: usize,
        nibble_end: usize,
    ) -> Result<Vec<u8>, PathError> {
        let nibbles = self
            .path
            .get(nibble_start..=nibble_end)
            .ok_or(PathError::PathTooShort)?;
        let path_bytes = nibbles_to_prefixed_bytes(nibbles, target)?;
        Ok(path_bytes)
    }
    /// Returns the index of the nibble being visiting next.
    pub fn visiting_index(&self) -> usize {
        self.visiting_index
    }
    /// Returns the nibble at the specified index.
    pub fn nibble_at_index(&self, index: usize) -> Result<u8, PathError> {
        Ok(*self.path.get(index).ok_or(PathError::InvalidIndex)?)
    }
}

/// Merkle proof that a key is or isn't part of the trie.
///
/// When traversing the trie and the final node is encountered,
/// whether the path diverges from the expected path
/// for that key determines if the proof is inclusion/exclusion.
///
/// This condition is necessary but not sufficient for the overall proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathNature {
    // Paths match, not yet 32 bytes
    SubPathMatches,
    // Paths diverge, not yet 32 bytes. Contains index of first divergent nibble.
    SubPathDiverges(usize),
    // 32 byte paths match
    FullPathMatches,
    // 32 byte paths diverge. Contains index of first divergent nibble.
    FullPathDiverges(usize),
}

/// Turns sequence of bytes in to sequence of nibbles. The bytes are prefixed
/// with extension/node and even/odd encoding. This encoding is removed from the result.
///
/// Each nibble will be represented as a u8.
///
/// E.g. from an encoded odd leaf path:
///
/// `vec![0x3f, 0x1c, 0xb8]` -> `vec![0xf, 0x1, 0xc, 0xb, 0x8]`
pub fn prefixed_bytes_to_nibbles(bytes: &[u8]) -> Result<Vec<u8>, PathError> {
    let mut nibbles = vec![];

    let first_byte = bytes.first().ok_or(PathError::ExtensionPathEmpty)?;
    match PrefixEncoding::try_from(first_byte)? {
        PrefixEncoding::ExtensionEven | PrefixEncoding::LeafEven => {
            // Do nothing. Whole first byte is encoding/padding.
        }
        PrefixEncoding::ExtensionOdd(nibble) | PrefixEncoding::LeafOdd(nibble) => {
            nibbles.push(nibble)
        }
    };
    bytes
        .iter()
        .skip(1) // First byte is compact encoding.
        .flat_map(byte_to_nibbles)
        .for_each(|nibble| nibbles.push(nibble));

    Ok(nibbles)
}

/// Converts a collection of nibbles into prefix-encoded bytes.
///
/// Each nibble is represented as a u8.
///
/// E.g. into an encoded odd leaf path:
///
/// `vec![0xf, 0x1, 0xc, 0xb, 0x8]` -> `vec![0x3f, 0x1c, 0xb8]`
pub fn nibbles_to_prefixed_bytes(
    unencoded_nibbles: &[u8],
    target: TargetNodeEncoding,
) -> Result<Vec<u8>, PathError> {
    let is_even = unencoded_nibbles.len() % 2 == 0;
    let mut encoded: Vec<u8> = vec![];
    match (target, is_even) {
        (TargetNodeEncoding::Extension, true) => {
            // 0 0 + remaining
            encoded.push(0x00);
            encoded.extend(nibbles_to_bytes(unencoded_nibbles)?);
        }
        (TargetNodeEncoding::Extension, false) => {
            // 1 first + remaining
            let (first, remaining) = unencoded_nibbles
                .split_first()
                .ok_or(PathError::NibblesEmpty)?;
            encoded.push(nibbles_to_byte(&[0x1, *first])?);
            encoded.extend(nibbles_to_bytes(remaining)?);
        }
        (TargetNodeEncoding::Leaf, true) => {
            // 2 0 + remaining
            encoded.push(0x20);
            encoded.extend(nibbles_to_bytes(unencoded_nibbles)?);
        }
        (TargetNodeEncoding::Leaf, false) => {
            // 3 first + remaining
            let (first, remaining) = unencoded_nibbles
                .split_first()
                .ok_or(PathError::NibblesEmpty)?;
            encoded.push(nibbles_to_byte(&[0x3, *first])?);
            encoded.extend(nibbles_to_bytes(remaining)?);
        }
    };
    Ok(encoded)
}

/// Hex prefix encoding, used for paths in Merkle Patricia Tries. The Odd variants
/// contain a nibble of data, the even variants only contain a padding.
///
/// https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#specification
pub enum PrefixEncoding {
    ExtensionEven,
    ExtensionOdd(u8),
    LeafEven,
    LeafOdd(u8),
}

impl TryFrom<&u8> for PrefixEncoding {
    type Error = PathError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        let nibbles = byte_to_nibbles(value);
        let encoding = match nibbles {
            [0, _] => PrefixEncoding::ExtensionEven,
            [1, nibble] => PrefixEncoding::ExtensionOdd(nibble),
            [2, _] => PrefixEncoding::LeafEven,
            [3, nibble] => PrefixEncoding::LeafOdd(nibble),
            [_, _] => return Err(PathError::InvalidPathPrefix),
        };
        Ok(encoding)
    }
}

impl TryFrom<&[u8]> for PrefixEncoding {
    type Error = PathError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let first_byte = value.first().ok_or(PathError::PathEmpty)?;
        first_byte.try_into()
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

/// Represents array of nibbles as little endian byte: [0xb, 0xc] -> 0xbc
pub fn nibbles_to_byte(nibbles: &[u8; 2]) -> Result<u8, PathError> {
    // 0xb -> 0xb0
    if nibbles[0] > 15 {
        return Err(PathError::InvalidNibble(nibbles[0]));
    }
    let high = nibbles[0] << 4;
    // 0xc -> 0x0c
    if nibbles[1] > 15 {
        return Err(PathError::InvalidNibble(nibbles[1]));
    }
    let low = nibbles[1] & 0x0F;
    // 0xb0 & 0x0c -> 0xbc
    Ok(high | low)
}

pub enum TargetNodeEncoding {
    Leaf,
    Extension,
}

/// Converts a collection of nibbles into bytes: [0xb, 0xc, 0x3, 0xa] -> [0xbc, 0x3a]
pub fn nibbles_to_bytes(nibbles: &[u8]) -> Result<Vec<u8>, PathError> {
    if nibbles.len() % 2 != 0 {
        return Err(PathError::OddNumberOfNibbles);
    }
    let mut bytes: Vec<u8> = vec![];
    for (index, nibble) in nibbles.iter().enumerate().step_by(2) {
        let byte = nibbles_to_byte(&[*nibble, nibbles[index + 1]])?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_prefixed_bytes_to_nibbles() {
        let even_extension = &hex::decode("00012345").unwrap();
        assert_eq!(
            prefixed_bytes_to_nibbles(even_extension).unwrap(),
            vec![0x0, 0x1, 0x2, 0x3, 0x4, 0x5]
        );
        let odd_extension = &hex::decode("112345").unwrap();
        assert_eq!(
            prefixed_bytes_to_nibbles(odd_extension).unwrap(),
            vec![0x1, 0x2, 0x3, 0x4, 0x5]
        );
        let even_leaf = &hex::decode("200f1cb8").unwrap();
        assert_eq!(
            prefixed_bytes_to_nibbles(even_leaf).unwrap(),
            vec![0x0, 0xf, 0x1, 0xc, 0xb, 0x8]
        );
        let odd_leaf = &hex::decode("3f1cb8").unwrap();
        assert_eq!(
            prefixed_bytes_to_nibbles(odd_leaf).unwrap(),
            vec![0xf, 0x1, 0xc, 0xb, 0x8]
        );
    }

    #[test]
    fn test_nibbles_to_prefixed_bytes() {
        // Even extension '012345'
        assert_eq!(
            nibbles_to_prefixed_bytes(
                &vec![0x0, 0x1, 0x2, 0x3, 0x4, 0x5],
                TargetNodeEncoding::Extension
            )
            .unwrap(),
            hex::decode("00012345").unwrap()
        );
        // Odd extension '12345'
        assert_eq!(
            nibbles_to_prefixed_bytes(
                &vec![0x1, 0x2, 0x3, 0x4, 0x5],
                TargetNodeEncoding::Extension
            )
            .unwrap(),
            hex::decode("112345").unwrap()
        );
        // Even leaf '0f1cb8'
        assert_eq!(
            nibbles_to_prefixed_bytes(
                &vec![0x0, 0xf, 0x1, 0xc, 0xb, 0x8],
                TargetNodeEncoding::Leaf
            )
            .unwrap(),
            hex::decode("200f1cb8").unwrap()
        );
        // Odd leaf 'f1cb8'
        assert_eq!(
            nibbles_to_prefixed_bytes(&vec![0xf, 0x1, 0xc, 0xb, 0x8], TargetNodeEncoding::Leaf)
                .unwrap(),
            hex::decode("3f1cb8").unwrap()
        );
    }

    /// Tests that adding an extension path to a partial traversal handles encoded hex prefix.
    #[test]
    fn test_append_prefixed_sequence() {
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

        traversal
            .append_prefixed_sequence(&hex::decode(extension).unwrap())
            .unwrap();
        expected_total.extend_from_slice(expected_nibbles);
        assert_eq!(
            traversal.path, expected_total,
            "Failed to add {extension} extension"
        )
    }
    #[test]
    fn test_init() {
        let traversal = NibblePath::init(&hex::decode("abc987").unwrap());
        assert_eq!(traversal.path, vec![0xa, 0xb, 0xc, 0x9, 0x8, 0x7])
    }

    #[test]
    fn test_append_one() {
        let mut traversal = NibblePath::init(&hex::decode("a46a34").unwrap());
        traversal.append_one(9).unwrap();
        assert_eq!(traversal.path, vec![0xa, 0x4, 0x6, 0xa, 0x3, 0x4, 0x9]);
        assert!(traversal.append_one(90).is_err());
    }

    #[test]
    fn test_visit_path_nibble() {
        let mut traversal = NibblePath::init(&hex::decode("abcd").unwrap());
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xa);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xb);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xc);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xd);
        assert!(traversal.visit_path_nibble().is_err());
    }

    #[test]
    fn test_skip_extension_node_odd_nibbles() {
        // Skip 'c2345' (an odd number of nibbles, for an extension node, hence prefix '1')
        let odd_extension = &hex::decode("1c2345").unwrap();
        assert_eq!(
            prefixed_bytes_to_nibbles(odd_extension).unwrap(),
            vec![0xc, 0x2, 0x3, 0x4, 0x5]
        );
        let mut traversal = NibblePath::init(&hex::decode("abc2345def6789").unwrap());
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xa);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xb);
        // Skip past 'c2345'
        traversal
            .skip_extension_node_nibbles(odd_extension)
            .unwrap();
        // End up at 'd'
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xd);
        // Try to skip again, using the same extension. Should fail.
        assert!(traversal
            .skip_extension_node_nibbles(odd_extension)
            .is_err());
    }

    #[test]
    fn test_skip_extension_node_even_nibbles() {
        // Skip '2345' (an even number of nibbles, for an extension node,
        // hence prefix '0' and padding '0')
        let odd_extension = &hex::decode("002345").unwrap();
        assert_eq!(
            prefixed_bytes_to_nibbles(odd_extension).unwrap(),
            vec![0x2, 0x3, 0x4, 0x5]
        );
        let mut traversal = NibblePath::init(&hex::decode("abc2345def6789").unwrap());
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xa);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xb);
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xc);
        // Skip past '2345'
        traversal
            .skip_extension_node_nibbles(odd_extension)
            .unwrap();
        // End up at 'd'
        assert_eq!(traversal.visit_path_nibble().unwrap(), 0xd);
        // Try to skip again, using the same extension. Should fail.
        assert!(traversal
            .skip_extension_node_nibbles(odd_extension)
            .is_err());
    }

    /// Traverses the trie path all in one go, by encountering an extension node
    /// that matches the entire path.
    #[test]
    fn test_terminal_extension_node_early_extension() {
        // Skip entire path (an even number of nibbles, for an extension node,
        // hence prefix '0' and padding '0')
        let even_extension =
            &hex::decode("000123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        let traversal = NibblePath::init(
            &hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap(),
        );
        assert_eq!(
            traversal.match_or_mismatch(even_extension).unwrap(),
            PathNature::FullPathMatches
        );
    }

    /// Traverses the trie path in two steps, together making a full path traversal.
    #[test]
    fn test_terminal_extension_node_two_parts() {
        // Skip partial path (an even number of nibbles, for an extension node,
        // hence prefix '0' and padding '0')
        let even_extension_1 =
            &hex::decode("000123456789abcdef0123456789abcdef0123456789").unwrap();
        let mut traversal = NibblePath::init(
            &hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap(),
        );

        assert_eq!(
            traversal.match_or_mismatch(even_extension_1).unwrap(),
            PathNature::SubPathMatches
        );
        assert_eq!(
            traversal
                .match_or_mismatch(&hex::decode("000123444444").unwrap())
                .unwrap(),
            PathNature::SubPathDiverges(5)
        );
        // Apply/traverse the first extension node.
        traversal
            .skip_extension_node_nibbles(even_extension_1)
            .unwrap();

        let even_extension_2 = &hex::decode("00abcdef0123456789abcdef").unwrap();
        // An exclusion proof should diverge before the final nibble of the path.
        assert_eq!(
            traversal.match_or_mismatch(even_extension_2).unwrap(),
            PathNature::FullPathMatches
        );

        let even_extension_3 = &hex::decode("00abcdef0123456789abcde9").unwrap();
        // Path that diverges in the final nibble.
        assert_eq!(
            traversal.match_or_mismatch(even_extension_3).unwrap(),
            PathNature::FullPathDiverges(63)
        );
    }

    /// Traverses the trie path in two steps, together making a full path traversal.
    #[test]
    fn test_terminal_leaf_node_two_parts() {
        // Skip partial path (an even number of nibbles, for a extension node,
        // hence prefix '0' and padding '0')
        let even_extension = &hex::decode("000123456789abcdef0123456789abcdef0123456789").unwrap();
        let mut traversal = NibblePath::init(
            &hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap(),
        );

        // Inclusion/exclusion proof cannot be evaluated without looking at the full path.
        assert_eq!(
            traversal.match_or_mismatch(even_extension).unwrap(),
            PathNature::SubPathMatches
        );
        // Apply/traverse the first extension node.
        traversal
            .skip_extension_node_nibbles(even_extension)
            .unwrap();

        // even leaf is '2' with padding '0'
        // The path including this too-short leaf is less than 64 nibbles.
        // So this is an attempt to declare inclusion/exclusion on an incomplete path.
        // However a leaf cannot have an incomplete path.
        let leaf_path_too_short = &hex::decode("20abcdef0123456789").unwrap();
        assert_eq!(
            traversal.match_or_mismatch(leaf_path_too_short).unwrap(),
            PathNature::SubPathMatches
        );

        // Enough for a full path
        let even_leaf = &hex::decode("20abcdef0123456789abcdef").unwrap();
        assert_eq!(
            traversal.match_or_mismatch(even_leaf).unwrap(),
            PathNature::FullPathMatches
        );
    }

    #[test]
    fn test_is_exclusion_proof_with_terminal_extension_node_early_divergence() {
        // Path diverges immediately
        // (an even number of nibbles, for an extension node,
        // hence prefix '0' and padding '0')
        let even_extension =
            &hex::decode("006666666666abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        let traversal = NibblePath::init(
            &hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap(),
        );
        assert_eq!(
            traversal.match_or_mismatch(even_extension).unwrap(),
            PathNature::FullPathDiverges(0)
        );
    }

    /// Traverses some of the trie path, then encounters an extension node that
    /// does not match the path. Asserts that it is an exclusion proof.
    #[test]
    fn test_is_exclusion_proof_with_terminal_extension_node_later_divergence() {
        // Traverse some of the the path (16 nibbles).
        // (an even number of nibbles, for an extension node,
        // hence prefix '0' and padding '0')
        let even_extension = &hex::decode("000123456789abcdef").unwrap();
        let mut traversal = NibblePath::init(
            &hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap(),
        );
        traversal
            .skip_extension_node_nibbles(even_extension)
            .unwrap();
        assert_eq!(traversal.visiting_index, 16);
        // First 6 nibbles match (15 + 6 = 21), then path diverges at index 22.
        let divergent_even_extension = &hex::decode("00012345ffff").unwrap();
        assert_eq!(
            traversal
                .match_or_mismatch(divergent_even_extension)
                .unwrap(),
            PathNature::SubPathDiverges(22)
        );
    }

    /// Traverses the trie path in two steps, together making a full path traversal.
    #[test]
    fn test_is_exclusion_proof_with_terminal_leaf_node() {
        // Skip partial path (an even number of nibbles, for a extension node,
        // hence prefix '0' and padding '0')
        let even_extension = &hex::decode("000123456789abcdef0123456789abcdef0123456789").unwrap();
        let mut traversal = NibblePath::init(
            &hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap(),
        );

        // Inclusion/exclusion proof cannot be evaluated without looking at the full path.
        assert_eq!(
            traversal.match_or_mismatch(even_extension).unwrap(),
            PathNature::SubPathMatches
        );
        // Apply/traverse the first extension node.
        traversal
            .skip_extension_node_nibbles(even_extension)
            .unwrap();

        // even leaf is '2' with padding '0'
        // The path including this too-short leaf is less than 64 nibbles.
        // So this is an attempt to declare inclusion/exclusion on an incomplete path.
        // However a leaf cannot have an incomplete path.
        let leaf_path_too_short = &hex::decode("20abcdef0123456789").unwrap();
        assert_eq!(
            traversal.match_or_mismatch(leaf_path_too_short).unwrap(),
            PathNature::SubPathMatches
        );

        // Enough for a full path, however, the leaf path diverges in the final 10 nibbles.
        let even_leaf = &hex::decode("20abcdef0123456789666666").unwrap();
        assert_eq!(
            traversal.match_or_mismatch(even_leaf).unwrap(),
            PathNature::FullPathDiverges(58)
        );
    }

    #[test]
    fn test_nibbles_to_byte() {
        assert_eq!(nibbles_to_byte(&[0x0, 0x0]).unwrap(), 0x00);
        assert_eq!(nibbles_to_byte(&[0xf, 0xf]).unwrap(), 0xff);
        assert_eq!(nibbles_to_byte(&[0xf, 0x0]).unwrap(), 0xf0);
        assert_eq!(nibbles_to_byte(&[0x0, 0xf]).unwrap(), 0x0f);
        assert_eq!(nibbles_to_byte(&[0x3, 0xc]).unwrap(), 0x3c);
        assert!(nibbles_to_byte(&[0x30, 0x9]).is_err());
    }

    #[test]
    fn test_get_encoded_path_even_extension() {
        let traversal = NibblePath::init(
            &hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap(),
        );
        let encoded_path = traversal
            .get_encoded_path(TargetNodeEncoding::Extension, 60, 63)
            .unwrap();
        // 00cdef
        assert_eq!(encoded_path, vec![0x00, 0xcd, 0xef]);
    }

    #[test]
    fn test_get_encoded_path_odd_extension() {
        let traversal = NibblePath::init(
            &hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap(),
        );
        let encoded_path = traversal
            .get_encoded_path(TargetNodeEncoding::Extension, 61, 63)
            .unwrap();
        // 1def
        assert_eq!(encoded_path, vec![0x1d, 0xef]);
    }

    #[test]
    fn test_get_encoded_path_even_leaf() {
        let traversal = NibblePath::init(
            &hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap(),
        );
        let encoded_path = traversal
            .get_encoded_path(TargetNodeEncoding::Leaf, 60, 63)
            .unwrap();
        // 20cdef
        assert_eq!(encoded_path, vec![0x20, 0xcd, 0xef]);
    }

    #[test]
    fn test_get_encoded_path_odd_leaf() {
        let traversal = NibblePath::init(
            &hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap(),
        );
        let encoded_path = traversal
            .get_encoded_path(TargetNodeEncoding::Leaf, 61, 63)
            .unwrap();
        // 3def
        assert_eq!(encoded_path, vec![0x3d, 0xef]);
    }

    #[test]
    fn test_nibbles_to_bytes() {
        assert_eq!(
            nibbles_to_bytes(&[0xb, 0xc, 0x3, 0xa, 0xf, 0x1]).unwrap(),
            vec![0xbc, 0x3a, 0xf1]
        );
        // Invalid nibbles
        assert!(nibbles_to_bytes(&[0xb, 0xc, 0x3, 0xa, 0xf6, 0x1e]).is_err());
        // Odd length
        assert!(nibbles_to_bytes(&[0xb, 0xc, 0x3, 0xa, 0x1]).is_err());
    }
}
