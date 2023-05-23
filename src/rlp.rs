//! For Recursive Length Prefix encoding/decoding

use ethers::types::U256;
use thiserror::Error;

use crate::eip1186::Account;

#[derive(Debug, Error)]
pub enum RlpError {
    #[error("Branch node (non-terminal) has value, expected none")]
    BranchNodeHasValue,
    #[error("Parent nodes (rlp: {parent}) do not contain hash of rlp(child) (hash: {child}")]
    ChildNotFound { parent: String, child: String },
    #[error("RLP decode error {0}")]
    DecodeError(#[from] rlp::DecoderError),
    #[error("Proof is empty")]
    EmptyProof,
    #[error(
        "Hash of node {computed} does not match the expected hash in the parent node {expected}"
    )]
    IncorrectHash { computed: String, expected: String },
    #[error("Merkle Patricia Node to have max 17 (16 + 1) items, got {0}")]
    InvalidNodeItemCount(usize),
    #[error("Account proof node has no value. RLP: {0}")]
    NoNodeAccountValue(String),
    #[error("Storage proof node has no value. RLP: {0}")]
    NoNodeStorageValue(String),
}

/// Decodes the final element of an storage proof and returns a storage value.
///
/// The element comprises: rlp(nodes, rlp(storage))
///
/// Where storage value is U256.
#[allow(dead_code)]
fn rlp_decode_final_storage_element(proof_leaf_rlp: &[u8]) -> Result<U256, RlpError> {
    let decoded: Vec<Vec<u8>> = rlp::decode_list(proof_leaf_rlp);
    let storage = decoded
        .last()
        .ok_or(RlpError::NoNodeStorageValue(hex::encode(proof_leaf_rlp)))?;
    if storage.is_empty() {
        return Ok(U256::from(0));
    }
    let val: U256 = rlp::decode(storage)?;
    Ok(val)
}

/// Decodes the final element of an account proof and returns an account object.
///
/// The element comprises: rlp(nodes, rlp(account_object))
///
/// Where account_object contains: nonce, balance, storage_hash, code_hash.
/// Nodes at this level are discarded as they are not used to evaluate the proof.
#[allow(dead_code)]
pub fn rlp_decode_final_account_element(proof_leaf_rlp: &[u8]) -> Result<Account, RlpError> {
    let decoded: Vec<Vec<u8>> = rlp::decode_list(proof_leaf_rlp);
    let account_rlp = decoded
        .last()
        .ok_or(RlpError::NoNodeAccountValue(hex::encode(proof_leaf_rlp)))?;
    let account: Account = rlp::decode(account_rlp)?;
    Ok(account)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    use ethers::types::H256;
    use rlp::Rlp;
    use rlp_derive::RlpDecodable;

    // A 17-item merkle patricia trie node.
    const BRANCH_NODE: &str = "f90151a0bf5e7a6355d2aae16870034397bcb78fb7f3677302857c4e3f0f11b2ad183ddaa0441a130e5b3344a0c6d4e01e69cdd8c3d54c9427c22df1c21e823bd5238bcedc80a0de4a8735f0afe745a73341f09b2641b136c4c6ceb33a4c04f868b8c0ae0c572da0616b1953ab56f21db0e3e0a8f04422bbdce75bd530e049560426deb7548c9324a0df7498a408a3cb6f416a60eb97bc61cdd31f9f9c1e3d9f2e131c476cca1a64aaa0b4b838d595815f1af27bc520f9054bbe7b8f1ae901d58ceba455a93a02b38fe3a088c2648a34b76ec09c67666bf1b2ff917c97a960dbebd2c8d56ec2b89c5f5d7ba080f002d80dc9f4e682660964f02c4f70fdfb5aeeee5f5651fca75c06f810c37980a0f6d68b8a203434af63aefd6acbce4e627b80e03c11d9c64334d48655f842ee24a02991191455c868799650d6cd4009a21443c9ac2aebedb76d55d9a01811d59a9c8080808080";

    // A 2-item merkle patricia trie node. RLP structure: list[integer, list[account]]
    const ACCOUNT_LEAF: &str = "f8669d33269ec9b8f075a4723d27c611ac1c52a464f3516b25e0105a0d1c2210b846f8440180a03836d7e3afb674e5180b7564e096f6f3e30308878a443fe59012ced093544b7fa02cfdfbdd943ec0153ed07b97f03eb765dc11cc79c6f750effcc2d126f93c4b31";

    // A 2-item merkle patricia trie node. RLP structure: list[string, ..., list[storage]]
    // This proof is for storage key = 0, value = 0.
    const STORAGE_LEAF: &str =
    "f871a0e4050339952e88a1d403d7078148abf3af96d8a2fdb175cf12244b721962fe4280808080808080a0cd71d6a12adb2cef5dba915f9cd9490173c5db30ea44a1aee026d8e0ea2fd27f80a059267a0b25d180d3cae2274c50da7b7da0ddddfd435671181e9dc2f7ba8cca7f808080808080";

    #[test]
    fn rlp_decode_account_proof_leaf() {
        // RLP-encoded account leaf
        let data_bytes = hex::decode(ACCOUNT_LEAF).unwrap();
        let account = rlp_decode_final_account_element(&data_bytes).unwrap();
        assert_eq!(
            account,
            Account {
                nonce: 1.into(),
                balance: 0.into(),
                storage_hash: H256::from_str(
                    "0x3836d7e3afb674e5180b7564e096f6f3e30308878a443fe59012ced093544b7f"
                )
                .unwrap(),
                code_hash: H256::from_str(
                    "0x2cfdfbdd943ec0153ed07b97f03eb765dc11cc79c6f750effcc2d126f93c4b31"
                )
                .unwrap()
            },
        );
    }

    #[test]
    fn rlp_decode_storage_proof_leaf_val_zero_1() {
        // RLP-encoded storage leaf
        let data_bytes = hex::decode(STORAGE_LEAF).unwrap();
        let storage = rlp_decode_final_storage_element(&data_bytes).unwrap();

        let expected = U256::from_str("0x0").unwrap();
        assert_eq!(storage, expected);
    }

    #[test]
    fn rlp_decode_storage_proof_leaf_val_nonzero_1() {
        // RLP-encoded storage leaf
        let data_bytes = hex::decode("ed9f208376e489f0656e4ae2d3a7f1b2fc108b42db04095810f535cc0ab222a6498c8b0422ca8b0a00a425000000").unwrap();
        let storage = rlp_decode_final_storage_element(&data_bytes).unwrap();
        let expected = U256::from_str("0x422ca8b0a00a425000000").unwrap();
        assert_eq!(storage, expected);
    }

    #[test]
    fn rlp_decode_storage_proof_leaf_val_nonzero_2() {
        // RLP-encoded storage leaf
        let data_bytes = hex::decode(
            "e79f3787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace868512a05f2000",
        )
        .unwrap();
        let storage = rlp_decode_final_storage_element(&data_bytes).unwrap();
        let expected = U256::from_str("0x12a05f2000").unwrap();
        assert_eq!(storage, expected);
    }

    #[test]
    fn rlp_basic() {
        let data = vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'];
        let rlp = Rlp::new(&data);
        let dog = rlp.at(1).unwrap().data().unwrap();
        assert_eq!(dog, &[b'd', b'o', b'g']);
    }

    #[test]
    fn rlp_short_list() {
        let data = vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'];
        let list: Vec<String> = rlp::decode_list(&data);
        assert_eq!(2, list.len());
        assert_eq!(list.get(1).unwrap(), &"dog".to_string());
    }

    #[derive(RlpDecodable)]
    struct Animals {
        first: String,
        second: String,
    }

    #[derive(RlpDecodable)]
    struct AnimalsInvalid {
        first: Vec<u8>,
        second: String,
    }

    #[derive(RlpDecodable)]
    struct AnimalsGroupedStruct {
        together: Vec<String>,
    }

    #[derive(RlpDecodable)]
    struct AnimalsGroupedTupleStruct(Vec<String>);

    #[test]
    fn rlp_struct_short_list() {
        let data = vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'];
        let animals: Animals = rlp::decode(&data).unwrap();
        assert_eq!(animals.first, "cat".to_string());
        assert_eq!(animals.second, "dog".to_string());

        let animals_invalid: AnimalsInvalid = rlp::decode(&data).unwrap();
        // First is a string, so is to be ignored as the struct expects bytes.
        assert!(animals_invalid.first.is_empty());
        assert_eq!(animals_invalid.second, "dog".to_string());

        let animals_grouped_struct: AnimalsGroupedStruct = rlp::decode(&data).unwrap();
        // Neither item is detected when grouped.
        assert_eq!(animals_grouped_struct.together.len(), 0);

        let animals_grouped_tuple_struct: AnimalsGroupedTupleStruct = rlp::decode(&data).unwrap();
        // Neither item is detected when grouped as tuple.
        assert_eq!(animals_grouped_tuple_struct.0.len(), 0);
    }

    #[test]
    fn rlp_long_list_basic() {
        let data_bytes = hex::decode(BRANCH_NODE).unwrap();
        let rlp = Rlp::new(&data_bytes);
        let known_first_item = "bf5e7a6355d2aae16870034397bcb78fb7f3677302857c4e3f0f11b2ad183dda";
        let known_last_item = "";

        // As item
        assert_eq!(rlp.item_count().unwrap(), 17);
        let first_item = rlp.at(0).unwrap().data().unwrap();
        assert_eq!(first_item, hex::decode(known_first_item).unwrap());
        let last_item = rlp.at(16).unwrap().data().unwrap();
        assert_eq!(last_item, hex::decode(known_last_item).unwrap());

        // As list
        let node_list: Vec<Vec<u8>> = rlp.as_list().unwrap();
        let first_item = node_list.get(0).unwrap();
        assert_eq!(first_item, &hex::decode(known_first_item).unwrap());
    }

    #[test]
    fn rlp_long_list_basic_heterogeneous() {
        let data_bytes = hex::decode(ACCOUNT_LEAF).unwrap();
        let rlp = Rlp::new(&data_bytes);
        let known_first_item = "33269ec9b8f075a4723d27c611ac1c52a464f3516b25e0105a0d1c2210";
        // Account (list of items).
        let known_last_item = "f8440180a03836d7e3afb674e5180b7564e096f6f3e30308878a443fe59012ced093544b7fa02cfdfbdd943ec0153ed07b97f03eb765dc11cc79c6f750effcc2d126f93c4b31";

        // As item
        assert_eq!(rlp.item_count().unwrap(), 2);
        let first_item = rlp.at(0).unwrap().data().unwrap();
        assert_eq!(first_item, hex::decode(known_first_item).unwrap());
        let last_item = rlp.at(1).unwrap().data().unwrap();
        assert_eq!(last_item, hex::decode(known_last_item).unwrap());

        // As list
        let node_list: Vec<Vec<u8>> = rlp.as_list().unwrap();
        let first_item = node_list.get(0).unwrap();
        assert_eq!(first_item, &hex::decode(known_first_item).unwrap());

        // Second list
        let inner_rlp = Rlp::new(last_item);
        assert!(inner_rlp.is_list());
        let account: Account = rlp::decode(last_item).unwrap();
        assert_eq!(account.nonce, 1.into());
        let known_code_hash =
            hex::decode("2cfdfbdd943ec0153ed07b97f03eb765dc11cc79c6f750effcc2d126f93c4b31")
                .unwrap();
        assert_eq!(account.code_hash.as_bytes(), known_code_hash);
    }
}
