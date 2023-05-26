use ethers::types::transaction::eip2930::AccessList;
use hex::FromHexError;
use revm::primitives::{B160, U256};
use thiserror::Error;

/// An error with tracing a block
#[derive(Debug, Error, PartialEq)]
pub enum UtilsError {
    #[error("Unable to convert Ethers H256 ({0}) to revm U256 ")]
    H256ValueTooLarge(String),
    #[error("Unable to convert Ethers U256 ({0}) to revm U256 ")]
    U256ValueTooLarge(String),
    #[error("Hex utils error {0}")]
    HexUtils(#[from] FromHexError),
}

/// Converts bytes to 0x-prefixed hex string.
pub fn hex_encode<T: AsRef<[u8]>>(bytes: T) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Converts 0x-prefixed hex string to bytes.
pub fn hex_decode<T: AsRef<str>>(string: T) -> Result<Vec<u8>, UtilsError> {
    let s = string.as_ref().trim_start_matches("0x");
    Ok(hex::decode(s)?)
}

/// Ethers U256 to revm U256
pub fn eu256_to_ru256(input: ethers::types::U256) -> Result<U256, UtilsError> {
    let mut bytes = [0u8; 32];
    input.to_big_endian(&mut bytes);
    let value = U256::from_be_bytes(bytes);
    Ok(value)
}

/// Ethers U64 to revm U256
pub fn eu64_to_ru256(input: ethers::types::U64) -> Result<U256, UtilsError> {
    let mut bytes = [0u8; 32];
    input.to_big_endian(&mut bytes);
    let value = U256::from_be_bytes(bytes);
    Ok(value)
}

/// Ethers U256 to u64
pub fn eu256_to_u64(input: ethers::types::U256) -> u64 {
    let mut bytes = [0u8; 8];
    input.to_big_endian(&mut bytes);

    u64::from_be_bytes(bytes)
}

/// revm U256 to u64
pub fn ru256_to_u64(input: U256) -> u64 {
    let bytes = input.to_be_bytes();

    u64::from_be_bytes(bytes)
}

/// Ethers H256 to revm U256
pub fn eh256_to_ru256(input: ethers::types::H256) -> U256 {
    let bytes: &[u8; 32] = input.as_fixed_bytes();

    U256::from_be_bytes(*bytes)
}

/// Helper for revm access list type conversion.
type RevmAccessList = Vec<RevmAccessesListItem>;

/// Helper for revm access list item type conversion.
type RevmAccessesListItem = (B160, Vec<U256>);

/// Ethers AccessList to revm access list
pub fn access_list_e_to_r(input: AccessList) -> RevmAccessList {
    input
        .0
        .into_iter()
        .map(|list| {
            let out_address: B160 = list.address.0.into();
            let out_values: Vec<U256> = list.storage_keys.into_iter().map(eh256_to_ru256).collect();
            (out_address, out_values)
        })
        .collect()
}

#[cfg(test)]
mod test {
    use ethers::types::{transaction::eip2930::AccessListItem, H160, H256};

    use super::*;

    use std::str::FromStr;

    #[test]
    fn test_eu256_to_ru256() {
        let input = ethers::types::U256::from_str("0x1234").unwrap();
        let derived: U256 = eu256_to_ru256(input).unwrap();
        let expected: U256 = U256::try_from_be_slice(&hex_decode("0x1234").unwrap()).unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_eu64_to_ru256() {
        let input = ethers::types::U64::from_str("0x1234").unwrap();
        let derived: U256 = eu64_to_ru256(input).unwrap();
        let expected: U256 = U256::try_from_be_slice(&hex_decode("0x1234").unwrap()).unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_eu256_to_u64() {
        let input = ethers::types::U256::from_str("0x1234").unwrap();
        let derived: u64 = eu256_to_u64(input);
        let expected: u64 = u64::from_str("0x1234").unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_ru256_to_u64() {
        let input = U256::from_str("0x1234").unwrap();
        let derived: u64 = ru256_to_u64(input);
        let expected: u64 = u64::from_str("0x1234").unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_eh256_to_ru256() {
        let input = ethers::types::H256::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000001234",
        )
        .unwrap();
        let derived: U256 = eh256_to_ru256(input);
        let expected: U256 = U256::try_from_be_slice(&hex_decode("0x1234").unwrap()).unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_access_list_e_to_r() {
        let input: AccessList = AccessList(vec![AccessListItem {
            address: H160::from_str("0x00004400").unwrap(),
            storage_keys: vec![H256::from_str("0x1234").unwrap()],
        }]);

        let derived = access_list_e_to_r(input);
        let address = B160::from_str("0x00004400").unwrap();
        let storage = U256::try_from_be_slice(&hex_decode("0x1234").unwrap()).unwrap();
        let expected: RevmAccessList = vec![(address, vec![storage])];
        assert_eq!(derived, expected);
    }
}
