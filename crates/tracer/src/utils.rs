use archors_types::alias::{SszH256, SszU256, SszU64};
use ethers::types::transaction::eip2930::AccessList;
use hex::FromHexError;
use revm::primitives::{B160, B256, U256};
use thiserror::Error;

/// An error with tracing a block
#[derive(Debug, Error, PartialEq)]
pub enum UtilsError {
    #[error("Unable to convert SSZ list to revm U256")]
    InvalidU256List,
    #[error("Unable to convert SSZ vector to revm U256")]
    InvalidH256Vector,
    #[error("Unable to convert SSZ bytes to u64")]
    InvalidU64List,
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
pub fn eu64_to_ru256(input: ethers::types::U64) -> U256 {
    U256::from_limbs_slice(input.0.as_slice())
}

/// Ethers U256 to u64
pub fn eu256_to_u64(input: ethers::types::U256) -> u64 {
    input.as_u64()
}

/// revm U256 to u64
pub fn ru256_to_u64(input: U256) -> u64 {
    let limbs = input.as_limbs();
    limbs[0]
}

/// Ethers H256 to revm U256
pub fn eh256_to_ru256(input: ethers::types::H256) -> U256 {
    let bytes: &[u8; 32] = input.as_fixed_bytes();

    U256::from_be_bytes(*bytes)
}

/// revm U256 to ethers U256
pub fn ru256_to_eu256(input: U256) -> ethers::types::U256 {
    let slice = input.as_le_slice();
    ethers::types::U256::from_little_endian(slice)
}

/// revm U256 to ethers H256
pub fn ru256_to_eh256(input: U256) -> ethers::types::H256 {
    let array: [u8; 32] = input.to_be_bytes();
    array.into()
}

/// revm B256 to ethers H256
pub fn rb256_to_eh256(input: revm::primitives::B256) -> ethers::types::H256 {
    let bytes: &[u8; 32] = input.as_fixed_bytes();
    bytes.into()
}

/// revm B160 to ethers H160
pub fn rb160_to_eh160(input: B160) -> ethers::types::H160 {
    let bytes: &[u8; 20] = input.as_fixed_bytes();
    bytes.into()
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

/// Convert SSZ U256 equivalent to revm U256.
///
/// Input is big endian.
pub fn ssz_u256_to_ru256(input: SszU256) -> Result<U256, UtilsError> {
    U256::try_from_be_slice(input.as_slice()).ok_or(UtilsError::InvalidU256List)
}

/// Convert SSZ H256 equivalent to revm U256.
///
/// Input is big endian.
pub fn ssz_h256_to_ru256(input: SszH256) -> Result<U256, UtilsError> {
    U256::try_from_be_slice(input.as_slice()).ok_or(UtilsError::InvalidH256Vector)
}

/// Convert SSZ U64 equivalent to u64.
///
/// Input is big endian.
pub fn ssz_u64_to_u64(input: SszU64) -> Result<u64, UtilsError> {
    let bytes = input.as_slice();
    let num = u64::from_be_bytes(bytes.try_into().map_err(|_| UtilsError::InvalidU64List)?);
    Ok(num)
}

/// Convert SSZ H256 equivalent to revm B256.
///
/// Input is big endian.
pub fn ssz_h256_to_rb256(input: &SszH256) -> B256 {
    B256::from_slice(input)
}

#[cfg(test)]
mod test {
    use ethers::types::{transaction::eip2930::AccessListItem, H160, H256};
    use revm::primitives::B256;

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
        let derived: U256 = eu64_to_ru256(input);
        let expected: U256 = U256::try_from_be_slice(&hex_decode("0x1234").unwrap()).unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_eu256_to_u64() {
        let input = ethers::types::U256::from_str("0x1234").unwrap();
        let derived: u64 = eu256_to_u64(input);
        let expected: u64 = 4660u64; // 0x1234
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_ru256_to_u64() {
        let input = U256::from_str("0x1234").unwrap();
        let derived: u64 = ru256_to_u64(input);
        let expected: u64 = 4660u64; // 0x1234
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
    fn test_ru256_to_eu256() {
        let input = U256::from_str("0x1234").unwrap();
        let derived = ru256_to_eu256(input);
        let expected = ethers::types::U256::from_str("0x1234").unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_ru256_to_eh256() {
        let input = U256::from_str("0x1234").unwrap();
        let derived = ru256_to_eh256(input);
        let expected = ethers::types::H256::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000001234",
        )
        .unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_rb256_to_eh256() {
        let hash_string = "0x0000000000000000000000000000000000000000000000000000000000001234";
        let input = B256::from_str(hash_string).unwrap();
        let derived = rb256_to_eh256(input);
        let expected = ethers::types::H256::from_str(hash_string).unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_rb160_to_eh160() {
        let hash_string = "0x0000000000000000000000000000000000001234";
        let input = B160::from_str(hash_string).unwrap();
        let derived = rb160_to_eh160(input);
        let expected = ethers::types::H160::from_str(hash_string).unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_access_list_e_to_r() {
        let address = "0x0000000000000000000000000000000000009876";
        let hash = "0x0000000000000000000000000000000000000000000000000000000000001234";
        let input: AccessList = AccessList(vec![AccessListItem {
            address: H160::from_str(address).unwrap(),
            storage_keys: vec![H256::from_str(hash).unwrap()],
        }]);

        let derived = access_list_e_to_r(input);
        let address = B160::from_str(address).unwrap();
        let storage = U256::try_from_be_slice(&hex_decode(hash).unwrap()).unwrap();
        let expected: RevmAccessList = vec![(address, vec![storage])];
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_ssz_u64_to_u64() {
        let expected = 123456789_u64;
        let bytes = expected.to_be_bytes();
        let mut ssz = SszU64::default();
        for byte in bytes {
            ssz.push(byte)
        }
        let derived = ssz_u64_to_u64(ssz).unwrap();
        assert_eq!(expected, derived);
    }

    #[test]
    fn test_ssz_u256_to_ru256() {
        let expected =
            U256::from(0x0000000000000000000000000000000000000000000000000000000000001234);
        let bytes = expected.to_be_bytes_vec();
        let ssz = SszU256::try_from(bytes).unwrap();
        let derived = ssz_u256_to_ru256(ssz).unwrap();
        assert_eq!(derived, expected);
    }
}
