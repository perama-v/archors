use hex::FromHexError;
use revm::primitives::U256;
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

/// Ethers H256 to revm U256
pub fn eh256_to_ru256(input: ethers::types::H256) -> Result<U256, UtilsError> {
    let bytes: &[u8; 32] = input.as_fixed_bytes();
    let value = U256::from_be_bytes(*bytes);
    Ok(value)
}

#[cfg(test)]
mod test {
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
    fn test_eh256_to_ru256() {
        let input = ethers::types::H256::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000001234",
        )
        .unwrap();
        let derived: U256 = eh256_to_ru256(input).unwrap();
        let expected: U256 = U256::try_from_be_slice(&hex_decode("0x1234").unwrap()).unwrap();
        assert_eq!(derived, expected);
    }
}
