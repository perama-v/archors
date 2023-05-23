use std::{
    array::TryFromSliceError,
    io::{self},
};

use hex::FromHexError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UtilsError {
    #[error("IO error {0}")]
    IoError(#[from] io::Error),
    #[error("Hex utils error {0}")]
    HexUtils(#[from] FromHexError),
    #[error("TryFromSlice utils error {0}")]
    TryFromSlice(#[from] TryFromSliceError),
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
