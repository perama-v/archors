use std::{
    array::TryFromSliceError,
    io::{self, Read},
    num::TryFromIntError,
};

use ethers::types::{H160, H256, U256, U64};
use hex::FromHexError;
use ssz_rs::SimpleSerializeError;
use thiserror::Error;

use crate::ssz::types::{SszH160, SszH256, SszU256, SszU64};

#[derive(Debug, Error)]
pub enum UtilsError {
    #[error("IO error {0}")]
    IoError(#[from] io::Error),
    #[error("Hex utils error {0}")]
    HexUtils(#[from] FromHexError),
    #[error("SimpleSerialize Error {0}")]
    SimpleSerializeError(#[from] SimpleSerializeError),
    #[error("TryFromIntError {0}")]
    TryFromIntError(#[from] TryFromIntError),
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

/// Performs snappy compression on bytes.
///
/// Takes ssz bytes, returns ssz_snappy bytes.
pub fn compress(ssz_bytes: Vec<u8>) -> Result<Vec<u8>, UtilsError> {
    /*
    Raw encoder (no frames):
    let mut snap_encoder = snap::raw::Encoder::new();
    let compressed_vec = snap_encoder.compress_vec(ssz_bytes.as_slice())?;
    */
    let mut buffer = vec![];
    snap::read::FrameEncoder::new(ssz_bytes.as_slice()).read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Performs snappy decompression on bytes.
///
/// Takes ssz_snappy bytes, returns ssz bytes.
pub fn decompress(ssz_snappy_bytes: Vec<u8>) -> Result<Vec<u8>, UtilsError> {
    /*
    Raw decoder (no frames):
    let mut snap_decoder = snap::raw::Decoder::new();
    let decompressed_vec = snap_decoder.decompress_vec(ssz_snappy_bytes.as_slice())?;
    */
    let mut buffer = vec![];
    snap::read::FrameDecoder::new(ssz_snappy_bytes.as_slice()).read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Convert ethers H256 to SSZ equivalent.
pub fn h256_to_ssz_h256(input: H256) -> Result<SszH256, UtilsError> {
    Ok(SszH256::try_from(input.0.to_vec()).map_err(|e| e.1)?)
}

/// Convert ethers H160 to SSZ equivalent.
pub fn h160_to_ssz_h160(input: H160) -> Result<SszH160, UtilsError> {
    Ok(SszH160::try_from(input.0.to_vec()).map_err(|e| e.1)?)
}

/// Convert ethers U256 to SSZ equivalent.
///
/// Output is big endian.
pub fn u256_to_ssz_u256(input: U256) -> SszU256 {
    let mut bytes = [0u8; 32];
    input.to_big_endian(&mut bytes);

    let mut output = SszU256::default();
    for byte in bytes.into_iter() {
        output.push(byte)
    }
    output
}

/// Convert ethers U64 to SSZ equivalent.
///
/// Output is big endian.
pub fn u64_to_ssz_u64(input: U64) -> SszU64 {
    let mut output = SszU64::default();
    for byte in input.0[0].to_be_bytes() {
        output.push(byte)
    }
    output
}

/// Converts usize to u16 and prevents overflow.
pub fn usize_to_u16(input: usize) -> Result<u16, UtilsError> {
    let num: u16 = input.try_into()?;
    Ok(num)
}
