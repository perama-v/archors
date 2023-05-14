use std::io::{self, Read};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum UtilsError {
    #[error("IO error {0}")]
    IoError(#[from] io::Error),
}

/// Converts bytes to 0x-prefixed hex string.
pub fn hex_encode<T: AsRef<[u8]>>(bytes: T) -> String {
    format!("0x{}", hex::encode(bytes))
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
