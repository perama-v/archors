/// Converts bytes to 0x-prefixed hex string.
pub fn hex_encode<T: AsRef<[u8]>>(bytes: T) -> String {
    format!("0x{}", hex::encode(bytes))
}
