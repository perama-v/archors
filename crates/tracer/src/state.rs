//! For representing state for an historical block.

use archors_inventory::types::BlockProofs;

/// Properties that state representation must have.
///
/// This is useful if there is a more efficient way to represent
/// state compared to unmodified EIP-1186 response, which has duplicate
/// data.
trait BlockState {
    /// Get a value for a storage key.
    fn read_key() {}
    /// Modify a value for a storage key.
    fn write_key() {}
}


impl BlockState for BlockProofs {
    fn read_key() {
        println!();
    }

    fn write_key() {}
}
