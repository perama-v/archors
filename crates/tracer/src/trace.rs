//! For executing a block using state.

use archors_inventory::types::BlockProofs;
use ethers::types::{Block, Transaction};
use thiserror::Error;

/// An error with tracing a block
#[derive(Debug, Error, Eq, PartialEq)]
pub enum TraceError {
    #[error("TODO")]
    Todo,
}

pub fn trace_block(block: Block<Transaction>, state: BlockProofs) -> Result<(), TraceError> {
    todo!();
    Ok(())
}