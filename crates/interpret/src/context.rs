//! Information important at the time of a single opcode step in the EVM.

use serde::{Deserialize, Serialize};
use std::fmt::Display;

use crate::processed::{is_precompile, ProcessedStep};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContextError {
    #[error("No parent call context present to access")]
    AbsentContext,
    #[error("serde_json error {0}")]
    SerdeJson(#[from] serde_json::Error),
}

/// Context during EVM execution.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Context {
    /// Address where the code being executed resides
    pub code_address: Address,
    /// Address message.sender resolves at this time.
    pub message_sender: Address,
    /// Address that storage modifications affect.
    pub storage_address: Address,
    /// Create-related information
    pub create_data: Option<CreateData>,
}

/// Create-related context
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateData {
    /// Contract creation index for transaction (first = 0, ...)
    ///
    /// Every use of CREATE/CREATE2 increments the index. Keeps track of addresses
    /// when they are returned.
    pub index: usize,
}

/// A contract may
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Address {
    /// Either existing or deployed via tx.to being nil (not using CREATE/CREATE2)
    Standard(String),
    /// New contract via CREATE/CREATE2, address not yet visible on the stack.
    ///
    /// The first created contract has index 0, increments thereafter.
    CreatedPending { index: usize },
}

/// An opcode may cause a change to the context that will apply to the next
/// EVM step.
pub enum ContextUpdate {
    /// Context does not need changing.
    None,
    /// Context needs to be added (e.g., entering a contract call).
    Add(Context),
    /// Current context needs to be removed (e.g., returning from a contract call).
    Remove,
    /// A new context is needed for the next transaction.
    Reset,
}

/// If a opcode affects the call context, determine the new context it would create.
///
/// It may ultimetely not be applied (e.g., CALL to EOA).
pub fn get_pending_context_update(
    context: &[Context],
    step: &ProcessedStep,
    create_counter: &mut usize,
) -> Result<ContextUpdate, ContextError> {
    match step {
        ProcessedStep::Call { to, value: _ } | ProcessedStep::StaticCall { to } => {
            if is_precompile(to) {
                return Ok(ContextUpdate::None);
            }
            let previous = context.last().ok_or(ContextError::AbsentContext)?;
            Ok(ContextUpdate::Add(Context {
                code_address: Address::Standard(to.clone()),
                message_sender: previous.message_sender.clone(),
                storage_address: Address::Standard(to.clone()),
                create_data: None,
            }))
        }
        ProcessedStep::CallCode { to, value: _ } => {
            if is_precompile(to) {
                return Ok(ContextUpdate::None);
            }
            let previous = context.last().ok_or(ContextError::AbsentContext)?;
            Ok(ContextUpdate::Add(Context {
                code_address: Address::Standard(to.clone()),
                message_sender: previous.code_address.clone(), // important
                storage_address: previous.storage_address.clone(),
                create_data: None,
            }))
        }
        ProcessedStep::DelegateCall { to, value: _ } => {
            if is_precompile(to) {
                return Ok(ContextUpdate::None);
            }
            let previous = context.last().ok_or(ContextError::AbsentContext)?;
            Ok(ContextUpdate::Add(Context {
                code_address: Address::Standard(to.clone()),
                message_sender: previous.message_sender.clone(), // important
                storage_address: previous.storage_address.clone(),
                create_data: None,
            }))
        }
        ProcessedStep::Create | ProcessedStep::Create2 => {
            let previous = context.last().ok_or(ContextError::AbsentContext)?;
            let update = ContextUpdate::Add(Context {
                code_address: Address::CreatedPending {
                    index: *create_counter,
                },
                message_sender: previous.message_sender.clone(),
                storage_address: Address::CreatedPending {
                    index: *create_counter,
                },
                create_data: Some(CreateData {
                    index: *create_counter,
                }),
            });
            // The next contract created will have a different index.
            *create_counter += 1;
            Ok(update)
        }
        ProcessedStep::Invalid
        | ProcessedStep::Return { stack_top_next: _ }
        | ProcessedStep::Revert
        | ProcessedStep::SelfDestruct
        | ProcessedStep::Stop { stack_top_next: _ } => Ok(ContextUpdate::Remove),
        ProcessedStep::TxFinished(_) => Ok(ContextUpdate::Reset),
        _ => Ok(ContextUpdate::None),
    }
}

/// Apply pending context to the current step.
pub fn apply_pending_context(context: &mut Vec<Context>, pending_context: &mut ContextUpdate) {
    match &pending_context {
        ContextUpdate::None => {}
        ContextUpdate::Add(pending) => {
            context.push(pending.clone());
        }
        ContextUpdate::Remove => {
            context.pop().unwrap();
        }
        ContextUpdate::Reset => {
            context.clear();
            context.push(Context::default());
        }
    }
    *pending_context = ContextUpdate::None;
}

impl Default for Context {
    fn default() -> Self {
        Self {
            code_address: Address::Standard("tx.to".to_string()),
            message_sender: Address::Standard("tx.from".to_string()),
            storage_address: Address::Standard("tx.to".to_string()),
            create_data: None,
        }
    }
}

impl Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.code_address == self.storage_address {
            write!(
                f,
                "using code and storage at {}, message.sender is {}",
                self.code_address, self.message_sender
            )
        } else {
            write!(
                f,
                "using code at {}, storage at {}, message.sender is {}",
                self.code_address, self.storage_address, self.message_sender
            )
        }
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Standard(address) => write!(f, "{address}"),
            Address::CreatedPending { index } => write!(f, "created contract (index {index})"),
        }
    }
}
