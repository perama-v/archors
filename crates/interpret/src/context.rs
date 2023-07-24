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
    pub code_address: String,
    /// Address message.sender resolves at this time.
    pub message_sender: String,
    /// Address that storage modifications affect.
    pub storage_address: String,
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
) -> Result<ContextUpdate, ContextError> {
    match step {
        ProcessedStep::Call { to, value: _ } | ProcessedStep::StaticCall { to } => {
            if is_precompile(to) {
                return Ok(ContextUpdate::None);
            }
            let previous = context.last().ok_or(ContextError::AbsentContext)?;
            Ok(ContextUpdate::Add(Context {
                code_address: to.clone(),
                message_sender: previous.message_sender.clone(),
                storage_address: to.clone(),
            }))
        }
        ProcessedStep::CallCode { to, value: _ } => {
            if is_precompile(to) {
                return Ok(ContextUpdate::None);
            }
            let previous = context.last().ok_or(ContextError::AbsentContext)?;
            Ok(ContextUpdate::Add(Context {
                code_address: to.clone(),
                message_sender: previous.code_address.clone(), // important
                storage_address: previous.storage_address.clone(),
            }))
        }
        ProcessedStep::DelegateCall { to, value: _ } => {
            if is_precompile(to) {
                return Ok(ContextUpdate::None);
            }
            let previous = context.last().ok_or(ContextError::AbsentContext)?;
            Ok(ContextUpdate::Add(Context {
                code_address: to.clone(),
                message_sender: previous.message_sender.clone(), // important
                storage_address: previous.storage_address.clone(),
            }))
        }
        ProcessedStep::Invalid
        | ProcessedStep::Return
        | ProcessedStep::Revert
        | ProcessedStep::SelfDestruct
        | ProcessedStep::Stop => Ok(ContextUpdate::Remove),
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
            code_address: "tx.to".to_string(),
            message_sender: "tx.from".to_string(),
            storage_address: "tx.to".to_string(),
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
