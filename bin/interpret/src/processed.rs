//! For the processed representation of a single instruction/opcode.
//!
//! For example, a CALL to an account with no code can be represented
//! as a payment.

use serde::{Deserialize, Serialize};
use std::fmt::Display;

use crate::{
    ether::Ether,
    opcode::{Eip3155Line, EvmOutput, EvmStep},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProcessedError {
    #[error("Unable to get index {index} from stack with length {length} ")]
    StackTooShort { index: usize, length: usize },

    #[error("serde_json error {0}")]
    SerdeJson(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProcessedStep {
    // Address {}, // Could use to give extra context.
    Call {
        to: String,
        value: String,
    },
    CallCode {
        to: String,
        value: String,
    },
    Create,
    Create2,
    DelegateCall {
        to: String,
        value: String,
    },
    /// Function call identified by use of a selector/JUMPI combination.
    Function {
        likely_selector: String,
    },
    Log0,
    Log1 {
        name: String,
    },
    Log2 {
        name: String,
    },
    Log3 {
        name: String,
    },
    Log4 {
        name: String,
    },
    Push4 {
        stack_0: String,
        stack_1: String,
    },
    /// A call variant made to a precompile contract.
    Precompile,
    /// A call variant made to an account with no code (just pays ether to it).
    PayCall {
        to: String,
        value: Ether,
        opcode: String,
    },
    Invalid,
    Return {
        stack_top_next: StackTopNext,
    },
    Revert,
    SelfDestruct,
    StaticCall {
        to: String,
    },
    Stop {
        stack_top_next: StackTopNext,
    },
    /// Deduction of how a transaction ended.
    TxFinished(FinishMechanism),
    /// EVM output containing specific post-transaction facts.
    TxSummary {
        output: String,
        gas_used: String,
    },
    Uninteresting,
}

impl TryFrom<&EvmStep> for ProcessedStep {
    type Error = ProcessedError;
    fn try_from(value: &EvmStep) -> Result<Self, Self::Error> {
        let op_name = value.op_name.as_str();
        Ok(match op_name {
            "CALL" => {
                let to = stack_nth(&value.stack, 1)?;
                let value = stack_nth(&value.stack, 2)?;
                match is_precompile(&to) {
                    true => Self::Precompile,
                    false => Self::Call { to, value },
                }
            }
            "CALLCODE" => {
                let to = stack_nth(&value.stack, 1)?;
                let value = stack_nth(&value.stack, 2)?;
                match is_precompile(&to) {
                    true => Self::Precompile,
                    false => Self::CallCode { to, value },
                }
            }
            "CREATE" => Self::Create,
            "CREATE2" => Self::Create2,
            "DELEGATECALL" => {
                let to = stack_nth(&value.stack, 1)?;
                let value = stack_nth(&value.stack, 2)?;
                match is_precompile(&to) {
                    true => Self::Precompile,
                    false => Self::DelegateCall { to, value },
                }
            }
            "STATICCALL" => {
                let to = stack_nth(&value.stack, 1)?;
                match is_precompile(&to) {
                    true => Self::Precompile,
                    false => Self::StaticCall { to },
                }
            }
            "PUSH4" => {
                // Could use for jumptable heuristics if need.
                // Count steps since PUSH4, where stack[0] == stack[1] and if JUMPI within ~5,
                // it is likely to be function call via jump table.
                Self::Uninteresting
            }
            "JUMPI" => {
                // Pattern if jumping within a jump table.
                // The third item on the stack usually contains the selector of interest
                // because it is prepared for failed lookups.
                // Next lookup is loaded by DUP1 -> PUSH4 -> JUMPI or similar.
                let reserved = stack_nth(&value.stack, 2)?;
                let four_bytes_reserved = reserved.len() == 10; // ten chars 0x00000000
                let jumping = stack_nth(&value.stack, 1)? != "0x0";
                if four_bytes_reserved && jumping {
                    // Using a jump table
                    Self::Function {
                        likely_selector: reserved,
                    }
                } else {
                    // Some JUMPI use not in a a function jump table
                    Self::Uninteresting
                }
            }
            "LOG0" => Self::Log0,
            "LOG1" => Self::Log1 {
                name: stack_nth(&value.stack, 2)?,
            },
            "LOG2" => Self::Log2 {
                name: stack_nth(&value.stack, 2)?,
            },
            "LOG3" => Self::Log3 {
                name: stack_nth(&value.stack, 2)?,
            },
            "LOG4" => Self::Log4 {
                name: stack_nth(&value.stack, 2)?,
            },
            "INVALID" => match value.depth {
                1 => Self::TxFinished(FinishMechanism::Invalid),
                _ => Self::Return {
                    stack_top_next: StackTopNext::NotChecked,
                },
            },
            "RETURN" => match value.depth {
                1 => Self::TxFinished(FinishMechanism::Return),
                _ => Self::Return {
                    stack_top_next: StackTopNext::NotChecked,
                },
            },
            "REVERT" => match value.depth {
                1 => Self::TxFinished(FinishMechanism::Revert),
                _ => Self::Revert,
            },
            "STOP" => {
                match value.depth {
                    0 => Self::Uninteresting, // Artefact unique to revm (used at start of transactions)
                    1 => Self::TxFinished(FinishMechanism::Stop),
                    _ => Self::Stop {
                        stack_top_next: StackTopNext::NotChecked,
                    },
                }
            }
            "SELFDESTRUCT" => Self::SelfDestruct,

            _ => Self::Uninteresting,
        })
    }
}

impl ProcessedStep {
    /// Includes additional information using the next line from the trace.
    ///
    /// E.g., read the top of the stack to see what the effect of the opcode was.
    pub(crate) fn add_peek(&mut self, current_raw: &Eip3155Line, peek_raw: &Eip3155Line) {
        match self {
            ProcessedStep::Call { to, value } => {
                if current_raw.same_depth(peek_raw) {
                    // No depth increase, therefore is a pay to no-code account.
                    *self = ProcessedStep::PayCall {
                        to: to.clone(),
                        value: Ether(value.to_string()),
                        opcode: "CALL".to_string(),
                    }
                }
            }
            ProcessedStep::CallCode { to, value } => {
                if current_raw.same_depth(peek_raw) {
                    // No depth increase, therefore is a pay to no-code account.
                    *self = ProcessedStep::PayCall {
                        to: to.clone(),
                        value: Ether(value.clone()),
                        opcode: "CALLCODE".to_string(),
                    }
                }
            }

            ProcessedStep::DelegateCall { to, value } => {
                if current_raw.same_depth(peek_raw) {
                    // No depth increase, therefore is a pay to no-code account.
                    *self = ProcessedStep::PayCall {
                        to: to.clone(),
                        value: Ether(value.clone()),
                        opcode: "DELEGATECALL".to_string(),
                    }
                }
            }
            ProcessedStep::Return { stack_top_next } | ProcessedStep::Stop { stack_top_next } => {
                // If something is returned, it will be at the top of the stack of the next step/line.
                match peek_raw {
                    Eip3155Line::Step(s) => {
                        *stack_top_next = match s.stack.last() {
                            Some(item) => StackTopNext::Some(item.clone()),
                            None => StackTopNext::None,
                        };
                    }
                    Eip3155Line::Output(_) => {}
                };
            }
            _ => {}
        }
    }
}

impl Display for ProcessedStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ProcessedStep::*;
        match self {
            Call { to: _, value: _ } => write!(f, "Contract (CALL)"),
            CallCode { to: _, value: _ } => write!(f, "Contract (CALLCODE)"),
            Create => write!(f, "Deploy contract (CREATE)"),
            Create2 => write!(f, "Deploy contract (CREATE2)"),
            DelegateCall { to: _, value: _ } => write!(f, "Contract (DELEGATECALL)"),
            StaticCall { to: _ } => write!(f, "Contract (STATICCALL)"),
            Function { likely_selector } => write!(f, "Function {likely_selector}"),
            Log0 => write!(f, "Log created"),
            Log1 { name } => write!(f, "Log1 created ({name})"),
            Log2 { name } => write!(f, "Log2 created ({name})"),
            Log3 { name } => write!(f, "Log3 created ({name})"),
            Log4 { name } => write!(f, "Log4 created ({name})"),
            Push4 {
                stack_0: _,
                stack_1: _,
            } => Ok(()),
            PayCall { to, value, opcode } => write!(
                f,
                "{value} ether paid to {to} ({opcode} to codeless account)"
            ),
            Precompile => write!(f, "Precompile used"),
            Invalid => write!(f, "Invalid opcode"),
            Return { stack_top_next: _ } => {
                write!(f, "Returned")
            }
            Revert => write!(f, "Reverted"),
            SelfDestruct => write!(f, "Self destructed"),
            Stop { stack_top_next: _ } => {
                write!(f, "Stopped")
            }
            TxFinished(mechanism) => write!(f, "Transaction finished ({mechanism})"),
            TxSummary { output, gas_used } => write!(
                f,
                "Transaction summary, gas used: {gas_used}, output: {output}"
            ),
            Uninteresting => Ok(()),
        }
    }
}

impl From<&EvmOutput> for ProcessedStep {
    fn from(value: &EvmOutput) -> Self {
        ProcessedStep::TxSummary {
            output: value.output.clone(),
            gas_used: value.gas_used.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FinishMechanism {
    Invalid,
    Stop,
    Return,
    Revert,
}

impl Display for FinishMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = match self {
            FinishMechanism::Invalid => "INVALID",
            FinishMechanism::Stop => "STOP",
            FinishMechanism::Return => "RETURN",
            FinishMechanism::Revert => "REVERT",
        };
        write!(f, "{m}")
    }
}

/// Gets item from the stack by index. Stack is a slice where top (index 0) is last.
fn stack_nth(stack: &[String], index: usize) -> Result<String, ProcessedError> {
    let length = stack.len();
    Ok(stack
        .get(length - 1 - index)
        .ok_or(ProcessedError::StackTooShort { index, length })?
        .to_owned())
}

/// Addresses of known precompile contracts
///
/// Useful because precompiles do not create a new call context.
pub fn is_precompile<T: AsRef<str>>(address: T) -> bool {
    matches!(
        address.as_ref(),
        "0x1" | "0x2" | "0x3" | "0x4" | "0x5" | "0x6" | "0x7" | "0x8" | "0x9"
    )
}

// Top of the stack for the next opcode.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StackTopNext {
    NotChecked,
    None,
    Some(String),
}
