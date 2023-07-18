//! Processes a transaction trace to produce a summary. The use case is
//! to be able to pipe any EIP-3155 output to this library.
//!
//! The input is new-line delineated JSON stream of EVM steps from stdin.

use std::{fmt::Display, io::BufRead};

use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FilterError {
    #[error("Unable to get index {index} from stack with length {length} ")]
    StackTooShort { index: usize, length: usize },
    #[error("No parent call context present to access")]
    AbsentContext,
}

/// A noteworthy occurrence whose summary might be meaningful.
#[derive(Debug,  Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Juncture<'a> {
    pub action: &'a ProcessedStep,
    pub situation: &'a Context,
    pub context_depth: usize,
}

impl Display for Juncture<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ProcessedStep::*;
        for _ in 0..self.context_depth {
            write!(f, "\t")?;
        }
        match self.action {
            Call { to: _ } |
            CallCode { to: _ } |
            DelegateCall { to: _ }|
            StaticCall { to: _ } => write!(f, "{} {}", self.action, self.situation),
            _ => write!(f, "{}", self.action),
        }

    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EvmStep {
    pub(crate) pc: u64,
    pub(crate) op: u64,
    pub(crate) gas: String,
    pub(crate) gas_cost: String,
    pub(crate) mem_size: u64,
    pub(crate) stack: Vec<String>,
    pub(crate) depth: u64,
    pub(crate) op_name: String,
    pub(crate) memory: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ProcessedStep {
    Call { to: String },
    CallCode { to: String },
    DelegateCall { to: String },
    JumpI { likely_selector: String },
    Log0,
    Log1 { name: String },
    Log2 { name: String },
    Log3 { name: String },
    Log4 { name: String },
    Push4 { stack_0: String, stack_1: String },
    Return,
    Revert,
    SelfDestruct,
    StaticCall { to: String },
    Uninteresting,
}

impl Display for ProcessedStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ProcessedStep::*;
        match self {
            Call { to: _ }
            | CallCode { to:_ }
            | DelegateCall { to:_ } | StaticCall { to:_ } => write!(f, "Contract"),
            | JumpI { likely_selector } => write!(f, "Function {likely_selector}"),
            | Log0 => write!(f, "Log created"),
            | Log1 { name }
            | Log2 { name }
            | Log3 { name }
            | Log4 { name } => write!(f, "Log created ({name})"),
            | Push4 { stack_0:_, stack_1:_ } => Ok(()),
            | Return =>  write!(f, "Returned"),
            | Revert =>  write!(f, "Reverted"),
            | SelfDestruct =>  write!(f, "Self destructed"),
            | Uninteresting => Ok(()),
        }
    }
}


pub fn process_trace() {
    let stdin = std::io::stdin();
    let reader = stdin.lock();

    let mut context: Vec<Context> = vec![Context::default()];
    println!("Starting transaction... {}", Context::default());

    reader
        .lines()
        .filter_map(|line| match line {
            Ok(l) => Some(l),
            Err(_) => None, // Bad stdin line
        })
        .filter_map(|line| match serde_json::from_str::<EvmStep>(&line) {
            Ok(l) => Some(l),
            Err(_) => None, // Not an EvmStep (e.g., output)
        })
        .filter_map(|step| process_step(step))
        .for_each(|step| {
            match update_context(&mut context, &step) {
                Ok(_) => {}
                Err(_) => todo!(),
            };
            let current_context = match context.last() {
                Some(c) => c,
                None => todo!(),
            };
            let juncture = Juncture{ action: &step, situation: current_context, context_depth: context.len() };
            println!("{juncture}");
            //println!("{}", json!(juncture));
        });
}

impl TryFrom<EvmStep> for ProcessedStep {
    type Error = FilterError;
    fn try_from(value: EvmStep) -> Result<Self, Self::Error> {
        let op_name = value.op_name.as_str();
        Ok(match op_name {
            "CALL" => Self::Call {
                to: stack_nth(&value.stack, 1)?,
            },
            "CALLCODE" => Self::CallCode {
                to: stack_nth(&value.stack, 1)?,
            },
            "DELEGATECALL" => Self::DelegateCall {
                to: stack_nth(&value.stack, 1)?,
            },
            "STATICCALL" => Self::DelegateCall {
                to: stack_nth(&value.stack, 1)?,
            },
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
                    Self::JumpI {
                        likely_selector: reserved,
                    }
                } else {
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
            "RETURN" => Self::Return,
            "REVERT" => Self::Revert,
            "SELFDESTRUCT" => Self::SelfDestruct,
            _ => Self::Uninteresting,
        })
    }
}

/// Context during EVM execution.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Context {
    /// Address where the code being executed resides
    pub code_address: String,
    /// Address message.sender resolves at this time.
    pub message_sender: String,
    /// Address that storage modifications affect.
    pub storage_address: String,
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
            write!(f, "using code and storage at {}, message.sender is {}", self.code_address, self.message_sender)
        } else {
            write!(f, "using code at {}, storage at {}, message.sender is {}", self.code_address, self.storage_address, self.message_sender)
        }

    }
}

/// An EVM step is replaced by a new representation if it is of interest.
fn process_step(step: EvmStep) -> Option<ProcessedStep> {
    match ProcessedStep::try_from(step) {
        Ok(ProcessedStep::Uninteresting) => None,
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

/// Gets item from the stack by index. Stack is a slice where top (index 0) is last.
fn stack_nth(stack: &[String], index: usize) -> Result<String, FilterError> {
    let length = stack.len();
    Ok(stack
        .get(length - 1 - index)
        .ok_or(FilterError::StackTooShort { index, length })?
        .to_owned())
}

/// If a opcode affects the call context, record the change.
fn update_context(context: &mut Vec<Context>, step: &ProcessedStep) -> Result<(), FilterError> {
    match step {
        ProcessedStep::Call { to } | ProcessedStep::StaticCall { to } => {
            // Add a new context.
            let previous = context.last().ok_or(FilterError::AbsentContext)?;
            context.push(Context {
                code_address: to.clone(),
                message_sender: previous.message_sender.clone(),
                storage_address: to.clone(),
            })
        }
        ProcessedStep::CallCode { to } => {
            let previous = context.last().ok_or(FilterError::AbsentContext)?;
            context.push(Context {
                code_address: to.clone(),
                message_sender: previous.code_address.clone(), // important
                storage_address: previous.storage_address.clone(),
            })
        }
        ProcessedStep::DelegateCall { to } => {
            let previous = context.last().ok_or(FilterError::AbsentContext)?;
            context.push(Context {
                code_address: to.clone(),
                message_sender: previous.message_sender.clone(), // important
                storage_address: previous.storage_address.clone(),
            })
        }
        ProcessedStep::Return | ProcessedStep::Revert | ProcessedStep::SelfDestruct => {
            context.pop().ok_or(FilterError::AbsentContext)?;
            return Ok(());
        }
        _ => {}
    }
    Ok(())
}
