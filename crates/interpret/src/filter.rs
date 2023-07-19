//! Processes a transaction trace to produce a summary. The use case is
//! to be able to pipe any EIP-3155 output to this library.
//!
//! The input is new-line delineated JSON stream of EVM steps from stdin.
//!
//! Note that a line in a trace is pre-application of the opcode. E.g., the opcode will
//! use the values in the stack on the same line.

use std::{fmt::Display, io::BufRead};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FilterError {
    #[error("Unable to get index {index} from stack with length {length} ")]
    StackTooShort { index: usize, length: usize },
    #[error("No parent call context present to access")]
    AbsentContext,
    #[error("serde_json error {0}")]
    SerdeJson(#[from] serde_json::Error),
}

/// A noteworthy occurrence whose summary might be meaningful.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Juncture<'a> {
    /// Transaction number encountered, not transaction index in block.
    pub transaction: usize,
    pub action: &'a ProcessedStep,
    pub current_context: &'a Context,
    pub context_depth: usize,
}

impl Display for Juncture<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ProcessedStep::*;
        for _ in 0..self.context_depth {
            write!(f, "\t")?;
        }
        match self.action {
            Call { to: _ } | CallCode { to: _ } | DelegateCall { to: _ } | StaticCall { to: _ } => {
                write!(f, "{} {}", self.action, self.current_context)
            }
            PayCall { to: _ } => write!(
                f,
                "{} from {}",
                self.action, self.current_context.message_sender
            ),
            _ => write!(f, "{}", self.action),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
    pub(crate) processed_step: Option<ProcessedStep>,
}

impl EvmStep {
    // Indicates the start of the transaction (revm).
    fn start_transaction() -> Result<Self, FilterError> {
        let json = r#"{"pc":0,"op":0,"gas":"0x0","gasCost":"0x0","memSize":0,"stack":[],"depth":0,"opName":"STOP"}"#;
        let e: EvmStep = serde_json::from_str(json)?;
        Ok(e)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ProcessedStep {
    Call {
        to: String,
    },
    CallCode {
        to: String,
    },
    DelegateCall {
        to: String,
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
    },
    Return,
    Revert,
    SelfDestruct,
    Start,
    StaticCall {
        to: String,
    },
    Stop,
    Uninteresting,
}

impl Display for ProcessedStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ProcessedStep::*;
        match self {
            Call { to: _ } =>  write!(f, "Contract (CALL)"),
            CallCode { to: _ } =>  write!(f, "Contract (CALLCODE)"),
            DelegateCall { to: _ } =>  write!(f, "Contract (DELEGATECALL)"),
            StaticCall { to: _ } =>  write!(f, "Contract (STATICCALL)"),
            Function { likely_selector } => write!(f, "Function {likely_selector}"),
            Log0 => write!(f, "Log created"),
            Log1 { name }=> write!(f, "Log1 created ({name})"),
            Log2 { name }=> write!(f, "Log2 created ({name})"),
            Log3 { name }=> write!(f, "Log3 created ({name})"),
            Log4 { name }=> write!(f, "Log4 created ({name})"),
            Push4 {
                stack_0: _,
                stack_1: _,
            } => Ok(()),
            PayCall { to } => write!(
                f,
                "Ether paid to codeless account {to} (via a call-like opcode)"
            ),
            Precompile => write!(f, "Precompile used"),
            Return => write!(f, "Returned"),
            Revert => write!(f, "Reverted"),
            SelfDestruct => write!(f, "Self destructed"),
            Start => write!(f, "Start transaction"),
            Stop => write!(f, "Stopped"),
            Uninteresting => Ok(()),
        }
    }
}

pub fn process_trace() {
    let stdin = std::io::stdin();
    let reader = stdin.lock();

    let mut transaction_counter = 0;
    let mut context: Vec<Context> = vec![Context::default()];
    let mut pending_context = ContextUpdate::None;
    let mut prev_transaction_concluded = false;

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
        .filter_map(|mut step| {
            // Add processed information to step.
            // Exclude uninteresting steps (ADD, ISZERO, ...)
            match process_step(&step) {
                Some(processed) => {
                    step.processed_step = Some(processed);
                    Some(step)
                }
                None => None,
            }
        })
        .tuple_windows() // Clone the step to give access to the next step.
        .for_each(|(step, peek)| {
            if prev_transaction_concluded {

                transaction_counter += 1;
                context = vec![Context::default()];
                println!("New tx, step.depth is {}", step.depth);
            }
            match &pending_context {
                ContextUpdate::None => {},
                ContextUpdate::Add(pending) => {
                    context.push(pending.clone());
                    pending_context = ContextUpdate::None;
                },
                ContextUpdate::Remove => {context.pop().unwrap();},
            }

            if step.depth as usize != context.len() {
                //println!("step {} context {}",step.depth ,context.len());
            }

            // Peek at next EVM step to differentiate CALL-type to addresses with/without code.
            let mut processed = step.processed_step.unwrap();
            let context_added = peek.depth - step.depth == 1;
            if !context_added {
                // Context depth did not increase. Called address must have no code.
                processed = convert_codeless_call(processed);
            }

            // Do display here
            match context.last() {
                Some(current_context) => {
                    let juncture = Juncture {
                        action: &processed,
                        current_context,
                        context_depth: step.depth as usize,
                        transaction: transaction_counter,
                    };

                    println!("{juncture}");
                    //println!("{}", json!(juncture));
                }
                None => {
                    todo!("error. Step depth {}", step.depth);

                }
            };


            // Determine next-opcode context change here.
            match get_pending_context_update(&context, &processed) {
                Ok(ContextUpdate::None) => {
                    pending_context = ContextUpdate::None;
                }
                Ok(ContextUpdate::Add(new_context)) => {
                    // While at the CALL-type opcode, save the context details (msg.sender etc.).
                    pending_context = ContextUpdate::Add(new_context);
                }
                Ok(ContextUpdate::Remove) => {
                    if step.depth == 1 {
                        pending_context = ContextUpdate::None;
                        prev_transaction_concluded = true;
                    } else {
                        pending_context = ContextUpdate::Remove;
                    }
                }
                Err(_) => todo!(),
            };

        });
}

fn convert_codeless_call(processed: ProcessedStep) -> ProcessedStep {
    match processed {
        ProcessedStep::Call { to } => ProcessedStep::PayCall { to },
        ProcessedStep::CallCode { to } => ProcessedStep::PayCall { to },
        ProcessedStep::DelegateCall { to } => ProcessedStep::PayCall { to },
        ProcessedStep::StaticCall { to } => ProcessedStep::PayCall { to },
        step => step, // return unchanged
    }
}

impl TryFrom<&EvmStep> for ProcessedStep {
    type Error = FilterError;
    fn try_from(value: &EvmStep) -> Result<Self, Self::Error> {
        let op_name = value.op_name.as_str();
        Ok(match op_name {
            "CALL" => {
                let to = stack_nth(&value.stack, 1)?;
                match is_precompile(&to) {
                    true => Self::Precompile,
                    false => Self::Call { to },
                }
            }
            "CALLCODE" => {
                let to = stack_nth(&value.stack, 1)?;
                match is_precompile(&to) {
                    true => Self::Precompile,
                    false => Self::CallCode { to },
                }
            }
            "DELEGATECALL" => {
                let to = stack_nth(&value.stack, 1)?;
                match is_precompile(&to) {
                    true => Self::Precompile,
                    false => Self::DelegateCall { to },
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
            "RETURN" => Self::Return,
            "REVERT" => Self::Revert,
            "SELFDESTRUCT" => Self::SelfDestruct,
            "STOP" => {
                if value == &EvmStep::start_transaction()? {
                    Self::Start
                } else {
                    Self::Stop
                }
            }
            _ => Self::Uninteresting,
        })
    }
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

/// An EVM step is replaced by a new representation if it is of interest.
fn process_step(step: &EvmStep) -> Option<ProcessedStep> {
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

/// An opcode may cause a change to the context that will apply to the next
/// EVM step.
enum ContextUpdate {
    None,
    Add(Context),
    Remove,
}

/// If a opcode affects the call context, determine the new context it would create.
///
/// It may ultimetely not be applied (e.g., CALL to EOA).
fn get_pending_context_update(context: &[Context], step: &ProcessedStep) -> Result<ContextUpdate, FilterError> {
    match step {
        ProcessedStep::Call { to } | ProcessedStep::StaticCall { to } => {
            if is_precompile(to) {
                return Ok(ContextUpdate::None);
            }
            let previous = context.last().ok_or(FilterError::AbsentContext)?;
            Ok(ContextUpdate::Add(Context {
                code_address: to.clone(),
                message_sender: previous.message_sender.clone(),
                storage_address: to.clone(),
            }))
        }
        ProcessedStep::CallCode { to } => {
            if is_precompile(to) {
                return Ok(ContextUpdate::None);
            }
            let previous = context.last().ok_or(FilterError::AbsentContext)?;
            Ok(ContextUpdate::Add(Context {
                code_address: to.clone(),
                message_sender: previous.code_address.clone(), // important
                storage_address: previous.storage_address.clone(),
            }))
        }
        ProcessedStep::DelegateCall { to } => {
            if is_precompile(to) {
                return Ok(ContextUpdate::None);
            }
            let previous = context.last().ok_or(FilterError::AbsentContext)?;
            Ok(ContextUpdate::Add(Context {
                code_address: to.clone(),
                message_sender: previous.message_sender.clone(), // important
                storage_address: previous.storage_address.clone(),
            }))
        }
        ProcessedStep::Return
        | ProcessedStep::Revert
        | ProcessedStep::SelfDestruct
        | ProcessedStep::Stop => Ok(ContextUpdate::Remove),
        _ => Ok(ContextUpdate::None),
    }
}

/// Addresses of known precompile contracts
///
/// Useful because precompiles do not create a new call context.
fn is_precompile<T: AsRef<str>>(address: T) -> bool {
    matches!(
        address.as_ref(),
        "0x1" | "0x2" | "0x3" | "0x4" | "0x5" | "0x6" | "0x7" | "0x8" | "0x9"
    )
}
