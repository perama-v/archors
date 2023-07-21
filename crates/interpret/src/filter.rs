//! Processes a transaction trace to produce a summary. The use case is
//! to be able to pipe any EIP-3155 output to this library.
//!
//! The input is new-line delineated JSON stream of EVM steps from stdin.
//!
//! Note that a line in a trace is pre-application of the opcode. E.g., the opcode will
//! use the values in the stack on the same line.

// Resources
/// - EVMOne: https://github.com/ethereum/evmone/pull/325
/// - Test case: https://github.com/Arachnid/EIPs/commit/28e73864f72d66b5dd31fdb5f7502f0327075131
use std::{cmp::Ordering, fmt::Display, io::BufRead};

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
    pub action: &'a ProcessedStep,
    pub current_context: &'a Context,
    pub context_depth: Option<usize>,
    pub tx_count: usize,
}

impl Display for Juncture<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ProcessedStep::*;
        if let Some(depth) = self.context_depth {
            for _ in 0..depth {
                write!(f, "\t")?;
            }
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
            TxFinished(_) => write!(f, "{}", self.action),
            TxSummary {
                output: _,
                gas_used: _,
            } => write!(f, "Transaction {} complete. {}", self.tx_count, self.action),
            _ => write!(f, "{}", self.action),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Eip3155Line {
    Step(EvmStep),
    Output(EvmOutput),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Step {
    pub trace: Eip3155Line,
    pub processed: ProcessedStep,
    pub tx_count: usize,
}
impl Step {
    /// Some opcodes have different behaviour, which can
    /// be understood by peeking at the next opcode.
    ///
    /// E.g. Call to account with no code (sends ether, no context increase).
    fn detect_call_to_no_code(self, peek: &Step) -> Step {
        let mut current = self;
        let current_depth = match current.trace {
            Eip3155Line::Step(ref s) => s.depth,
            Eip3155Line::Output(_) => 0,
        };
        let peek_depth = match peek.trace {
            Eip3155Line::Step(ref s) => s.depth,
            Eip3155Line::Output(_) => 0,
        };
        match peek_depth.cmp(&current_depth) {
            Ordering::Less => {}    // peek has less context
            Ordering::Greater => {} // added context
            Ordering::Equal => {
                // same context
                // If call type, this is a call to an account with no code.
                current.processed = current.processed.clone().convert_to_codeless_call();
            }
        }
        current
    }
    /// In the stream, the final line does not have a subsequent line to peek from.
    fn update_final_line(self) -> Step {
        self
    }
    /// Convert to juncture (to display)
    fn as_juncture<'a>(&'a self, context: &'a [Context]) -> Juncture {
        let current_context = context.last().unwrap();
        let context_depth = match &self.trace {
            Eip3155Line::Step(s) => Some(s.depth as usize),
            Eip3155Line::Output(_) => None,
        };
        Juncture {
            action: &self.processed,
            current_context,
            context_depth,
            tx_count: self.tx_count,
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
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EvmOutput {
    pub(crate) output: String,
    pub(crate) gas_used: String,
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
    Invalid,
    Return,
    Revert,
    SelfDestruct,

    StaticCall {
        to: String,
    },
    Stop,
    /// Deduction of how a transaction ended.
    TxFinished(FinishMechanism),
    /// EVM output containing specific post-transaction facts.
    TxSummary {
        output: String,
        gas_used: String,
    },
    Uninteresting,
}

impl ProcessedStep {
    fn convert_to_codeless_call(self) -> ProcessedStep {
        match self {
            ProcessedStep::Call { to } => ProcessedStep::PayCall { to },
            ProcessedStep::CallCode { to } => ProcessedStep::PayCall { to },
            ProcessedStep::DelegateCall { to } => ProcessedStep::PayCall { to },
            ProcessedStep::StaticCall { to } => ProcessedStep::PayCall { to },
            step => step, // return unchanged
        }
    }
}

impl Display for ProcessedStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ProcessedStep::*;
        match self {
            Call { to: _ } => write!(f, "Contract (CALL)"),
            CallCode { to: _ } => write!(f, "Contract (CALLCODE)"),
            DelegateCall { to: _ } => write!(f, "Contract (DELEGATECALL)"),
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
            PayCall { to } => write!(
                f,
                "Ether paid to codeless account {to} (via a call-like opcode)"
            ),
            Precompile => write!(f, "Precompile used"),
            Invalid => write!(f, "Invalid opcode"),
            Return => write!(f, "Returned"),
            Revert => write!(f, "Reverted"),
            SelfDestruct => write!(f, "Self destructed"),
            Stop => write!(f, "Stopped"),
            TxFinished(mechanism) => write!(f, "Transaction finished ({mechanism})"),
            TxSummary { output, gas_used } => write!(
                f,
                "Transaction summary, gas used: {gas_used}, output: {output}"
            ),
            Uninteresting => Ok(()),
        }
    }
}

pub fn process_trace() {
    let stdin = std::io::stdin();
    let reader = stdin.lock();

    let mut transaction_counter = 0;

    let mut peekable_lines = reader
        .lines()
        .filter_map(|line| match line {
            Ok(l) => Some(l),
            Err(_) => None, // Bad stdin line
        })
        .filter_map(|line| match serde_json::from_str::<EvmStep>(&line) {
            Ok(step) => Some(Eip3155Line::Step(step)),
            Err(_) => {
                // Not an EvmStep (e.g., output)
                match serde_json::from_str::<EvmOutput>(&line) {
                    Ok(output) => Some(Eip3155Line::Output(output)),
                    Err(_) => None, // Not an EvmStep or Output
                }
            }
        })
        .filter_map(|step| {
            // Add processed information to step.
            // Exclude uninteresting steps (ADD, ISZERO, ...)
            process_step(&step).map(|processed| {
                let current_count = transaction_counter;
                if let ProcessedStep::TxSummary {
                    output: _,
                    gas_used: _,
                } = &processed
                {
                    transaction_counter += 1; // for next tx (if present)
                }
                Step {
                    trace: step,
                    processed,
                    tx_count: current_count,
                }
            })
        })
        .peekable();

    let mut context: Vec<Context> = vec![Context::default()];
    let mut pending_context = ContextUpdate::None;

    while let Some(line) = peekable_lines.next() {
        let parsed_line = match peekable_lines.peek() {
            Some(peek) => line.detect_call_to_no_code(peek),
            None => line.update_final_line(),
        };

        apply_pending_context(&mut context, &mut pending_context);
        pending_context = get_pending_context_update(&context, &parsed_line.processed).unwrap();

        let juncture = parsed_line.as_juncture(&context);

        //println!("{juncture}");
        println!("{}", json!(juncture));
    }
}

/// Apply pending context to the current step.
fn apply_pending_context(context: &mut Vec<Context>, pending_context: &mut ContextUpdate) {
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
            "INVALID" => match value.depth {
                1 => Self::TxFinished(FinishMechanism::Invalid),
                _ => Self::Return,
            },
            "RETURN" => match value.depth {
                1 => Self::TxFinished(FinishMechanism::Return),
                _ => Self::Return,
            },
            "REVERT" => match value.depth {
                1 => Self::TxFinished(FinishMechanism::Revert),
                _ => Self::Revert,
            },
            "STOP" => {
                match value.depth {
                    0 => Self::Uninteresting, // Artefact unique to revm (used at start of transactions)
                    1 => Self::TxFinished(FinishMechanism::Stop),
                    _ => Self::Stop,
                }
            }
            "SELFDESTRUCT" => Self::SelfDestruct,

            _ => Self::Uninteresting,
        })
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

/// If a line from the trace is of interest, a new representation is created.
fn process_step(step: &Eip3155Line) -> Option<ProcessedStep> {
    match step {
        Eip3155Line::Step(evm_step) => match ProcessedStep::try_from(evm_step) {
            Ok(ProcessedStep::Uninteresting) => None,
            Ok(processed_step) => Some(processed_step),
            Err(_) => None,
        },
        Eip3155Line::Output(evm_output) => Some(ProcessedStep::from(evm_output)),
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
fn get_pending_context_update(
    context: &[Context],
    step: &ProcessedStep,
) -> Result<ContextUpdate, FilterError> {
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
        ProcessedStep::Invalid
        | ProcessedStep::Return
        | ProcessedStep::Revert
        | ProcessedStep::SelfDestruct
        | ProcessedStep::Stop => Ok(ContextUpdate::Remove),
        ProcessedStep::TxFinished(_) => Ok(ContextUpdate::Reset),
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
