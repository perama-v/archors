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
use std::{cmp::Ordering, io::BufRead};

use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::{
    context::{apply_pending_context, get_pending_context_update, Context, ContextUpdate},
    juncture::Juncture,
    opcode::{Eip3155Line, EvmOutput, EvmStep},
    processed::ProcessedStep,
};

#[derive(Debug, Error)]
pub enum FilterError {
    #[error("serde_json error {0}")]
    SerdeJson(#[from] serde_json::Error),
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
        .peekable();

    let mut context: Vec<Context> = vec![Context::default()];
    let mut pending_context = ContextUpdate::None;
    let mut create_counter: usize = 0;

    while let Some(unprocessed_step) = peekable_lines.next() {
        // Add processed information to step.
        // Exclude uninteresting steps (ADD, ISZERO, ...)
        let Some(mut processed) = process_step(&unprocessed_step) else {continue};

        // Get the stack from the peek and include it in the processed step.
        if let Some(peek) = peekable_lines.peek() {
            processed.add_peek(&unprocessed_step, peek);
        }
        // Update transaction counter.
        let tx_count = transaction_counter;
        if let ProcessedStep::TxSummary { .. } = processed {
            transaction_counter += 1;
        };
        // Group processed and raw information together.
        let step = Step {
            trace: unprocessed_step,
            processed,
            tx_count,
        };

        apply_pending_context(&mut context, &mut pending_context);
        pending_context =
            get_pending_context_update(&context, &step.processed, &mut create_counter).unwrap();

        let juncture = step.as_juncture(&context);
        juncture.print_pretty();
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
            raw_trace: &self.trace,
            current_context,
            context_depth,
            tx_count: self.tx_count,
        }
    }
}
