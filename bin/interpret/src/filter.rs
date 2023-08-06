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
use std::io::{BufRead, Write};

use thiserror::Error;

use crate::{
    cli::ModeFlag,
    context::{apply_pending_context, get_pending_context_update, Context, ContextUpdate},
    juncture::Juncture,
    opcode::{EvmOutput, EvmStepDebug, EvmStepEip3155, TraceLine},
    processed::ProcessedStep,
};

#[derive(Debug, Error)]
pub enum FilterError {
    #[error("serde_json error {0}")]
    SerdeJson(#[from] serde_json::Error),
}

pub fn process_trace(trace_style: ModeFlag) {
    let stdin = std::io::stdin();
    let reader = stdin.lock();

    let mut transaction_counter = 0;

    let mut peekable_lines = reader
        .lines()
        .filter_map(|line| match line {
            Ok(l) => Some(l),
            Err(_) => None, // Bad stdin line
        })
        .filter_map(|line| {
            match trace_style {
                ModeFlag::Eip3155 => {
                    let json = serde_json::from_str::<EvmStepEip3155>(&line);
                    match json {
                        Ok(step) => Some(TraceLine::StepEip3155(step)),
                        Err(_) => {
                            // Not an EvmStep (e.g., output)
                            match serde_json::from_str::<EvmOutput>(&line) {
                                Ok(output) => Some(TraceLine::Output(output)),
                                Err(_) => None, // Not an EvmStep or Output
                            }
                        }
                    }
                }
                ModeFlag::Debug => {
                    let json = serde_json::from_str::<EvmStepDebug>(&line);
                    match json {
                        Ok(step) => Some(TraceLine::StepDebug(step)),
                        Err(_) => {
                            // Not an EvmStep (e.g., output)
                            match serde_json::from_str::<EvmOutput>(&line) {
                                Ok(output) => Some(TraceLine::Output(output)),
                                Err(_) => None, // Not an EvmStep or Output
                            }
                        }
                    }
                }
            }
        })
        .peekable();

    let mut context: Vec<Context> = vec![Context::default()];
    let mut pending_context = ContextUpdate::None;
    let mut create_counter: usize = 0;

    let mut stdout = Box::new(std::io::stdout());

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

        // Update context
        apply_pending_context(&mut context, &mut pending_context);
        pending_context =
            get_pending_context_update(&context, &processed, &mut create_counter).unwrap();

        // Group processed and raw information together.

        let juncture = Juncture::create(&processed, &unprocessed_step, &context, tx_count);
        //juncture.print_json();
        //juncture.print_pretty();
        writeln!(stdout, "{}", juncture).expect("Could not write to stdout");
    }
}

/// If a line from the trace is of interest, a new representation is created.
fn process_step(step: &TraceLine) -> Option<ProcessedStep> {
    match step {
        TraceLine::StepEip3155(evm_step) => match ProcessedStep::try_from_evm_step(evm_step) {
            Ok(ProcessedStep::Uninteresting) => None,
            Ok(processed_step) => Some(processed_step),
            Err(_) => None,
        },
        TraceLine::StepDebug(evm_step) => match ProcessedStep::try_from_evm_step(evm_step) {
            Ok(ProcessedStep::Uninteresting) => None,
            Ok(processed_step) => Some(processed_step),
            Err(_) => None,
        },
        TraceLine::Output(evm_output) => Some(ProcessedStep::from(evm_output)),
    }
}
