//! For an important occurence during a tranasction. Includes things
//! that a human might find worthwhile being aware of.

use serde::Serialize;
use serde_json::json;
use std::fmt::Display;

use crate::{context::Context, opcode::Eip3155Line, processed::ProcessedStep};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum JunctureError {
    #[error("serde_json error {0}")]
    SerdeJson(#[from] serde_json::Error),
}

/// A noteworthy occurrence whose summary might be meaningful.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Juncture<'a> {
    pub action: &'a ProcessedStep,
    #[serde(skip_serializing)]
    pub raw_trace: &'a Eip3155Line,
    pub current_context: &'a Context,
    pub context_depth: Option<usize>,
    pub tx_count: usize,
}

impl Juncture<'_> {
    /// Prints to stdout ina minimal, human readable format.
    pub fn print_pretty(&self) {
        println!("{self}");
    }
    /// Prints in newline delimited JSON.
    ///
    /// Useful if another system will ingest the stream from stdout.
    pub fn print_json(&self) {
        println!("{}", json!(self));
    }
    /// Prints dense information, useful for debugging.
    pub fn print_debug(&self) {
        println!("{self:?}");
    }
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
            Call { to: _, value: _ }
            | CallCode { to: _, value: _ }
            | DelegateCall { to: _, value: _ }
            | StaticCall { to: _ } => {
                write!(f, "{} {}", self.action, self.current_context)
            }
            PayCall {
                to: _,
                value: _,
                opcode: _,
            } => write!(
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
