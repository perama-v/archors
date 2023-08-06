//! For Command Line Interface for archors_interpret

use clap::{Parser, ValueEnum};

/// Interpret an EVM trace. To use: Pipe NDJSON trace to the app.
///
/// NDJSON can be made from JSON-RPC by:
/// ```
/// <call node> | jq '.["result"]["structLogs"][]' -c | <archors_interpret>
/// ```
/// (for a single transaction) or
/// ```
/// <call node> | jq '.["result"][]["result"]["structLogs"][]' -c | <archors_interpret>
/// ```
/// (for a whole block)
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct AppArgs {
    #[clap(value_enum, default_value_t=ModeFlag::Debug)]
    pub trace_style: ModeFlag,
}

/// Different traces have different fields (e.g., op vs opName)
///
/// For example
/// - revm with EIP-3155 tracer inspector
/// - debug_traceTransaction
#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum ModeFlag {
    /// EIP-3155 style trace
    Eip3155,
    /// For debug_traceBlockByNumber or debug_traceTransaction (see NDJSON instructions)
    Debug,
}
