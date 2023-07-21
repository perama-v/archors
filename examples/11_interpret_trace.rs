use std::io::BufRead;

use anyhow::Result;
use archors_interpret::process_trace;

/// Produces a summary of a transaction trace by processing it as a stream
/// ```command
/// cargo run --release --example 09_use_proof | cargo run --release --example 11_interpret_trace
/// ```
fn main() -> Result<()> {
    process_trace();
    Ok(())
}
