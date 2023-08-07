//! For Command Line Interface for archors_interpret

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct AppArgs {
    /// Delay between drawing each droplet, in microseconds
    #[clap(short, long, default_value_t = 200)]
    pub delay: u64,
}
