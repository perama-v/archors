use std::{
    io::{BufRead, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{channel, Receiver, Sender},
        Arc,
    },
    thread,
    time::Duration,
};

use clap::Parser;
use cli::AppArgs;
use crossterm::{
    cursor::{self},
    terminal, ExecutableCommand,
};
use ctrlc::set_handler;
use droplet::Droplet;
use rand::Rng;

mod cli;
mod droplet;

fn main() {
    let args = AppArgs::parse();
    let (tx, rx) = channel::<Droplet>();
    thread::spawn(move || read_from_stdin(tx));
    write_to_terminal(rx, args.delay).expect("App could not be run.");
}

/// Reads lines from terminal, and sends them in a channel as Droplet.
fn read_from_stdin(tx: Sender<Droplet>) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let reader = stdin.lock();
    let mut rng = rand::thread_rng();
    let (col, row) = terminal::size()?;
    let lowest_draw = row / 3;

    for line in reader.lines() {
        let x_pos = rng.gen_range(0..col);
        let y_pos = rng.gen_range(0..lowest_draw);
        let mut text = line?.to_string();
        text.push_str("             ");
        let length = text.len();
        if length == 0 {
            continue;
        }
        let droplet = Droplet {
            text,
            length,
            shade: rng.gen_range(20..255),
            x_pos,
            y_pos,
            current_char: 0,
        };
        tx.send(droplet)?;
    }
    Ok(())
}

/// Recevies Droplets in a channel and displays them in the terminal.
fn write_to_terminal(rx: Receiver<Droplet>, delay: u64) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout();
    stdout.execute(terminal::EnterAlternateScreen)?;
    stdout.execute(cursor::Hide)?;
    let (_, max_height) = terminal::size()?;

    let mut droplets: Vec<Droplet> = vec![];

    // Set up Ctrl+C signal handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");

    // Accept new droplets as they arrive.
    // Hold droplets until they are finished.
    // Draw all held droplets at the same time.
    while running.load(Ordering::SeqCst) {
        match rx.recv() {
            Ok(droplet) => droplets.push(droplet),
            Err(_) => {
                if droplets.is_empty() {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            }
        }

        // Draw droplets
        droplets.retain_mut(|droplet| {
            droplet
                .draw_droplet(max_height)
                .expect("Couldn't draw droplet.");
            // All droplets have been queued, draw them.
            stdout.flush().expect("Could not flush stdout");
            thread::sleep(Duration::from_micros(delay));
            // Get retention info prior to updating status.
            let retain_droplet = !droplet.is_final_char();
            droplet.current_char += 1;
            retain_droplet
        });
        if droplets.is_empty() {
            break;
        }
    }
    stdout.execute(terminal::LeaveAlternateScreen)?;
    stdout.execute(terminal::Clear(terminal::ClearType::All))?;
    stdout.execute(cursor::Show)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::io::Write;

    /// Generates a few lines to pass to the operator app. Use as follows:
    /// ```
    /// cargo -q test -p archors_operator -- std | cargo run -p archors_operator
    /// ```
    /// Repeater:
    /// ```
    /// for i in {1..3}; do cargo test -p archors_operator -- std; sleep 1; done | cargo run -p archors_operator
    /// while true; do cargo test -q -p archors_operator --  std; done | cargo run -q -p archors_operator
    /// ```
    #[test]
    #[ignore]
    fn test_write_to_std_out() {
        let mut stdout = Box::new(std::io::stdout());
        for line in 0..100 {
            writeln!(stdout, "Line abcde 123456789  {}", line).unwrap();
        }
    }
}
