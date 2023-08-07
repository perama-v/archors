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
    style::{Color, Print, SetForegroundColor},
    terminal, ExecutableCommand, QueueableCommand,
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

            let retain_droplet = !droplet.is_final_char();
            for (index, char) in droplet.text.char_indices() {
                match droplet.get_draw_info(char, index, max_height) {
                    droplet::DrawInfo::DrawChar { letter, colour, x, y } => {
                        stdout
                            .queue(SetForegroundColor(colour))
                            .unwrap()
                            .queue(cursor::MoveTo(x,y))
                            .unwrap()
                            .queue(Print(letter))
                            .unwrap();
                    }
                    droplet::DrawInfo::IgnoreChar => continue,
                    droplet::DrawInfo::EndDroplet => break,
                };
            }
            // All droplets have been queued, draw them.
            stdout.flush().expect("Could not flush stdout");
            thread::sleep(Duration::from_micros(delay));
            // Update droplet draw position and remove if finished.
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

/// Every droplet is visited multiple times. Each time, characters have
/// a status, relative to the phase of the droplet.
pub enum Status {
    /// Char is not yet ready to be drawn for this droplet, nothing to be done
    TooEarly,
    /// White char, needs to be drawn
    BrightestUndrawn,
    /// White char, has been drawn, nothing to be done.
    BrightestDrawn,
    /// Needs to be drawn in normal colour
    NormalUndrawn,
    /// Has been drawn, nothing to be done
    NormalDrawn,
    /// Has been drawn, now ready to erase
    ToErase,
    /// Has been erased, now is far in the past, nothing to be done
    Stale,
}

impl Status {
    fn get(char_index: usize, draw_index: usize) -> Self {
        let diff = char_index.abs_diff(draw_index);
        let after = char_index > draw_index;
        match (after, diff) {
            (false, 0) => Status::BrightestUndrawn,
            (false, 1 | 2) => Status::BrightestDrawn,
            (false, 3) => Status::NormalUndrawn,
            (false, 4..=40) => Status::NormalDrawn,
            (false, 41) => Status::ToErase,
            (false, _) => Status::Stale,
            (true, _) => Status::TooEarly,
        }
    }
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
    fn test_write_to_std_out() {
        let mut stdout = Box::new(std::io::stdout());
        for line in 0..100 {
            writeln!(stdout, "Line abcde 123456789  {}", line).unwrap();
        }
    }
}
