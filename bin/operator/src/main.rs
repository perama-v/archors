use std::{
    io::{stdout, BufRead},
    sync::mpsc::{channel, Receiver, Sender},
    thread,
    time::Duration,
};

use clap::Parser;
use cli::AppArgs;
use crossterm::{
    cursor::{self, Hide},
    style::{Color, Print, SetForegroundColor},
    terminal, ExecutableCommand,
};
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
    let mut stdout = stdout();
    stdout.execute(terminal::Clear(terminal::ClearType::All))?;
    stdout.execute(Hide)?;
    let (_, max_height) = terminal::size()?;

    let mut started = false;
    let mut droplets: Vec<Droplet> = vec![];

    // Accept new droplets as they arrive.
    // Hold droplets until they are finished.
    // Draw all held droplets at the same time.
    loop {
        match rx.recv() {
            Ok(droplet) => droplets.push(droplet),
            Err(_) => {
                if droplets.is_empty() {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
            }
        }
        if !started {
            stdout.execute(terminal::Clear(terminal::ClearType::All))?;
            started = true;
        }

        // Draw droplets
        droplets.retain_mut(|droplet| {
            let final_char = droplet.current_char == droplet.length - 1;

            for (index, char) in droplet.text.char_indices() {
                let (letter, colour) = match (Status::get(index, droplet.current_char), final_char)
                {
                    (_, true) => (' ', Color::Green),
                    (Status::NormalUndrawn, false) => (
                        char,
                        Color::Rgb {
                            r: 0,
                            g: droplet.shade,
                            b: 0,
                        },
                    ),
                    (Status::NormalDrawn, false) => continue,
                    (Status::ToErase, false) => (' ', Color::Green),
                    (Status::TooEarly, false) => break,
                    (Status::Stale, false) => continue,
                    (Status::Brightest, false) => (
                        char,
                        Color::Rgb {
                            r: droplet.shade,
                            g: droplet.shade,
                            b: droplet.shade,
                        },
                    ),
                };
                let y_pos_abs = droplet.y_pos + index as u16;
                let y_pos = match y_pos_abs >= max_height {
                    true => y_pos_abs.wrapping_rem(max_height),
                    false => y_pos_abs,
                };
                stdout
                    .execute(SetForegroundColor(colour))
                    .unwrap()
                    .execute(cursor::MoveTo(droplet.x_pos, y_pos))
                    .unwrap()
                    .execute(Print(letter))
                    .unwrap();
            }
            thread::sleep(Duration::from_millis(delay));
            // Update droplet draw position and remove if finished.
            droplet.current_char += 1;
            // If droplet is not at end, retain droplet.
            !final_char
        });
        if droplets.is_empty() {
            break;
        }
    }
    stdout.execute(terminal::Clear(terminal::ClearType::All))?;
    stdout.execute(cursor::Show)?;
    Ok(())
}

/// Every droplet is visited multiple times. Each time, characters have
/// a status, relative to the phase of the droplet.
pub enum Status {
    /// Char is not yet ready to be drawn for this droplet, nothing to be done
    TooEarly,
    /// White chars
    Brightest,
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
            (false, 0 | 1 | 2) => Status::Brightest,
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
    /// cargo test -p archors_operator --  std | cargo run -p archors_operator
    /// ```
    #[test]
    fn test_write_to_std_out() {
        let mut stdout = Box::new(std::io::stdout());
        for line in 0..10 {
            writeln!(stdout, "Line abcde 123456789  {}", line).unwrap();
        }
    }
}