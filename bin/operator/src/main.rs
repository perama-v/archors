use std::io::stdout;
use std::io::{BufRead, Write};

use crossterm::{cursor, terminal};
use crossterm::{
    style::{Color, Print, SetForegroundColor},
    ExecutableCommand,
};
use rand::Rng;

fn main() {
    begin().expect("App could not be run.");
}

fn begin() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let reader = stdin.lock();

    let mut stdout = stdout();
    stdout.execute(terminal::Clear(terminal::ClearType::All))?;
    let mut rng = rand::thread_rng();
    let (col, _row) = terminal::size()?;
    let mut started = false;
    let mut y_pos = 1;

    for line in reader.lines() {
        if !started {
            stdout.execute(terminal::Clear(terminal::ClearType::All))?;
            started = true;
        }
        let text = format!("{}", line.unwrap());
        let x_pos = rng.gen_range(0..col);

        for (index, char) in text.char_indices() {
            stdout
                .execute(SetForegroundColor(Color::Green))?
                .execute(cursor::MoveTo(x_pos, y_pos + index as u16))?
                .execute(Print(char))?;
        }
        let delay = std::time::Duration::from_millis(10);
        std::thread::sleep(delay);
        // Reset y_pos if new group found
        y_pos += 1
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    /// Generates a few lines to pass to the operator app. Use as follows:
    /// ```
    /// cargo test -p archors_operator --  std | cargo run -p archors_operator
    /// ```
    #[test]
    fn test_write_to_std_out() {
        let mut stdout = Box::new(std::io::stdout());
        for line in 0..10 {
            writeln!(stdout, "Line {}", line).unwrap();
        }
    }
}
