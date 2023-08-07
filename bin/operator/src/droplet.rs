//! For representing a vertical lines of text.

use crossterm::{
    cursor,
    style::{Color, Print, SetForegroundColor},
    QueueableCommand,
};

/// A single line of text
pub struct Droplet {
    pub text: String,
    /// Length of string
    pub length: usize,
    /// Greyscale (fades further within a group)
    pub shade: u8,
    /// Col
    pub x_pos: u16,
    /// Row
    pub y_pos: u16,
    /// Index of character being drawn
    pub current_char: usize,
}

impl Droplet {
    pub fn is_final_char(&self) -> bool {
        self.current_char == self.length - 1
    }
    pub fn draw_droplet(&self, max_height: u16) -> anyhow::Result<()> {
        for (index, char) in self.text.char_indices() {
            match self
                .draw_char(char, index, max_height)
                .expect("Could not draw char")
            {
                DrawInfo::ContinueDroplet => continue,
                DrawInfo::EndDroplet => break,
            };
        }
        Ok(())
    }
    /// Draw a character, which has an index in the droplet, and which has a position
    /// relative to the char that the droplet is up to (leading edge in the animation).
    pub fn draw_char(
        &self,
        original_char: char,
        index: usize,
        max_height: u16,
    ) -> anyhow::Result<DrawInfo> {
        let (letter, colour) = match (Status::get(index, self.current_char), self.is_final_char()) {
            (_, true) => (' ', Color::Green),
            (Status::NormalUndrawn, false) => {
                let (r, g, b) = (0, self.shade, 0);
                (original_char, Color::Rgb { r, g, b })
            }
            (Status::NormalDrawn, false) => return Ok(DrawInfo::ContinueDroplet),
            (Status::ToErase, false) => (' ', Color::Green),
            (Status::TooEarly, false) => return Ok(DrawInfo::EndDroplet),
            (Status::Stale, false) => return Ok(DrawInfo::ContinueDroplet),
            (Status::BrightestDrawn, false) => return Ok(DrawInfo::ContinueDroplet),
            (Status::BrightestUndrawn, false) => {
                let (r, g, b) = (self.shade, self.shade, self.shade);
                (original_char, Color::Rgb { r, g, b })
            }
        };
        let y_pos_abs = self.y_pos + index as u16;
        let y_pos = match y_pos_abs >= max_height {
            true => y_pos_abs.wrapping_rem(max_height),
            false => y_pos_abs,
        };
        std::io::stdout()
            .queue(SetForegroundColor(colour))?
            .queue(cursor::MoveTo(self.x_pos, y_pos))?
            .queue(Print(letter))?;
        Ok(DrawInfo::ContinueDroplet)
    }
}

/// Whether to proceed with the rest of the drop.
pub enum DrawInfo {
    /// No action required for current charactor
    ContinueDroplet,
    /// No further drawing required for droplet.
    EndDroplet,
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