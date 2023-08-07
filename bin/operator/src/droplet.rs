//! For representing a vertical lines of text.

use crossterm::style::Color;

use crate::Status;

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
    pub fn get_draw_info(&self, original_char: char,index: usize, max_height: u16) -> DrawInfo {
        let (letter, colour) = match (Status::get(index, self.current_char), self.is_final_char())
        {
            (_, true) => (' ', Color::Green),
            (Status::NormalUndrawn, false) => {
                let (r, g, b) = (0, self.shade, 0);
                (original_char, Color::Rgb { r, g, b })
            }
            (Status::NormalDrawn, false) => return DrawInfo::IgnoreChar,
            (Status::ToErase, false) => (' ', Color::Green),
            (Status::TooEarly, false) => return DrawInfo::EndDroplet,
            (Status::Stale, false) => return DrawInfo::IgnoreChar,
            (Status::BrightestDrawn, false) => return DrawInfo::IgnoreChar,
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
        DrawInfo::DrawChar { letter, colour, x: self.x_pos, y: y_pos }
    }
}

/// Information about a particular character for a self.
pub enum DrawInfo {
    /// Drawing required
    DrawChar { letter: char, colour: Color, x: u16, y: u16 },
    /// No action required for current charactor
    IgnoreChar,
    /// No further drawing required for self.
    EndDroplet,
}
