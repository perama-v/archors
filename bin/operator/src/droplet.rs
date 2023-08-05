//! For representing a vertical lines of text.

/// A single line of text
pub struct Droplet {
    pub text: String,
    /// Length of string
    pub length: usize,
    /// Greyscale (fades further within a   group)
    pub shade: usize,
    /// Col
    pub x_pos: u16,
    /// Row
    pub y_pos: u16,
    /// Index of character being drawn
    pub current_char: usize,
}
