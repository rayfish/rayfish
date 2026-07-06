//! ANSI-aware column alignment for CLI tables.
//!
//! Hand-rolled (no `comfy-table`) to keep the lightweight, borderless "polished
//! plain" look of [`crate::style`]. Each [`Cell`] carries the *plain* text used
//! for width math and the *styled* text actually printed, so ANSI escape bytes
//! never inflate column widths. Padding spaces have no color, so they're simply
//! appended (left-align) or prepended (right-align) to the styled string.

use unicode_width::UnicodeWidthStr;

/// Horizontal alignment within a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

/// One table cell: `plain` drives width math, `styled` is what gets printed.
#[derive(Debug, Clone)]
pub struct Cell {
    plain: String,
    styled: String,
    align: Align,
}

impl Cell {
    /// Left-aligned cell whose styled form differs from its plain form.
    pub fn new(plain: impl Into<String>, styled: impl Into<String>) -> Self {
        Cell {
            plain: plain.into(),
            styled: styled.into(),
            align: Align::Left,
        }
    }

    /// Right-aligned variant (for numeric columns: ports, latency, bytes).
    pub fn right(plain: impl Into<String>, styled: impl Into<String>) -> Self {
        Cell {
            align: Align::Right,
            ..Cell::new(plain, styled)
        }
    }

    /// Unstyled cell: plain and styled are identical.
    pub fn plain(text: impl Into<String> + Clone) -> Self {
        Cell::new(text.clone(), text)
    }

    fn width(&self) -> usize {
        UnicodeWidthStr::width(self.plain.as_str())
    }
}

/// Render `rows` as space-aligned columns separated by `gap` spaces.
///
/// Column widths are the max visible width of each column's cells. Returns a
/// newline-terminated multi-line string; ragged rows (fewer cells) are fine.
pub fn columns(rows: &[Vec<Cell>], gap: usize) -> String {
    let ncols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0usize; ncols];
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.width());
        }
    }

    let sep = " ".repeat(gap);
    let mut out = String::new();
    for row in rows {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            // The final cell in a row needs no trailing pad.
            let is_last = i + 1 == row.len();
            let pad = widths[i].saturating_sub(cell.width());
            if i > 0 {
                line.push_str(&sep);
            }
            match cell.align {
                Align::Left => {
                    line.push_str(&cell.styled);
                    if !is_last {
                        line.push_str(&" ".repeat(pad));
                    }
                }
                Align::Right => {
                    line.push_str(&" ".repeat(pad));
                    line.push_str(&cell.styled);
                }
            }
        }
        // Trim trailing spaces that a right-aligned last column can't produce
        // but a left-aligned padding never added anyway.
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligns_plain_columns() {
        let rows = vec![
            vec![Cell::plain("a"), Cell::plain("bbb")],
            vec![Cell::plain("aaa"), Cell::plain("b")],
        ];
        let out = columns(&rows, 2);
        assert_eq!(out, "a    bbb\naaa  b\n");
    }

    #[test]
    fn width_ignores_ansi_escapes() {
        // Styled cell is wider in bytes but 1 col visually; the next column must
        // still align with a plain 1-wide cell in the other row.
        let styled = "\x1b[38;5;42m●\x1b[0m";
        let rows = vec![
            vec![Cell::new("●", styled), Cell::plain("online")],
            vec![Cell::plain("X"), Cell::plain("x")],
        ];
        let out = columns(&rows, 1);
        let lines: Vec<&str> = out.lines().collect();
        // Both second columns start at the same visible offset (after 1 glyph +
        // 1 gap). Strip ANSI to compare positions.
        assert!(lines[0].ends_with("online"));
        assert!(lines[1] == "X x");
    }

    #[test]
    fn right_align_pads_left() {
        let rows = vec![
            vec![Cell::plain("host"), Cell::right("12ms", "12ms")],
            vec![Cell::plain("h"), Cell::right("8ms", "8ms")],
        ];
        let out = columns(&rows, 1);
        assert_eq!(out, "host 12ms\nh     8ms\n");
    }

    #[test]
    fn empty_input() {
        assert_eq!(columns(&[], 2), "");
    }
}
