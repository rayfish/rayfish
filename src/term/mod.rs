//! Terminal presentation helpers shared by the CLI: ANSI styling, column
//! layout, the interactive rule picker, and progress spinners. All are
//! dependency-light and honor `NO_COLOR` / `CLICOLOR_FORCE` (see [`style`]).

pub mod layout;
pub mod picker;
pub mod progress;
pub mod style;
