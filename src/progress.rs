//! Spinner / progress-bar constructors for genuinely-slow CLI operations.
//!
//! Thin factory over `indicatif`: each returns a configured
//! [`indicatif::ProgressBar`] drawn to **stderr** (so stdout stays clean for
//! piping), or a hidden no-op bar when styling is off ([`crate::style::is_enabled`]):
//! non-TTY, `NO_COLOR`, or `--json`. A hidden bar makes every method a no-op, so
//! call sites use the normal `ProgressBar` API with no branching.

use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

/// A ticking spinner labeled `msg`. Call `.finish_and_clear()` when done.
pub fn spinner(msg: impl Into<String>) -> ProgressBar {
    if !crate::style::is_enabled() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new_spinner();
    pb.set_draw_target(ProgressDrawTarget::stderr());
    pb.set_style(
        ProgressStyle::with_template("  {spinner} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", " "]),
    );
    pb.set_message(msg.into());
    pb.enable_steady_tick(Duration::from_millis(90));
    pb
}
