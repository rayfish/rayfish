//! Minimal, dependency-free ANSI styling for CLI output.
//!
//! Colors are applied only when stdout is a terminal and `NO_COLOR` is unset
//! (honoring the https://no-color.org convention). `CLICOLOR_FORCE` overrides
//! the TTY check so piped/captured output can still be colorized on request.

use std::io::IsTerminal;
use std::sync::OnceLock;

fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        if let Some(v) = std::env::var_os("CLICOLOR_FORCE")
            && v != "0"
        {
            return true;
        }
        // On legacy Windows consoles, ANSI sequences are inert until VT
        // processing is switched on. No-op on modern terminals (and elsewhere).
        #[cfg(windows)]
        let _ = enable_ansi_support::enable_ansi_support();
        std::io::stdout().is_terminal()
    })
}

fn paint(code: &str, s: &str) -> String {
    if enabled() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

// Palette — mirrors the rose/emerald/zinc identity used on the website mockup.
/// Brand accent (the prompt, join codes). rose-400-ish.
pub fn rose(s: &str) -> String {
    paint("38;5;204", s)
}
/// Success / live / online. emerald-400-ish.
pub fn green(s: &str) -> String {
    paint("38;5;42", s)
}
/// Secondary labels (IPv4 / IPv6 / join). zinc-500-ish.
pub fn label(s: &str) -> String {
    paint("38;5;245", s)
}
/// Tertiary, easy-to-ignore text (comments, hints). zinc-600-ish.
pub fn faint(s: &str) -> String {
    paint("38;5;240", s)
}
/// Primary value text — bright and readable.
pub fn value(s: &str) -> String {
    paint("38;5;252", s)
}
/// Emphasis for names/headlines.
pub fn bold(s: &str) -> String {
    paint("1;38;5;255", s)
}
/// Warning / loss. red-400-ish.
pub fn red(s: &str) -> String {
    paint("38;5;203", s)
}

/// A filled status dot, colored by liveness.
pub fn dot_online() -> String {
    green("●")
}

/// Color a latency value (in ms): green is snappy, amber is fine, red is laggy.
pub fn latency(ms: f64) -> String {
    let text = format!("{ms:.0}ms");
    let code = if ms < 50.0 {
        "38;5;42" // green
    } else if ms < 150.0 {
        "38;5;221" // amber
    } else {
        "38;5;203" // red
    };
    paint(code, &text)
}
