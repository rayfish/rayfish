//! Minimal, dependency-free ANSI styling for CLI output.
//!
//! Colors are applied only when stdout is a terminal and `NO_COLOR` is unset
//! (honoring the https://no-color.org convention). `CLICOLOR_FORCE` overrides
//! the TTY check so piped/captured output can still be colorized on request.

use std::io::IsTerminal;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Hard override that forces all styling, spinners, and interactive UI off,
/// set once by `--json` so machine-readable output is never colorized.
static PLAIN: AtomicBool = AtomicBool::new(false);

/// Force plain (uncolored, non-interactive) output for the rest of the process.
pub fn set_plain(plain: bool) {
    PLAIN.store(plain, Ordering::Relaxed);
}

fn enabled() -> bool {
    if PLAIN.load(Ordering::Relaxed) {
        return false;
    }
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

// Palette: mirrors the rose/emerald/zinc identity used on the website mockup.
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
/// Primary value text, bright and readable.
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

/// Whether colorized/styled output is active (TTY + not `NO_COLOR`). Exposed so
/// callers can gate interactive UI (spinners, the firewall picker) on the same
/// signal as coloring.
pub fn is_enabled() -> bool {
    enabled()
}

/// A filled status dot, colored by liveness.
pub fn dot_online() -> String {
    green("●")
}

/// A hollow status dot for offline/standby peers.
pub fn dot_offline() -> String {
    faint("○")
}

/// A muted filled dot for idle peers: a known roster member with no live link
/// (dialed on demand). Distinct from the green online dot and the hollow offline
/// dot: present, presumed reachable, just not currently connected.
pub fn dot_idle() -> String {
    paint("38;5;245", "●")
}

/// Success check mark.
pub fn check() -> String {
    green("✓")
}

/// Failure cross.
pub fn cross() -> String {
    red("✗")
}

/// A faint `·tag·` marker for inline annotations (roles, "suggested by …").
pub fn marker(s: &str) -> String {
    faint(&format!("·{s}·"))
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
