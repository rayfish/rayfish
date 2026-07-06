//! In-memory capture of the Rust core's `tracing` output for Android
//! diagnostics. A bounded ring buffer holds recent log lines; two atomic
//! counters track WARN/ERROR since process start. Installed once as the process
//! subscriber in `Node::new`; read by `Node::health_snapshot`/`log_snapshot`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// Max buffered log lines before the oldest is evicted.
const MAX_LINES: usize = 4000;
/// Max total buffered bytes before the oldest lines are evicted.
const MAX_BYTES: usize = 1_000_000;
/// Max WARN/ERROR lines kept for `recent_errors`.
const MAX_ERROR_LINES: usize = 20;

/// Bounded ring of formatted log lines plus a small tail of WARN/ERROR lines.
pub(crate) struct Ring {
    lines: VecDeque<String>,
    bytes: usize,
    errors: VecDeque<String>,
}

impl Ring {
    fn new() -> Self {
        Ring {
            lines: VecDeque::new(),
            bytes: 0,
            errors: VecDeque::new(),
        }
    }

    /// Append a line, evicting oldest lines past the line/byte caps. WARN/ERROR
    /// lines are also mirrored into the bounded `errors` tail.
    pub(crate) fn push(&mut self, line: String, level: Level) {
        if level == Level::WARN || level == Level::ERROR {
            self.errors.push_back(line.clone());
            while self.errors.len() > MAX_ERROR_LINES {
                self.errors.pop_front();
            }
        }
        self.bytes += line.len();
        self.lines.push_back(line);
        while self.lines.len() > MAX_LINES || self.bytes > MAX_BYTES {
            match self.lines.pop_front() {
                Some(old) => self.bytes -= old.len(),
                None => break,
            }
        }
    }

    /// All buffered lines joined newline-separated.
    pub(crate) fn text(&self) -> String {
        let mut out = String::with_capacity(self.bytes + self.lines.len());
        for l in &self.lines {
            out.push_str(l);
            out.push('\n');
        }
        out
    }

    pub(crate) fn errors(&self) -> Vec<String> {
        self.errors.iter().cloned().collect()
    }
}

/// Process-global diagnostics state.
struct Diag {
    ring: Mutex<Ring>,
    warn: AtomicU64,
    error: AtomicU64,
}

static DIAG: OnceLock<Diag> = OnceLock::new();

fn diag() -> &'static Diag {
    DIAG.get_or_init(|| Diag {
        ring: Mutex::new(Ring::new()),
        warn: AtomicU64::new(0),
        error: AtomicU64::new(0),
    })
}

/// Formats an event's fields into a single string, prioritizing `message`.
#[derive(Default)]
struct LineVisitor {
    text: String,
}

impl Visit for LineVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        if field.name() == "message" {
            let _ = write!(self.text, "{value:?} ");
        } else {
            let _ = write!(self.text, "{}={value:?} ", field.name());
        }
    }
}

/// The `tracing` layer that pushes each event into the ring buffer.
struct DiagLayer;

impl<S> Layer<S> for DiagLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let level = *meta.level();
        let mut visitor = LineVisitor::default();
        event.record(&mut visitor);
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let line = format!(
            "{millis} {level} {}: {}",
            meta.target(),
            visitor.text.trim_end()
        );

        let d = diag();
        if level == Level::WARN {
            d.warn.fetch_add(1, Ordering::Relaxed);
        } else if level == Level::ERROR {
            d.error.fetch_add(1, Ordering::Relaxed);
        }
        // Also mirror the line to Android logcat so `adb logcat -s rayfish`
        // shows the core's tracing during development (the ring buffer alone is
        // only readable through the in-app "Send diagnostics" attachment).
        #[cfg(target_os = "android")]
        android_log::write(level, meta.target(), visitor.text.trim_end());
        // Keep the log path non-blocking: drop the line if the buffer is
        // momentarily contended rather than stalling a logging thread.
        if let Ok(mut ring) = d.ring.try_lock() {
            ring.push(line, level);
        }
    }
}

/// Thin FFI bridge to Android's liblog so core `tracing` events show up in
/// logcat under the `rayfish` tag. Kept as a direct `__android_log_write` call
/// (linked via `-llog`) to avoid pulling in another logging crate.
#[cfg(target_os = "android")]
mod android_log {
    use std::ffi::CString;
    use std::os::raw::c_char;

    use tracing::Level;

    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(prio: i32, tag: *const c_char, text: *const c_char) -> i32;
    }

    /// Android log priorities (see `<android/log.h>`).
    const ANDROID_LOG_DEBUG: i32 = 3;
    const ANDROID_LOG_INFO: i32 = 4;
    const ANDROID_LOG_WARN: i32 = 5;
    const ANDROID_LOG_ERROR: i32 = 6;

    pub(super) fn write(level: Level, target: &str, text: &str) {
        let prio = match level {
            Level::ERROR => ANDROID_LOG_ERROR,
            Level::WARN => ANDROID_LOG_WARN,
            Level::INFO => ANDROID_LOG_INFO,
            _ => ANDROID_LOG_DEBUG,
        };
        // liblog splits on the tag, so keep the crate target in the message.
        let Ok(tag) = CString::new("rayfish") else {
            return;
        };
        // A NUL in the message would truncate it; skip the line rather than lose
        // the tag alignment.
        if let Ok(msg) = CString::new(format!("{target}: {text}")) {
            // SAFETY: both pointers are valid NUL-terminated C strings that
            // outlive the call, and liblog is always present on Android.
            unsafe {
                __android_log_write(prio, tag.as_ptr(), msg.as_ptr());
            }
        }
    }
}

/// Install the diagnostics layer as the process subscriber. Idempotent: a second
/// call is a no-op (the global subscriber can only be set once).
pub fn install() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,rayfish=debug"));
    let _ = tracing_subscriber::registry()
        .with(DiagLayer.with_filter(filter))
        .try_init();
}

pub fn warn_count() -> u64 {
    diag().warn.load(Ordering::Relaxed)
}

pub fn error_count() -> u64 {
    diag().error.load(Ordering::Relaxed)
}

pub fn recent_errors() -> Vec<String> {
    diag().ring.lock().map(|r| r.errors()).unwrap_or_default()
}

pub fn snapshot() -> String {
    diag().ring.lock().map(|r| r.text()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_past_line_cap() {
        let mut ring = Ring::new();
        for i in 0..(MAX_LINES + 5) {
            ring.push(format!("line {i}"), Level::INFO);
        }
        assert_eq!(ring.lines.len(), MAX_LINES);
        // The first five lines were evicted; the oldest kept is "line 5".
        assert_eq!(ring.lines.front().unwrap(), "line 5");
    }

    #[test]
    fn evicts_past_byte_cap() {
        let mut ring = Ring::new();
        let big = "x".repeat(100_000);
        for _ in 0..20 {
            ring.push(big.clone(), Level::INFO);
        }
        assert!(ring.bytes <= MAX_BYTES);
    }

    #[test]
    fn tracks_recent_errors_only() {
        let mut ring = Ring::new();
        ring.push("info one".into(), Level::INFO);
        ring.push("warn one".into(), Level::WARN);
        ring.push("err one".into(), Level::ERROR);
        assert_eq!(ring.errors(), vec!["warn one", "err one"]);
    }

    #[test]
    fn recent_errors_bounded() {
        let mut ring = Ring::new();
        for i in 0..(MAX_ERROR_LINES + 5) {
            ring.push(format!("err {i}"), Level::ERROR);
        }
        assert_eq!(ring.errors().len(), MAX_ERROR_LINES);
    }
}
