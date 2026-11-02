//! Process setup for the `ray` binary: the root check, tracing and log files,
//! the OpenTelemetry layer, and the panic hook.

use crate::*;

pub(crate) fn check_root() {
    #[cfg(unix)]
    {
        if uzers::get_effective_uid() == 0 || has_cap_net_admin() {
            return;
        }
        eprintln!(
            "rayfish needs root or CAP_NET_ADMIN to create TUN devices. Run with sudo, or use the systemd unit (which grants CAP_NET_ADMIN to a dynamic user)."
        );
        std::process::exit(1);
    }
}

/// Whether this process holds CAP_NET_ADMIN — i.e. it is running under a
/// unit like the bundled `rayfish.service`, which drops full root but keeps
/// the network-administration capability the daemon needs for TUN, routes
/// and DNS. Linux only; elsewhere this is always false.
#[cfg(target_os = "linux")]
pub(crate) fn has_cap_net_admin() -> bool {
    const CAP_NET_ADMIN: u32 = 12;
    // Read the effective capability set from /proc instead of calling
    // capget(2): libc does not expose the __user_cap_* structs portably.
    // CapEff uses one bit per capability, index 12 = CAP_NET_ADMIN.
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let Some(hex) = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:").map(str::trim))
    else {
        return false;
    };
    let Ok(effective) = u64::from_str_radix(hex, 16) else {
        return false;
    };
    effective & (1 << CAP_NET_ADMIN) != 0
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn has_cap_net_admin() -> bool {
    false
}

/// Guards that must outlive the process: the file appender's `WorkerGuard`
/// (flushes buffered log lines) and, under the `otel` feature, the OpenTelemetry
/// tracer provider (flushed on drop so in-flight spans are exported).
#[derive(Default)]
pub(crate) struct LogGuard {
    _appender: Option<tracing_appender::non_blocking::WorkerGuard>,
    #[cfg(feature = "otel")]
    otel_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        #[cfg(feature = "otel")]
        if let Some(provider) = self.otel_provider.take() {
            let _ = provider.shutdown();
        }
    }
}

/// Build the tracing subscriber. The console layer (stdout) is always present;
/// the daemon additionally gets a rolling daily file layer under [`logdir::log_dir`]
/// so that `ray report` has on-disk logs to bundle. With the `otel` feature and an
/// OTLP endpoint configured, spans are also exported to an OpenTelemetry collector.
/// The returned [`LogGuard`] must be kept alive for the lifetime of the process.
pub(crate) fn init_tracing(to_file: bool) -> LogGuard {
    use std::io::IsTerminal;
    use tracing_subscriber::prelude::*;

    // The global gate must be permissive enough for the most verbose layer (the
    // file), or events are dropped before any layer sees them. Default it to our
    // crate at `debug` (dependencies stay at `info` so iroh/quinn don't flood the
    // file), then keep the console quieter with a per-layer `info` filter below.
    // `RUST_LOG` overrides both, so an operator can still dial either up or down.
    let global_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,rayfish=debug"));
    let console_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // Console layer: human text on stdout, held at `info` so CLI output and the
    // daemon console stay readable while the file keeps the `debug` detail.
    // Color only when stdout is a terminal: under systemd stdout is a pipe to
    // journald, and ANSI escapes would end up verbatim in syslog.
    let console_layer = tracing_subscriber::fmt::layer()
        .with_ansi(std::io::stdout().is_terminal())
        .with_filter(console_filter);

    // File layer: daemon only, human text with ANSI stripped, rotated daily.
    let (file_layer, appender_guard) = if to_file {
        match std::fs::create_dir_all(logdir::log_dir()) {
            Ok(()) => {
                // Daily rotation; retain the 7 most recent files so logs older
                // than ~a week are pruned automatically (bounds disk usage).
                match tracing_appender::rolling::Builder::new()
                    .rotation(tracing_appender::rolling::Rotation::DAILY)
                    .filename_prefix("rayfish.log")
                    .max_log_files(7)
                    .build(logdir::log_dir())
                {
                    Ok(appender) => {
                        let (writer, guard) = tracing_appender::non_blocking(appender);
                        let layer = tracing_subscriber::fmt::layer()
                            .with_ansi(false)
                            .with_writer(writer);
                        (Some(layer), Some(guard))
                    }
                    Err(e) => {
                        eprintln!(
                            "warning: cannot build rolling log appender: {e} (file logging disabled)"
                        );
                        (None, None)
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "warning: cannot create log directory {}: {e} (file logging disabled)",
                    logdir::log_dir().display()
                );
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    let mut guard = LogGuard {
        _appender: appender_guard,
        #[cfg(feature = "otel")]
        otel_provider: None,
    };

    // OTLP span export layer: only built when the feature is on AND an endpoint
    // is configured. Type-erased to `Box<dyn Layer>` so the `None` case has a
    // concrete type; the daemon flushes the provider on shutdown via `LogGuard`.
    let otel_layer = build_otel_layer(&mut guard);

    tracing_subscriber::registry()
        .with(global_filter)
        .with(console_layer)
        .with(file_layer)
        .with(otel_layer)
        .init();
    guard
}

#[cfg(feature = "otel")]
pub(crate) fn build_otel_layer<S>(
    guard: &mut LogGuard,
) -> Option<Box<dyn tracing_subscriber::Layer<S> + Send + Sync>>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a> + Send + Sync,
{
    use opentelemetry::trace::TracerProvider as _;
    use tracing_subscriber::Layer as _;

    // Respect the standard OTLP env vars: do nothing unless an endpoint is set.
    if std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_none()
        && std::env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_none()
    {
        return None;
    }

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .build()
    {
        Ok(e) => e,
        Err(e) => {
            eprintln!("otel: failed to build OTLP exporter: {e}");
            return None;
        }
    };

    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name("rayfish")
        .build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();
    let tracer = provider.tracer("rayfish");
    guard.otel_provider = Some(provider);

    tracing::info!("OpenTelemetry OTLP span export enabled");
    Some(tracing_opentelemetry::layer().with_tracer(tracer).boxed())
}

/// No-op when the `otel` feature is disabled; the registry sees an inert layer.
#[cfg(not(feature = "otel"))]
pub(crate) fn build_otel_layer(
    _guard: &mut LogGuard,
) -> Option<tracing_subscriber::layer::Identity> {
    None
}

/// Install a fail-fast panic hook (daemon only). On any panic (including in a
/// spawned tokio task, which the runtime would otherwise swallow) it records the
/// crash (message, location, thread, backtrace) via `tracing::error!` (rolling file
/// log + any OTLP exporter) and synchronously appends it to `panic.log` in the log
/// dir, then **aborts the process**.
///
/// Rationale: a panic is an invariant violation. For a VPN daemon, limping on with
/// a dead subsystem (e.g. a stalled forwarding loop) is worse than a clean restart,
/// and a live-but-broken process won't trip the service manager's restart. Aborting
/// lets systemd/launchd restart from known-good state; peers then reconnect. The
/// crash is captured (durably in `panic.log`) and bundled by `ray report`.
pub(crate) fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let thread = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string();
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_string());

        tracing::error!(
            location = %location,
            thread = %thread,
            "panic: {message}\n{backtrace}"
        );
        // Durable, synchronous capture: survives even though abort() skips the
        // async log appender's flush.
        if let Err(e) = append_panic_log(&location, &thread, &message, &backtrace) {
            eprintln!("failed to write panic log: {e}");
        }

        // Hand DNS back to the OS and remove the exit-node kernel state before
        // we abort, so a crash leaves neither a dead resolver nor an open router.
        rayfish::daemon::restore_host_state();

        // Print the standard panic message to stderr (journal), then fail fast so
        // the service manager restarts the daemon cleanly.
        default_hook(info);
        std::process::abort();
    }));
}

/// `ray daemon --cleanup`: the service manager's post-stop hook.
pub(crate) fn cmd_daemon_cleanup() -> Result<()> {
    #[cfg(unix)]
    {
        match daemon::cleanup_after_exit()? {
            daemon::CleanupOutcome::Cleaned => tracing::info!("post-stop cleanup done"),
            daemon::CleanupOutcome::DaemonRunning => {
                tracing::info!("a rayfish daemon is running; leaving its state alone")
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    anyhow::bail!("ray daemon --cleanup is not used on this platform")
}

/// Append a panic record to `<log_dir>/panic.log`. Best-effort durability in case
/// the tracing pipeline itself is implicated in the crash.
pub(crate) fn append_panic_log(
    location: &str,
    thread: &str,
    message: &str,
    backtrace: &std::backtrace::Backtrace,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let dir = logdir::log_dir();
    std::fs::create_dir_all(&dir)?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("panic.log"))?;
    writeln!(f, "=== panic @ unix {ts} ===")?;
    writeln!(f, "thread:   {thread}")?;
    writeln!(f, "location: {location}")?;
    writeln!(f, "message:  {message}")?;
    writeln!(f, "backtrace:\n{backtrace}\n")?;
    Ok(())
}
