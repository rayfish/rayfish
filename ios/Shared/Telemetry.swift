import Foundation
import Sentry

/// Sentry crash reporting, gated by the user's opt-out toggle in the You tab.
///
/// The app and the tunnel each run their own client. Both read the toggle from
/// the app group: the tunnel at start, when it is ready, before each report,
/// and when the app forwards a change with `Command.reloadTelemetry`.
enum Telemetry {
    /// Start or stop the client to match the toggle. Runs on the main thread:
    /// a start from any other thread installs the client later, so
    /// `isEnabled` would read false in between and two quick toggles could
    /// start it twice or skip the close.
    static func apply() {
        guard Thread.isMainThread else { return DispatchQueue.main.sync { apply() } }
        if Preferences.crashReporting { enable() } else { disable() }
    }

    /// No-op when the build carries no DSN.
    private static func enable() {
        guard !SentrySDK.isEnabled, let dsn = info("RayfishSentryDSN"), !dsn.isEmpty else { return }
        SentrySDK.start { options in
            options.dsn = dsn
            options.releaseName = "rayfish-ios@\(info("CFBundleShortVersionString") ?? "unknown")"
            // The commit the build came from, so a report can be placed against
            // a fix. Empty for builds made outside the just recipes.
            if let sha = info("RayfishGitSHA"), !sha.isEmpty { options.dist = sha }
            #if DEBUG
            options.environment = "dev"
            #else
            options.environment = "production"
            #endif
            options.sendDefaultPii = false
            // Crashes and explicit reports only. Tracing, hang detection and
            // swizzling cost memory the tunnel's 50 MB limit cannot spare.
            options.tracesSampleRate = 0
            options.enableAutoPerformanceTracing = false
            options.enableAppHangTracking = false
            options.enableSwizzling = false
            options.initialScope = { scope in
                scope.setTag(value: Preferences.installId, key: "install_id")
                return scope
            }
        }
    }

    private static func disable() {
        guard SentrySDK.isEnabled else { return }
        SentrySDK.close()
    }

    /// A node that will not start leaves the device offline with nothing on
    /// screen saying why, so it is reported without waiting for the user.
    /// At most once per half hour: every connect attempt retries the start, and
    /// each retry is a new tunnel process, so the last report time is kept in
    /// the app group.
    static func captureStartFailure(_ error: Error, node: Node) {
        // Re-read the toggle: it may have changed while the tunnel was starting.
        apply()
        guard SentrySDK.isEnabled else { return }
        let now = Date().timeIntervalSince1970
        let key = "lastStartFailureReport"
        guard now - AppGroup.defaults.double(forKey: key) >= 30 * 60 else { return }
        AppGroup.defaults.set(now, forKey: key)
        let logs = node.logSnapshot()
        SentrySDK.capture(error: error) { scope in
            // The Swift error says the start failed; the core's log says why.
            attach(logs, to: scope)
        }
    }

    /// The core's log and health as one report. False when reporting is off.
    static func sendDiagnostics(node: Node) -> Bool {
        apply()
        guard SentrySDK.isEnabled else { return false }
        let logs = node.logSnapshot()
        let health = node.healthSnapshot()
        SentrySDK.capture(message: "rayfish diagnostics") { scope in
            scope.setLevel(.info)
            scope.setContext(value: [
                "running": health.running,
                "networks": health.networkCount,
                "peers_online": health.peersOnline,
            ], key: "rayfish")
            attach(logs, to: scope)
        }
        return true
    }

    private static func attach(_ logs: String, to scope: Scope) {
        guard !logs.isEmpty else { return }
        scope.addAttachment(Attachment(data: Data(logs.utf8), filename: "rayfish-logs.txt",
                                       contentType: "text/plain"))
    }

    private static func info(_ key: String) -> String? {
        Bundle.main.object(forInfoDictionaryKey: key) as? String
    }
}
