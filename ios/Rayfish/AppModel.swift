import Foundation
import SwiftUI
import UserNotifications

/// One observed state for every tab. Reads are serialized, and a failed read
/// keeps the last known data on screen.
@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var snapshot = Snapshot()
    @Published private(set) var loaded = false
    @Published private(set) var refreshFailed = false
    @Published private(set) var tunnelState = TunnelState.off
    @Published var toast: String?
    /// Nil until checked. Starting the node mints an identity, so a fresh
    /// install is offered a restore before anything else runs.
    @Published var hasIdentity: Bool?

    let tunnel: Tunnel
    private var refreshing = false
    private var refreshAgain = false

    init() {
        let directory = (try? AppGroup.stateDirectory())
            ?? FileManager.default.temporaryDirectory.appendingPathComponent("rayfish")
        let local = NodeHost(directory: directory)
        #if targetEnvironment(simulator)
        tunnel = SimulatorTunnel(local: local)
        #else
        tunnel = DeviceTunnel(local: local)
        #endif
        tunnel.onChange = { [weak self] in
            guard let self else { return }
            tunnelState = tunnel.state
            refresh()
        }
    }

    var isSimulator: Bool {
        #if targetEnvironment(simulator)
        true
        #else
        false
        #endif
    }

    func checkIdentity() async {
        let local = tunnel.local
        hasIdentity = await Task.detached { local.node.hasIdentity() }.value
    }

    /// First run after the identity gate: load the VPN configuration and, in the
    /// simulator, bring the in-app node up like a VPN that was left on.
    func launch() async {
        await seedDeviceName()
        await tunnel.load()
        tunnelState = tunnel.state
        if isSimulator, tunnel.state == .off {
            try? await tunnel.connect()
        }
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])
        refresh()
    }

    /// Name the device after its model on first run, so pairing auto-joins all
    /// use one name. iOS only shares the user's own device name with an entitlement.
    private func seedDeviceName() async {
        let node = tunnel.local.node
        let model = UIDevice.current.model
        await Task.detached {
            guard node.defaultHostname().isEmpty else { return }
            try? node.setDefaultHostname(name: Hostnames.sanitize(model))
        }.value
    }

    func refresh() {
        guard !refreshing else {
            refreshAgain = true
            return
        }
        refreshing = true
        Task {
            defer {
                refreshing = false
                if refreshAgain {
                    refreshAgain = false
                    refresh()
                }
            }
            do {
                let reply = try await tunnel.send(.snapshot)
                if let snapshot = reply.snapshot { self.snapshot = snapshot }
                refreshFailed = false
            } catch {
                refreshFailed = true
            }
            loaded = true
            ReceivedFiles.collect()
        }
    }

    /// Run a command, show its error as a toast, and refresh on success.
    @discardableResult
    func perform(_ command: Command, success: String? = nil) async -> Reply? {
        do {
            let reply = try await tunnel.send(command)
            if let snapshot = reply.snapshot { self.snapshot = snapshot }
            if let message = success ?? reply.message { toast = message }
            refresh()
            return reply
        } catch {
            toast = error.localizedDescription
            return nil
        }
    }

    func setTunnel(_ on: Bool) async {
        do {
            if on { try await tunnel.connect() } else { await tunnel.disconnect() }
        } catch {
            toast = "Could not start Rayfish: \(error.localizedDescription)"
        }
        tunnelState = tunnel.state
        refresh()
    }

    /// Restart the node so a saved engine or identity change takes effect.
    func restart() async {
        guard tunnelState == .on else { return }
        await tunnel.disconnect()
        for _ in 0..<50 where tunnel.state != .off {
            try? await Task.sleep(for: .milliseconds(100))
        }
        await setTunnel(true)
    }
}

/// Moves finished downloads from the shared container into Documents, which
/// the Files app shows under Rayfish. The tunnel cannot write there itself.
enum ReceivedFiles {
    static func collect() {
        let manager = FileManager.default
        guard let received = try? AppGroup.received(),
              let documents = manager.urls(for: .documentDirectory, in: .userDomainMask).first,
              let files = try? manager.contentsOfDirectory(at: received, includingPropertiesForKeys: nil),
              !files.isEmpty else { return }
        for file in files {
            let target = FileNames.unique(file.lastPathComponent, in: documents)
            do {
                try manager.moveItem(at: file, to: target)
            } catch {
                RayfishLog.app.error("Moving a received file failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }
}

enum Hostnames {
    /// Lowercase `[a-z0-9-]`, hyphens collapsed and trimmed, at most 63
    /// characters: the core's hostname rules.
    static func sanitize(_ raw: String) -> String {
        var name = raw.lowercased()
            .replacingOccurrences(of: "[^a-z0-9-]", with: "-", options: .regularExpression)
            .replacingOccurrences(of: "-+", with: "-", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        if name.count > 63 { name = String(name.prefix(63)).trimmingCharacters(in: CharacterSet(charactersIn: "-")) }
        return name.isEmpty ? "phone" : name
    }
}
