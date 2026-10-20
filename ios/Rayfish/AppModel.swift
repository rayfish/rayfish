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
    private var keychainChecked: String?

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
        Task.detached(priority: .utility) { Outbox.prune() }
        refresh()
    }

    /// Name the device after the one set in Settings on first run, so pairing
    /// auto-joins all use one name: `Alice's iPhone` becomes `alice-iphone`.
    /// Without the user-assigned-device-name entitlement iOS answers `iPhone`.
    private func seedDeviceName() async {
        let node = tunnel.local.node
        let name = UIDevice.current.name
        await Task.detached { try? node.seedDefaultHostname(name: name) }.value
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
                if let snapshot = reply.snapshot { apply(snapshot) }
                if refreshFailed { refreshFailed = false }
            } catch {
                if !refreshFailed { refreshFailed = true }
            }
            if !loaded { loaded = true }
            await Task.detached(priority: .utility) { ReceivedFiles.collect() }.value
        }
    }

    /// Run a command, show its error as a toast, and refresh on success.
    @discardableResult
    func perform(_ command: Command, success: String? = nil) async -> Reply? {
        do {
            let reply = try await tunnel.send(command)
            if let message = success ?? reply.message { toast = message }
            // Most commands answer with a fresh snapshot; only fetch one if not.
            if let snapshot = reply.snapshot { apply(snapshot) } else { refresh() }
            return reply
        } catch {
            toast = error.localizedDescription
            return nil
        }
    }

    /// Every published change redraws the tabs; the 2 s poll mostly repeats itself.
    private func apply(_ next: Snapshot) {
        if next != snapshot { snapshot = next }
        keepKeychainBackup()
    }

    /// Keep this device's identity in iCloud Keychain, once per identity and
    /// launch, so a new phone on the same Apple ID can restore it.
    private func keepKeychainBackup() {
        let nodeId = snapshot.nodeId
        guard !nodeId.isEmpty, nodeId != keychainChecked else { return }
        keychainChecked = nodeId
        let node = tunnel.local.node
        let name = snapshot.deviceName.isEmpty ? UIDevice.current.name : snapshot.deviceName
        Task.detached(priority: .utility) {
            guard !IdentityKeychain.list().contains(where: { $0.publicKey == nodeId }) else { return }
            try? IdentityKeychain.save(node: node, deviceName: name)
        }
    }

    /// An invite code for `network`, ready to show.
    func invite(_ network: String) async -> SharedCode? {
        guard let code = await perform(.invite(network: network))?.code else { return nil }
        return SharedCode(title: "Invite to \(network)", code: code)
    }

    func copy(_ text: String, toast message: String? = nil) {
        copyToClipboard(text)
        toast = message ?? "Copied \(text)"
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
