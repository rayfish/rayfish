import Combine
import Foundation
import NetworkExtension
import OSLog

@MainActor
final class TunnelController: ObservableObject {
    private static let migrationCompletedKey = "legacyMigrationCompleted"
    private var didStart = false
    private var isRefreshing = false
    private var isQuitting = false
    private var pollingTask: Task<Void, Never>?

    @Published var status: ProviderStatus?
    @Published var error: String? {
        didSet {
            if let error, error != oldValue { RayfishLog.app.error("\(error, privacy: .public)") }
        }
    }
    @Published var isLoading = false
    @Published var activity: String?
    @Published private(set) var connectionStatus: NEVPNStatus = .disconnected {
        didSet {
            if connectionStatus != oldValue {
                RayfishLog.app.info("VPN state: \(self.connectionLabel, privacy: .public)")
            }
        }
    }

    var isConnected: Bool { connectionStatus == .connected }
    var connectionLabel: String {
        switch connectionStatus {
        case .connected: "connected"
        case .connecting, .reasserting: "connecting"
        case .disconnecting: "disconnecting"
        default: "disconnected"
        }
    }

    deinit { pollingTask?.cancel() }

    func startup() async {
        guard !didStart else { return }
        didStart = true
        RayfishLog.app.info("Starting Rayfish build \(Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown", privacy: .public)")
        do {
            let manager = try await TunnelPreferences.load()
            let needsImport = LegacyDaemon.isInstalled
                && !UserDefaults.standard.bool(forKey: Self.migrationCompletedKey)
            if needsImport || manager?.connection.status == .connected || manager?.connection.status == .connecting {
                // Activation replaces an older extension before using its command service.
                await connect()
            } else {
                await refresh()
            }
        } catch { self.error = error.localizedDescription }
        // Closing a window does not stop status updates for the menu bar.
        pollingTask = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: 3_000_000_000) }
                catch { return }
                await self?.refresh()
            }
        }
    }

    func refresh() async {
        guard !isLoading, !isRefreshing, !isQuitting else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        do {
            let manager = try await TunnelPreferences.load()
            guard !isLoading, !isQuitting else { return }
            connectionStatus = manager?.connection.status ?? .disconnected
            guard isConnected else { status = nil; return }
            let response = try await TunnelIPC.request(ProviderRequest(action: .status))
            guard !isLoading, !isQuitting else { return }
            status = response.status
            error = nil
        } catch {
            if !isLoading, !isQuitting { self.error = error.localizedDescription }
        }
    }

    func connect() async {
        guard !isLoading, !isQuitting else { return }
        isLoading = true
        error = nil
        activity = "Activating the Rayfish network extension..."
        defer { isLoading = false; activity = nil }
        do {
            let installer = SystemExtensionInstaller(identifier: TunnelPreferences.providerIdentifier)
            installer.onNeedsUserApproval = { [weak self] in
                self?.activity = "Enable Rayfish Tunnel in System Settings > General > Login Items & Extensions > Network Extensions to continue."
            }
            try await installer.install()
            guard !isQuitting else { return }
            activity = "Connecting..."
            let manager = try await TunnelPreferences.configured()
            guard !isQuitting else { return }
            if manager.connection.status != .connected && manager.connection.status != .connecting {
                try manager.connection.startVPNTunnel()
            }
            var observedConnecting = false
            connectionStatus = .connecting
            for _ in 0..<180 {
                guard !isQuitting else { return }
                let current = manager.connection.status
                // startVPNTunnel returns before macOS publishes the new state.
                // Until then, disconnected and its last error describe the old session.
                if current == .disconnected && !observedConnecting {
                    try await Task.sleep(nanoseconds: 500_000_000)
                    continue
                }
                connectionStatus = current
                observedConnecting = observedConnecting || current == .connecting || current == .reasserting
                if isConnected {
                    let response = try await TunnelIPC.request(ProviderRequest(action: .status))
                    status = response.status
                    UserDefaults.standard.set(true, forKey: Self.migrationCompletedKey)
                    return
                }
                if connectionStatus == .disconnected || connectionStatus == .invalid {
                    try await manager.connection.fetchLastDisconnectError()
                    throw TunnelIPCError.unavailable
                }
                try await Task.sleep(nanoseconds: 500_000_000)
            }
            throw TunnelIPCError.timedOut
        } catch {
            self.error = error.localizedDescription
            connectionStatus = (try? await TunnelPreferences.load())?.connection.status ?? .disconnected
        }
    }

    func disconnect() async {
        guard !isLoading else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            try await stopTunnel()
            error = nil
        } catch { self.error = error.localizedDescription }
    }

    func prepareToQuit() async -> Bool {
        isQuitting = true
        RayfishLog.app.info("Disconnecting before quit")
        do {
            try await stopTunnel()
            pollingTask?.cancel()
            return true
        } catch {
            isQuitting = false
            self.error = "Could not disconnect before quitting: \(error.localizedDescription)"
            return false
        }
    }

    private func stopTunnel() async throws {
        let started = DispatchTime.now().uptimeNanoseconds
        guard let manager = try await TunnelPreferences.load() else { return }
        RayfishLog.app.info("Requesting VPN disconnect")
        manager.connection.stopVPNTunnel()
        for _ in 0..<100 {
            connectionStatus = manager.connection.status
            if connectionStatus == .disconnected || connectionStatus == .invalid {
                status = nil
                let elapsedMs = (DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
                RayfishLog.app.info("VPN disconnected in \(elapsedMs) ms")
                return
            }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        throw TunnelIPCError.timedOut
    }

    func create(name: String?, hostname: String?) async {
        _ = await perform(ProviderRequest(action: .create, name: name, hostname: hostname))
    }

    func join(code: String, hostname: String?) async {
        _ = await perform(ProviderRequest(action: .join, code: code, hostname: hostname))
    }

    func invite(network: String) async -> String? {
        await perform(ProviderRequest(action: .invite, name: network))?.inviteCode
    }

    func leave(network: String) async {
        _ = await perform(ProviderRequest(action: .leave, name: network))
    }

    func setHostname(network: String, hostname: String) async {
        _ = await perform(ProviderRequest(action: .setHostname, name: network, hostname: hostname))
    }

    func accept(request: ProviderJoinRequest) async {
        _ = await perform(ProviderRequest(action: .acceptRequest, name: request.network, id: request.id))
    }

    func deny(request: ProviderJoinRequest) async {
        _ = await perform(ProviderRequest(action: .denyRequest, name: request.network, id: request.id))
    }

    private func perform(_ request: ProviderRequest) async -> ProviderResponse? {
        guard !isLoading, !isQuitting else { return nil }
        isLoading = true
        defer { isLoading = false }
        do {
            let response = try await TunnelIPC.request(request)
            status = response.status
            error = nil
            return response
        } catch {
            self.error = error.localizedDescription
            return nil
        }
    }
}
