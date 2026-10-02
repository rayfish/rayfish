import Combine
import Darwin
import Foundation
import Network
import NetworkExtension
import OSLog
import ServiceManagement

@MainActor
final class TunnelController: ObservableObject {
    private static let migrationCompletedKey = "legacyMigrationCompleted"
    private static let reconnectAfterUpdateKey = "reconnectAfterUpdate"
    private var didStart = false
    private var isRefreshing = false
    private var isQuitting = false
    private var pollingTask: Task<Void, Never>?
    private var machinesTask: Task<Void, Never>?
    private var reconnectTask: Task<Void, Never>?
    private let pathMonitor = NWPathMonitor()
    private let pathMonitorQueue = DispatchQueue(label: "com.rayfish.app.network-path")
    private var networkAvailable = false
    private var wantsConnection = false
    private var lastMachinesRefresh = Date.distantPast
    let notifications = RayfishNotifications()

    @Published var page: RayfishPage = .networks

    @Published var status: ProviderStatus? {
        didSet { notifications.update(status) }
    }
    @Published private(set) var firewall: ProviderFirewallState?
    @Published private(set) var machines: [ProviderMachine] = []
    @Published private(set) var machinesError: String?
    @Published private(set) var isRefreshingMachines = false
    @Published var error: String? {
        didSet {
            if let error, error != oldValue { RayfishLog.app.error("\(error, privacy: .public)") }
        }
    }
    @Published var isLoading = false
    @Published var activity: String?
    @Published private(set) var launchAtLoginEnabled = false
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

    deinit {
        pollingTask?.cancel()
        machinesTask?.cancel()
        reconnectTask?.cancel()
        pathMonitor.cancel()
    }

    func startup() async {
        guard !didStart else { return }
        didStart = true
        startNetworkMonitoring()
        Task { await notifications.requestAuthorization() }
        refreshLaunchAtLogin()
        RayfishLog.app.info("Starting Rayfish build \(Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown", privacy: .public)")
        do {
            let manager = try await TunnelPreferences.load()
            let needsImport = LegacyDaemon.isInstalled
                && !UserDefaults.standard.bool(forKey: Self.migrationCompletedKey)
            let reconnectAfterUpdate = UserDefaults.standard.bool(forKey: Self.reconnectAfterUpdateKey)
            UserDefaults.standard.removeObject(forKey: Self.reconnectAfterUpdateKey)
            wantsConnection = reconnectAfterUpdate || needsImport || launchAtLoginEnabled
                || manager?.connection.status == .connected
                || manager?.connection.status == .connecting
                || manager?.connection.status == .reasserting
            if wantsConnection {
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

    private func startNetworkMonitoring() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            let available = path.status == .satisfied
            Task { @MainActor [weak self] in
                self?.networkAvailabilityChanged(available)
            }
        }
        pathMonitor.start(queue: pathMonitorQueue)
    }

    private func networkAvailabilityChanged(_ available: Bool) {
        guard networkAvailable != available else { return }
        networkAvailable = available
        if available {
            scheduleReconnect()
        } else {
            reconnectTask?.cancel()
            reconnectTask = nil
        }
    }

    private func scheduleReconnect() {
        guard wantsConnection, networkAvailable, !isQuitting,
              !isConnected, reconnectTask == nil else { return }
        reconnectTask = Task { [weak self] in
            defer { self?.reconnectTask = nil }
            for delay in [1, 2, 4, 8, 15, 30] {
                do { try await Task.sleep(for: .seconds(delay)) }
                catch { return }
                guard let self, self.wantsConnection, self.networkAvailable,
                      !self.isQuitting else { return }
                let current = (try? await TunnelPreferences.load())?.connection.status ?? .disconnected
                self.connectionStatus = current
                if current == .connected || current == .connecting || current == .reasserting {
                    return
                }
                RayfishLog.app.info("Network is available, retrying VPN connection")
                await self.connect()
                if self.isConnected { return }
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
            guard isConnected else { status = nil; clearMachines(); return }
            let response = try await TunnelIPC.request(ProviderRequest(action: .status))
            guard !isLoading, !isQuitting else { return }
            status = response.status
            if status?.needsTCPHelper == true { try SSHHelper.register() }
            error = status?.needsTCPHelper == true ? SSHHelper.approvalMessage : nil
            if Date().timeIntervalSince(lastMachinesRefresh) >= 30 { refreshMachines() }
        } catch {
            if !isLoading, !isQuitting { self.error = error.localizedDescription }
        }
    }

    func connect() async {
        wantsConnection = true
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
            if let current = try await TunnelPreferences.load(),
               current.connection.status == .connected || current.connection.status == .connecting
                   || current.connection.status == .reasserting,
               TunnelOwner.uid(in: (current.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration) != getuid() {
                try await stopTunnel()
            }
            let manager = try await TunnelPreferences.configured()
            guard !isQuitting else { return }
            if manager.connection.status != .connected && manager.connection.status != .connecting
                && manager.connection.status != .reasserting {
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
                    if status?.needsTCPHelper == true {
                        try SSHHelper.register(openSettings: true)
                        error = SSHHelper.approvalMessage
                    }
                    refreshMachines()
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
            scheduleReconnect()
        }
    }

    func disconnect() async {
        wantsConnection = false
        reconnectTask?.cancel()
        reconnectTask = nil
        guard !isLoading else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            try await stopTunnel()
            error = nil
        } catch { self.error = error.localizedDescription }
    }

    func prepareToQuit(forUpdate: Bool = false) async -> Bool {
        let resumeConnection = wantsConnection
        isQuitting = true
        wantsConnection = false
        reconnectTask?.cancel()
        reconnectTask = nil
        RayfishLog.app.info("Disconnecting before quit")
        do {
            try await stopTunnel()
            if forUpdate {
                UserDefaults.standard.set(resumeConnection, forKey: Self.reconnectAfterUpdateKey)
            }
            pollingTask?.cancel()
            return true
        } catch {
            isQuitting = false
            wantsConnection = resumeConnection
            scheduleReconnect()
            self.error = "Could not disconnect before quitting: \(error.localizedDescription)"
            return false
        }
    }

    private func stopTunnel() async throws {
        clearMachines()
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

    func refreshMachines() {
        guard isConnected, !isQuitting, machinesTask == nil else { return }
        isRefreshingMachines = true
        machinesTask = Task { [weak self] in
            do {
                let response = try await TunnelIPC.request(ProviderRequest(action: .machines))
                guard !Task.isCancelled, let self, self.isConnected else { return }
                guard let machines = response.machines else { throw TunnelIPCError.noResponse }
                self.machines = machines.sorted { $0.hostname.localizedStandardCompare($1.hostname) == .orderedAscending }
                self.machinesError = nil
            } catch {
                guard !Task.isCancelled else { return }
                self?.machinesError = error.localizedDescription
            }
            self?.lastMachinesRefresh = Date()
            self?.isRefreshingMachines = false
            self?.machinesTask = nil
        }
    }

    private func clearMachines() {
        machinesTask?.cancel()
        machinesTask = nil
        machines = []
        machinesError = nil
        isRefreshingMachines = false
        lastMachinesRefresh = .distantPast
    }

    func setSetting(_ setting: ProviderSetting, enabled: Bool) async {
        if setting == .ssh, enabled {
            do { try SSHHelper.register(openSettings: true) }
            catch { self.error = error.localizedDescription; return }
        }
        guard await perform(ProviderRequest(action: .setSetting, setting: setting, enabled: enabled)) != nil else { return }
        if setting == .ssh, enabled { error = SSHHelper.approvalMessage }
    }

    func selectExitNode(network: String, peer: String?) async {
        _ = await perform(ProviderRequest(action: .selectExitNode, peer: peer, network: network))
    }

    func reconnect() async {
        await disconnect()
        guard connectionStatus == .disconnected || connectionStatus == .invalid else { return }
        await connect()
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        let service = SMAppService.mainApp
        do {
            if enabled {
                try service.register()
            } else {
                try service.unregister()
            }
            refreshLaunchAtLogin()
            if enabled, service.status == .requiresApproval {
                SMAppService.openSystemSettingsLoginItems()
            }
            error = nil
        } catch {
            refreshLaunchAtLogin()
            self.error = "Could not update Start at login: \(error.localizedDescription)"
        }
    }

    private func refreshLaunchAtLogin() {
        let status = SMAppService.mainApp.status
        launchAtLoginEnabled = status == .enabled || status == .requiresApproval
    }

    func connectPeer(id: String, hostname: String?) async -> String? {
        await perform(ProviderRequest(action: .connectPeer, hostname: hostname, id: id))?.message
    }

    func approveConnection(id: String) async {
        _ = await perform(ProviderRequest(action: .approveConnection, id: id))
    }

    func rejectConnection(id: String) async {
        _ = await perform(ProviderRequest(action: .rejectConnection, id: id))
    }

    func acceptFile(_ file: ProviderFile, directory: URL) async {
        _ = await perform(ProviderRequest(action: .acceptFile, fileId: file.transferId,
                                         directory: directory.path, uid: getuid(), gid: getgid()))
    }

    func rejectFile(_ file: ProviderFile) async {
        _ = await perform(ProviderRequest(action: .rejectFile, fileId: file.transferId))
    }

    func setSSHRule(_ rule: ProviderSSHRule, allow: Bool) async -> Bool {
        await perform(ProviderRequest(action: .setSSHRule, name: rule.network, id: rule.peer,
                                      enabled: allow, users: rule.users)) != nil
    }

    func loadFirewall() async {
        _ = await perform(ProviderRequest(action: .firewallShow))
    }

    func addFirewallRule(direction: String, action: String, protocolName: String,
                         port: String, peer: String?, network: String?) async {
        _ = await perform(ProviderRequest(action: .firewallAdd, direction: direction, ruleAction: action,
                                          protocolName: protocolName, port: port.isEmpty ? nil : port,
                                          peer: peer, network: network))
    }

    func removeFirewallRule(at index: UInt32) async {
        _ = await perform(ProviderRequest(action: .firewallRemove, ruleIndex: index))
    }

    func setFirewallDefaultInbound(_ action: String) async {
        _ = await perform(ProviderRequest(action: .firewallSetDefault, ruleAction: action))
    }

    private func perform(_ request: ProviderRequest) async -> ProviderResponse? {
        guard !isLoading, !isQuitting else { return nil }
        isLoading = true
        defer { isLoading = false }
        do {
            let response = try await TunnelIPC.request(request)
            status = response.status
            if let firewall = response.firewall { self.firewall = firewall }
            error = nil
            return response
        } catch {
            self.error = error.localizedDescription
            return nil
        }
    }
}
