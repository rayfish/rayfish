import Foundation
import NetworkExtension

enum TunnelState: Equatable {
    case off, connecting, on, disconnecting

    var isTransitioning: Bool { self == .connecting || self == .disconnecting }
}

/// Where the node runs, and how the app reaches it.
@MainActor
protocol Tunnel: AnyObject {
    var state: TunnelState { get }
    var onChange: (() -> Void)? { get set }
    /// The node in this process. Unstarted on a device: it answers from the
    /// saved config, and backs up or restores the identity while the tunnel is off.
    var local: NodeHost { get }
    func load() async
    func connect() async throws
    func disconnect() async
    func send(_ command: Command) async throws -> Reply
}

enum TunnelError: LocalizedError {
    case offline, timedOut, noResponse, notConfigured
    case node(String)

    var errorDescription: String? {
        switch self {
        case .offline: "Turn Rayfish on first"
        case .timedOut: "Rayfish did not answer in time"
        case .noResponse: "Rayfish returned no response"
        case .notConfigured: "The Rayfish VPN configuration is missing"
        case .node(let message): message
        }
    }
}

extension NodeHost {
    /// Run a command off the main thread. A node that is not running reports
    /// that plainly instead of the core's internal error name.
    func run(_ command: Command) async throws -> Reply {
        try await Task.detached(priority: .userInitiated) {
            do {
                return try self.handle(command)
            } catch RayError.NotStarted {
                throw TunnelError.offline
            } catch let error as RayError {
                throw TunnelError.node(userMessage(error))
            }
        }.value
    }
}

/// The real thing: the node lives in the packet tunnel extension and the app
/// talks to it with provider messages while the VPN is connected.
@MainActor
final class DeviceTunnel: Tunnel {
    private(set) var state = TunnelState.off
    var onChange: (() -> Void)?
    let local: NodeHost
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    init(local: NodeHost) {
        self.local = local
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.update() }
        }
    }

    func load() async {
        do {
            manager = try await NETunnelProviderManager.loadAllFromPreferences().first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == AppGroup.tunnelBundleIdentifier
            }
        } catch {
            RayfishLog.app.error("Loading VPN preferences failed: \(error.localizedDescription, privacy: .public)")
        }
        update()
    }

    func connect() async throws {
        let manager = try await configuredManager()
        try manager.connection.startVPNTunnel()
        update()
    }

    func disconnect() async {
        manager?.connection.stopVPNTunnel()
        update()
    }

    /// Whether the VPN starts by itself whenever the device has a network.
    var onDemand: Bool { manager?.isOnDemandEnabled ?? false }

    func setOnDemand(_ enabled: Bool) async throws {
        let manager = try await configuredManager()
        manager.onDemandRules = [NEOnDemandRuleConnect()]
        manager.isOnDemandEnabled = enabled
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
    }

    func send(_ command: Command) async throws -> Reply {
        guard state == .on, let session = manager?.connection as? NETunnelProviderSession else {
            return try await local.run(command)
        }
        let data = try JSONEncoder().encode(command)
        let reply = try await ProviderMessage.send(data, timeout: command.timeout) { data, handler in
            try session.sendProviderMessage(data, responseHandler: handler)
        }
        let decoded = try JSONDecoder().decode(Reply.self, from: reply)
        if let error = decoded.error { throw TunnelError.node(error) }
        return decoded
    }

    /// Install the VPN configuration on first use. iOS asks the person to allow it.
    private func configuredManager() async throws -> NETunnelProviderManager {
        let manager = manager ?? NETunnelProviderManager()
        let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppGroup.tunnelBundleIdentifier
        proto.serverAddress = "Rayfish mesh"
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Rayfish"
        manager.isEnabled = true
        try await manager.saveToPreferences()
        // A freshly saved configuration cannot start until it is reloaded.
        try await manager.loadFromPreferences()
        self.manager = manager
        return manager
    }

    private func update() {
        let next: TunnelState = switch manager?.connection.status {
        case .connected: .on
        case .connecting, .reasserting: .connecting
        case .disconnecting: .disconnecting
        default: .off
        }
        guard next != state else { return }
        state = next
        onChange?()
    }
}

/// The simulator cannot run packet tunnels, so it starts the node in the app.
/// Everything but the data plane works: networks, peers, files, pairing.
@MainActor
final class SimulatorTunnel: Tunnel {
    private(set) var state = TunnelState.off
    var onChange: (() -> Void)?
    let local: NodeHost

    init(local: NodeHost) {
        self.local = local
        local.onReceived = { name in RayfishLog.app.info("Received \(name, privacy: .public)") }
    }

    func load() async {}

    func connect() async throws {
        set(.connecting)
        do {
            try await Task.detached { [local] in try local.start() }.value
            set(.on)
        } catch {
            set(.off)
            throw error
        }
    }

    func disconnect() async {
        set(.disconnecting)
        await Task.detached { [local] in local.stop() }.value
        set(.off)
    }

    func send(_ command: Command) async throws -> Reply {
        let reply = try await local.run(command)
        if case .acceptFile = command {} else { local.autoAcceptOwnDevices() }
        return reply
    }

    private func set(_ next: TunnelState) {
        state = next
        onChange?()
    }
}

enum ProviderMessage {
    /// Send one provider message and wait for its reply, failing after `timeout`.
    @MainActor
    static func send(
        _ data: Data,
        timeout: TimeInterval,
        using sendMessage: @MainActor (Data, @escaping (Data?) -> Void) throws -> Void
    ) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            let pending = PendingReply(continuation)
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                pending.finish(.failure(TunnelError.timedOut))
            }
            do {
                try sendMessage(data) { reply in
                    pending.finish(reply.map { .success($0) } ?? .failure(TunnelError.noResponse))
                }
            } catch {
                pending.finish(.failure(error))
            }
        }
    }
}

private final class PendingReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?

    init(_ continuation: CheckedContinuation<Data, Error>) {
        self.continuation = continuation
    }

    func finish(_ result: Result<Data, Error>) {
        let continuation = lock.withLock {
            defer { self.continuation = nil }
            return self.continuation
        }
        continuation?.resume(with: result)
    }
}
