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
    case timedOut, noResponse
    case node(String)

    var errorDescription: String? {
        switch self {
        case .timedOut: "Rayfish did not answer in time"
        case .noResponse: "Rayfish returned no response"
        case .node(let message): message
        }
    }
}

extension NodeHost {
    /// Run a command off the main thread, with the core's errors in words.
    func run(_ command: Command) async throws -> Reply {
        try await Task.detached(priority: .userInitiated) {
            do {
                return try self.handle(command)
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
            manager = try await VPNPreferences.load()
        } catch {
            RayfishLog.app.error("Loading VPN preferences failed: \(error.localizedDescription, privacy: .public)")
        }
        update()
    }

    func connect() async throws {
        manager = try await VPNPreferences.start(install: true)
        update()
    }

    func disconnect() async {
        do {
            if let current = try await VPNPreferences.stop() { manager = current }
        } catch {
            RayfishLog.app.error("Turning off on-demand failed: \(error.localizedDescription, privacy: .public)")
            manager?.connection.stopVPNTunnel()
        }
        update()
    }

    func send(_ command: Command) async throws -> Reply {
        guard state == .on, let session = manager?.connection as? NETunnelProviderSession else {
            return try await local.run(command)
        }
        let data = try JSONEncoder().encode(command)
        let reply = try await ProviderReply.send(
            data, timeout: command.timeout, timedOut: TunnelError.timedOut, noResponse: TunnelError.noResponse
        ) { data, handler in
            try session.sendProviderMessage(data, responseHandler: handler)
        }
        let decoded = try JSONDecoder().decode(Reply.self, from: reply)
        if let error = decoded.error { throw TunnelError.node(error) }
        return decoded
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
        VPNPreferences.reloadControl()
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
            Telemetry.captureStartFailure(error, node: local.node)
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
