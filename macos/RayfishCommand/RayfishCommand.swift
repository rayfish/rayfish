import Darwin
import Foundation
import NetworkExtension
import SystemExtensions

@main
@MainActor
struct RayfishCommand {
    private static let providerBundleIdentifier = "com.rayfish.app.tunnel"

    static func main() async {
        do {
            let command = Array(CommandLine.arguments.dropFirst())
            switch command.first {
            case "up":
                try await connect()
            case "down":
                try await disconnect()
            case "status":
                try await status()
            case "create":
                try await request(.create, name: command.dropFirst().first)
            case "join":
                guard let code = command.dropFirst().first else {
                    throw CommandError.usage
                }
                try await request(.join, code: code)
            case "invite":
                guard let network = command.dropFirst().first else {
                    throw CommandError.usage
                }
                try await request(.invite, name: network)
            case "leave":
                guard let network = command.dropFirst().first else {
                    throw CommandError.usage
                }
                try await request(.leave, name: network)
            default:
                print("Usage: ray <up|down|status|create [name]|join <code>|invite <network>|leave <network>>")
            }
        } catch {
            FileHandle.standardError.write(Data("ray: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }

    private static func connect() async throws {
        let installer = SystemExtensionInstaller(identifier: providerBundleIdentifier)
        try await installer.install()
        let manager = try await configuredManager()
        try manager.connection.startVPNTunnel()
        print("Rayfish is connecting.")
    }

    private static func disconnect() async throws {
        let manager = try await manager()
        manager.connection.stopVPNTunnel()
        print("Rayfish disconnected.")
    }

    private static func status() async throws {
        let response = try await send(ProviderRequest(action: .status))
        guard let status = response.status else {
            throw CommandError.noStatus
        }
        let connection = status.active ? "connected" : "disconnected"
        print("Rayfish is \(connection) (\(status.ipv6)).")
        for network in status.networks {
            print("\(network.name)  \(network.hostname).\(network.name).ray  \(network.peers.count) devices")
        }
    }

    private static func request(
        _ action: ProviderRequest.Action,
        name: String? = nil,
        code: String? = nil
    ) async throws {
        let response = try await send(ProviderRequest(action: action, name: name, code: code))
        if let inviteCode = response.inviteCode {
            print(inviteCode)
        }
    }

    private static func send(_ request: ProviderRequest) async throws -> ProviderResponse {
        let manager = try await manager()
        let data = try JSONEncoder().encode(request)
        guard let session = manager.connection as? NETunnelProviderSession else {
            throw CommandError.notTunnelSession
        }
        let responseData: Data = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Data, Error>) in
            do {
                try session.sendProviderMessage(data) { response in
                    guard let response else {
                        continuation.resume(throwing: CommandError.noResponse)
                        return
                    }
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
        let response = try JSONDecoder().decode(ProviderResponse.self, from: responseData)
        guard response.success else {
            throw CommandError.provider(response.error ?? "The Rayfish tunnel rejected the request")
        }
        return response
    }

    private static func manager() async throws -> NETunnelProviderManager {
        let managers = try await loadManagers()
        guard let manager = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                == providerBundleIdentifier
        }) else {
            throw CommandError.notInstalled
        }
        return manager
    }

    private static func configuredManager() async throws -> NETunnelProviderManager {
        let manager = try await managerOrNew()
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = providerBundleIdentifier
        configuration.serverAddress = "Rayfish"
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "Rayfish"
        manager.isEnabled = true
        try await save(manager)
        try await load(manager)
        return manager
    }

    private static func managerOrNew() async throws -> NETunnelProviderManager {
        let managers = try await loadManagers()
        return managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                == providerBundleIdentifier
        }) ?? NETunnelProviderManager()
    }

    private static func loadManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<[NETunnelProviderManager], Error>) in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
    }

    private static func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private static func load(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }
}

private enum CommandError: LocalizedError {
    case usage
    case notInstalled
    case noResponse
    case noStatus
    case notTunnelSession
    case provider(String)

    var errorDescription: String? {
        switch self {
        case .usage:
            "Missing a required command argument"
        case .notInstalled:
            "Install Rayfish first with `ray up`"
        case .noResponse:
            "The Rayfish tunnel did not respond"
        case .noStatus:
            "The Rayfish tunnel returned no status"
        case .notTunnelSession:
            "The Rayfish VPN configuration is not a packet tunnel"
        case let .provider(message):
            message
        }
    }
}
