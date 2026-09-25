import Darwin
import NetworkExtension

@MainActor
enum TunnelPreferences {
    static let providerIdentifier = "com.rayfish.app.tunnel"

    static func load() async throws -> NETunnelProviderManager? {
        try await NETunnelProviderManager.loadAllFromPreferences().first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerIdentifier
        }
    }

    static func configured() async throws -> NETunnelProviderManager {
        let manager = try await load() ?? NETunnelProviderManager()
        let configuration = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        if (manager.connection.status == .connected || manager.connection.status == .connecting),
           TunnelOwner.uid(in: configuration.providerConfiguration) == getuid() { return manager }
        configuration.providerBundleIdentifier = providerIdentifier
        configuration.serverAddress = "Rayfish"
        var providerConfiguration = configuration.providerConfiguration ?? [:]
        providerConfiguration[TunnelOwner.key] = NSNumber(value: getuid())
        configuration.providerConfiguration = providerConfiguration
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "Rayfish"
        manager.isEnabled = true
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        return manager
    }
}
