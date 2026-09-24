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
        if manager.connection.status == .connected || manager.connection.status == .connecting { return manager }
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = providerIdentifier
        configuration.serverAddress = "Rayfish"
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "Rayfish"
        manager.isEnabled = true
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        return manager
    }
}
