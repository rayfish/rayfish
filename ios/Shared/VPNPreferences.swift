import Foundation
import NetworkExtension
import WidgetKit

/// The Rayfish VPN configuration. The app and the Control Center toggle both
/// change it, so every call loads a fresh copy: saving one the other process
/// has since saved fails as stale.
enum VPNPreferences {
    static let providerBundleIdentifier = "xyz.rayfish.ios.tunnel"
    static let controlKind = "xyz.rayfish.ios.tunnel-control"

    static func load() async throws -> NETunnelProviderManager? {
        try await NETunnelProviderManager.loadAllFromPreferences().first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundleIdentifier
        }
    }

    /// Starting also turns on-demand on, so iOS brings the tunnel back after a
    /// reboot or when it stops the extension, like an always-on VPN. With
    /// `install`, a missing configuration is created; iOS asks the person to
    /// allow it, which only the app can show.
    static func start(install: Bool) async throws -> NETunnelProviderManager {
        guard let manager = try await load() ?? (install ? NETunnelProviderManager() : nil) else {
            throw VPNPreferencesError.notInstalled
        }
        try await save(manager, onDemand: true)
        try manager.connection.startVPNTunnel()
        return manager
    }

    /// On-demand goes off first: otherwise iOS restarts the tunnel right away.
    static func stop() async throws -> NETunnelProviderManager? {
        guard let manager = try await load() else { return nil }
        defer { manager.connection.stopVPNTunnel() }
        if manager.isOnDemandEnabled {
            try await save(manager, onDemand: false)
        }
        return manager
    }

    /// Ask Control Center to read the toggle's state again.
    static func reloadControl() {
        if #available(iOS 18.0, *) {
            ControlCenter.shared.reloadControls(ofKind: controlKind)
        }
    }

    private static func save(_ manager: NETunnelProviderManager, onDemand: Bool) async throws {
        let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = providerBundleIdentifier
        proto.serverAddress = "Rayfish mesh"
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Rayfish"
        manager.isEnabled = true
        manager.onDemandRules = [NEOnDemandRuleConnect()]
        manager.isOnDemandEnabled = onDemand
        try await manager.saveToPreferences()
        // A freshly saved configuration cannot start until it is reloaded.
        try await manager.loadFromPreferences()
    }
}

enum VPNPreferencesError: LocalizedError {
    case notInstalled

    var errorDescription: String? { "Open Rayfish to set up the VPN first" }
}
