import Combine
import Foundation
import NetworkExtension

@MainActor
final class TunnelController: ObservableObject {
    private static let providerBundleIdentifier = "xyz.rayfish.app.tunnel"

    @Published var status: ProviderStatus?
    @Published var error: String?
    @Published var isLoading = false

    func refresh() async {
        await perform(ProviderRequest(action: .status), replaceStatus: true)
    }

    func connect() async {
        isLoading = true
        defer { isLoading = false }
        do {
            let installer = SystemExtensionInstaller(identifier: Self.providerBundleIdentifier)
            try await installer.install()
            let manager = try await configuredManager()
            try manager.connection.startVPNTunnel()
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    func create(name: String?) async {
        await perform(ProviderRequest(action: .create, name: name, code: nil), replaceStatus: true)
    }

    func join(code: String) async {
        await perform(ProviderRequest(action: .join, name: nil, code: code), replaceStatus: true)
    }

    private func perform(_ request: ProviderRequest, replaceStatus: Bool) async {
        isLoading = true
        defer { isLoading = false }
        do {
            let manager = try await loadManager()
            let data = try JSONEncoder().encode(request)
            let responseData = try await send(data, through: manager.connection)
            let response = try JSONDecoder().decode(ProviderResponse.self, from: responseData)
            guard response.success else {
                throw TunnelError.provider(response.error ?? "The tunnel rejected the request")
            }
            if replaceStatus {
                status = response.status
            }
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func loadManager() async throws -> NETunnelProviderManager {
        let managers = try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
        guard let manager = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                == Self.providerBundleIdentifier
        }) else {
            throw TunnelError.notInstalled
        }
        return manager
    }

    private func configuredManager() async throws -> NETunnelProviderManager {
        let managers = try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
        let manager = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                == Self.providerBundleIdentifier
        }) ?? NETunnelProviderManager()
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = Self.providerBundleIdentifier
        configuration.serverAddress = "Rayfish"
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "Rayfish"
        manager.isEnabled = true
        try await withCheckedThrowingContinuation { continuation in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
        try await withCheckedThrowingContinuation { continuation in
            manager.loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
        return manager
    }

    private func send(_ data: Data, through connection: NETunnelProviderSession) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            do {
                try connection.sendProviderMessage(data) { response in
                    guard let response else {
                        continuation.resume(throwing: TunnelError.noResponse)
                        return
                    }
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}

private enum TunnelError: LocalizedError {
    case notInstalled
    case noResponse
    case provider(String)

    var errorDescription: String? {
        switch self {
        case .notInstalled:
            "Install and connect Rayfish before using it."
        case .noResponse:
            "The Rayfish tunnel did not respond."
        case let .provider(message):
            message
        }
    }
}
