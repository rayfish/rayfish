import Foundation
import SystemExtensions
import OSLog

@MainActor
final class SystemExtensionInstaller: NSObject, @preconcurrency OSSystemExtensionRequestDelegate {
    private let identifier: String
    private var continuation: CheckedContinuation<Void, Error>?
    var onNeedsUserApproval: (() -> Void)?

    init(identifier: String) {
        self.identifier = identifier
    }

    func install() async throws {
        RayfishLog.app.info("Requesting tunnel extension activation")
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: identifier,
                queue: .main
            )
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        RayfishLog.app.info("Extension activation result: \(result.rawValue)")
        if result == .willCompleteAfterReboot {
            finish(.failure(TunnelIPCError.provider("Restart this Mac to finish updating the Rayfish tunnel.")))
        } else {
            finish(.success(()))
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        RayfishLog.app.error("Extension activation failed: \(error.localizedDescription, privacy: .public)")
        finish(.failure(error))
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        RayfishLog.app.notice("Tunnel extension is waiting for approval in System Settings")
        onNeedsUserApproval?()
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension replacement: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        RayfishLog.app.info("Replacing tunnel build \(existing.bundleVersion, privacy: .public) with \(replacement.bundleVersion, privacy: .public)")
        return .replace
    }

    private func finish(_ result: Result<Void, Error>) {
        let continuation = continuation
        self.continuation = nil
        continuation?.resume(with: result)
    }
}
