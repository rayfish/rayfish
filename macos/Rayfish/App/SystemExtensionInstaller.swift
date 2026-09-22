import Foundation
import SystemExtensions

@MainActor
final class SystemExtensionInstaller: NSObject, OSSystemExtensionRequestDelegate {
    private let identifier: String
    private var continuation: CheckedContinuation<Void, Error>?

    init(identifier: String) {
        self.identifier = identifier
    }

    func install() async throws {
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
        finish(.success(()))
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        finish(.failure(error))
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {}

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension replacement: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    private func finish(_ result: Result<Void, Error>) {
        let continuation = continuation
        self.continuation = nil
        continuation?.resume(with: result)
    }
}
