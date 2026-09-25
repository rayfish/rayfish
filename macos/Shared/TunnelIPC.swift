import Foundation
import NetworkExtension
import OSLog

enum RayfishLog {
    static let app = Logger(subsystem: "com.rayfish.app", category: "app")
    static let tunnel = Logger(subsystem: "com.rayfish.app", category: "tunnel")
    static let ipc = Logger(subsystem: "com.rayfish.app", category: "ipc")
}

@MainActor
enum TunnelIPC {
    static func request(_ request: ProviderRequest) async throws -> ProviderResponse {
        RayfishLog.ipc.debug("Sending \(request.action.rawValue, privacy: .public)")
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            guard let manager = managers.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.rayfish.app.tunnel"
            }), let session = manager.connection as? NETunnelProviderSession else {
                throw TunnelIPCError.unavailable
            }
            // NetworkExtension authenticates the containing app and routes messages to its provider.
            let data = try JSONEncoder().encode(request)
            let timeout: TimeInterval = request.action == .acceptFile ? 300
                : (request.action == .connectPeer || request.action == .approveConnection ? 90 : 10)
            let reply = try await send(data, timeout: timeout) { data, reply in
                try session.sendProviderMessage(data, responseHandler: reply)
            }
            let response = try JSONDecoder().decode(ProviderResponse.self, from: reply)
            guard response.success else { throw TunnelIPCError.provider(response.error ?? "Request rejected") }
            return response
        } catch {
            RayfishLog.ipc.error("\(request.action.rawValue, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            throw error
        }
    }

    static func send(
        _ data: Data,
        timeout: TimeInterval = 10,
        using sendMessage: @MainActor (Data, @escaping (Data?) -> Void) throws -> Void
    ) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            let pending = PendingTunnelReply(continuation: continuation)
            let timer = DispatchWorkItem { pending.finish(.failure(TunnelIPCError.timedOut)) }
            pending.setTimer(timer)
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timer)
            do {
                try sendMessage(data) { response in
                    if let response {
                        pending.finish(.success(response))
                    } else {
                        pending.finish(.failure(TunnelIPCError.noResponse))
                    }
                }
            } catch {
                pending.finish(.failure(error))
            }
        }
    }
}

private final class PendingTunnelReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    private var timer: DispatchWorkItem?

    init(continuation: CheckedContinuation<Data, Error>) {
        self.continuation = continuation
    }

    func setTimer(_ timer: DispatchWorkItem) {
        lock.lock()
        if continuation == nil { timer.cancel() } else { self.timer = timer }
        lock.unlock()
    }

    func finish(_ result: Result<Data, Error>) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        let timer = self.timer
        self.timer = nil
        lock.unlock()
        guard let continuation else { return }
        timer?.cancel()
        continuation.resume(with: result)
    }
}

enum TunnelIPCError: LocalizedError {
    case unavailable, timedOut, noResponse
    case provider(String)

    var errorDescription: String? {
        switch self {
        case .unavailable: "The Rayfish tunnel's control connection is unavailable."
        case .timedOut: "The Rayfish tunnel request timed out."
        case .noResponse: "The Rayfish tunnel returned no response."
        case .provider(let message): message
        }
    }
}
