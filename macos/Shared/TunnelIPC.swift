import Foundation
import NetworkExtension
import OSLog

enum RayfishLog {
    static let app = Logger(subsystem: "com.rayfish.app", category: "app")
    static let tunnel = Logger(subsystem: "com.rayfish.app", category: "tunnel")
    static let ipc = Logger(subsystem: "com.rayfish.app", category: "ipc")
}

// NetworkExtension retains sessions created by preference loads. Reuse the
// manager until its configuration changes, including while polling status.
@MainActor
final class TunnelManagerCache {
    nonisolated static let providerIdentifier = "com.rayfish.app.tunnel"
    static let shared = TunnelManagerCache()

    private let loadManagers: @MainActor () async throws -> [NETunnelProviderManager]
    private let notificationCenter: NotificationCenter
    private var observer: NSObjectProtocol?
    private var manager: NETunnelProviderManager?
    private var hasLoaded = false
    private var generation = 0
    private var loading: Task<NETunnelProviderManager?, Error>?

    init(notificationCenter: NotificationCenter = .default,
         loadManagers: @escaping @MainActor () async throws -> [NETunnelProviderManager] = {
             try await NETunnelProviderManager.loadAllFromPreferences()
         }) {
        self.notificationCenter = notificationCenter
        self.loadManagers = loadManagers
        observer = notificationCenter.addObserver(forName: .NEVPNConfigurationChange, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.invalidate() }
        }
    }

    deinit {
        if let observer { notificationCenter.removeObserver(observer) }
    }

    func load() async throws -> NETunnelProviderManager? {
        if hasLoaded { return manager }
        let task: Task<NETunnelProviderManager?, Error>
        if let loading {
            task = loading
        } else {
            generation += 1
            task = Task { try await loadManagers().first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.providerIdentifier
            } }
            loading = task
        }
        let currentGeneration = generation
        do {
            let loaded = try await task.value
            // A configuration change can arrive while preferences are loading.
            guard generation == currentGeneration else { return try await load() }
            manager = loaded
            hasLoaded = true
            loading = nil
            return loaded
        } catch {
            if generation == currentGeneration { loading = nil }
            throw error
        }
    }

    func store(_ manager: NETunnelProviderManager) {
        invalidate()
        self.manager = manager
        hasLoaded = true
    }

    private func invalidate() {
        generation += 1
        manager = nil
        hasLoaded = false
        loading = nil
    }
}

@MainActor
enum TunnelIPC {
    static func request(_ request: ProviderRequest) async throws -> ProviderResponse {
        RayfishLog.ipc.debug("Sending \(request.action.rawValue, privacy: .public)")
        do {
            guard let manager = try await TunnelManagerCache.shared.load(),
                  let session = manager.connection as? NETunnelProviderSession else {
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
