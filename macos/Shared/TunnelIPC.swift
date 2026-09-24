import Foundation
import Security
import OSLog

enum RayfishLog {
    static let app = Logger(subsystem: "com.rayfish.app", category: "app")
    static let tunnel = Logger(subsystem: "com.rayfish.app", category: "tunnel")
    static let ipc = Logger(subsystem: "com.rayfish.app", category: "ipc")
}

@objc protocol TunnelMessageService {
    func send(_ data: Data, reply: @escaping (Data?) -> Void)
}

enum TunnelIPC {
    static let serviceName = "group.com.rayfish.app.tunnel"

    static func request(_ request: ProviderRequest) async throws -> ProviderResponse {
        RayfishLog.ipc.debug("Sending \(request.action.rawValue, privacy: .public)")
        do {
            let data = try JSONEncoder().encode(request)
            let response = try JSONDecoder().decode(ProviderResponse.self, from: await send(data))
            guard response.success else { throw TunnelIPCError.provider(response.error ?? "Request rejected") }
            return response
        } catch {
            RayfishLog.ipc.error("\(request.action.rawValue, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            throw error
        }
    }

    static func requirement(for identifier: String) throws -> String {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess,
              let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let team = (info as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String,
              !team.isEmpty,
              team.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) else {
            throw TunnelIPCError.missingSigningIdentity
        }
        return "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and identifier \"\(identifier)\""
    }

    static func send(_ data: Data) async throws -> Data {
        let connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        connection.setCodeSigningRequirement(try requirement(for: "com.rayfish.app.tunnel"))
        return try await send(data, connection: connection)
    }

    static func send(_ data: Data, connection: NSXPCConnection, timeout: TimeInterval = 10) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            let pending = PendingTunnelReply(connection: connection, continuation: continuation)
            connection.remoteObjectInterface = NSXPCInterface(with: TunnelMessageService.self)
            connection.interruptionHandler = { pending.finish(.failure(TunnelIPCError.unavailable)) }
            connection.invalidationHandler = { pending.finish(.failure(TunnelIPCError.unavailable)) }
            connection.resume()
            let timer = DispatchWorkItem { pending.finish(.failure(TunnelIPCError.timedOut)) }
            pending.setTimer(timer)
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timer)
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
                pending.finish(.failure(error))
            }) as? TunnelMessageService else {
                pending.finish(.failure(TunnelIPCError.unavailable))
                return
            }
            proxy.send(data) { response in
                if let response {
                    pending.finish(.success(response))
                } else {
                    pending.finish(.failure(TunnelIPCError.noResponse))
                }
            }
        }
    }
}

private final class PendingTunnelReply: @unchecked Sendable {
    private let lock = NSLock()
    private let connection: NSXPCConnection
    private var continuation: CheckedContinuation<Data, Error>?
    private var timer: DispatchWorkItem?

    init(connection: NSXPCConnection, continuation: CheckedContinuation<Data, Error>) {
        self.connection = connection
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
        connection.invalidationHandler = nil
        connection.interruptionHandler = nil
        connection.invalidate()
        continuation.resume(with: result)
    }
}

final class TunnelMessageListener: NSObject, NSXPCListenerDelegate, TunnelMessageService {
    private let listener: NSXPCListener
    private let clientRequirement: String
    private let handler: (Data, @escaping (Data?) -> Void) -> Void

    init(listener: NSXPCListener, clientRequirement: String,
         handler: @escaping (Data, @escaping (Data?) -> Void) -> Void) {
        self.listener = listener
        self.clientRequirement = clientRequirement
        self.handler = handler
        super.init()
        listener.delegate = self
        listener.resume()
    }

    func invalidate() { listener.invalidate() }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.setCodeSigningRequirement(clientRequirement)
        connection.exportedInterface = NSXPCInterface(with: TunnelMessageService.self)
        connection.exportedObject = self
        connection.resume()
        return true
    }

    func send(_ data: Data, reply: @escaping (Data?) -> Void) {
        // All clients share the provider's request handler, with serialized access.
        DispatchQueue.main.async { self.handler(data, reply) }
    }
}

enum TunnelIPCError: LocalizedError {
    case missingSigningIdentity, unavailable, timedOut, noResponse
    case provider(String)

    var errorDescription: String? {
        switch self {
        case .missingSigningIdentity: "Rayfish's signing identity is unavailable."
        case .unavailable: "The Rayfish tunnel is unavailable. Open Rayfish and connect first."
        case .timedOut: "The Rayfish tunnel request timed out."
        case .noResponse: "The Rayfish tunnel returned no response."
        case .provider(let message): message
        }
    }
}
