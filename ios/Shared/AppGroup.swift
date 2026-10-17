import Foundation
import OSLog

enum RayfishLog {
    static let app = Logger(subsystem: "xyz.rayfish.ios", category: "app")
    static let tunnel = Logger(subsystem: "xyz.rayfish.ios", category: "tunnel")
    static let ipc = Logger(subsystem: "xyz.rayfish.ios", category: "ipc")
}

/// Storage the app and its packet tunnel share. The node's identity and config
/// live here, so either process can read them while the other one runs.
enum AppGroup {
    static let identifier = "group.xyz.rayfish.ios"
    static let tunnelBundleIdentifier = "xyz.rayfish.ios.tunnel"

    /// The app group container. A build without the app group entitlement (an
    /// unsigned simulator build) gets the app's own Application Support instead,
    /// which only the in-process simulator node uses.
    static func root() throws -> URL {
        let manager = FileManager.default
        if let url = manager.containerURL(forSecurityApplicationGroupIdentifier: identifier) {
            return url
        }
        #if targetEnvironment(simulator)
        return try manager.url(for: .applicationSupportDirectory, in: .userDomainMask,
                               appropriateFor: nil, create: true)
        #else
        throw AppGroupError.unavailable
        #endif
    }

    static func stateDirectory() throws -> URL { try directory("rayfish") }
    /// Copies of files the user picked to send, readable by the tunnel.
    static func outbox() throws -> URL { try directory("Outbox") }
    /// Downloads in progress, one folder per offer.
    static func incoming() throws -> URL { try directory("Incoming") }
    /// Finished downloads, waiting for the app to move them into Documents.
    static func received() throws -> URL { try directory("Received") }

    static var defaults: UserDefaults { UserDefaults(suiteName: identifier) ?? .standard }

    private static func directory(_ name: String) throws -> URL {
        let url = try root().appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}

enum Preferences {
    static let autoAcceptOwnDevicesKey = "autoAcceptOwnDevices"

    static var autoAcceptOwnDevices: Bool {
        get { AppGroup.defaults.bool(forKey: autoAcceptOwnDevicesKey) }
        set { AppGroup.defaults.set(newValue, forKey: autoAcceptOwnDevicesKey) }
    }
}

enum AppGroupError: LocalizedError {
    case unavailable

    var errorDescription: String? { "Rayfish shared storage is unavailable" }
}

/// The core's errors in words for a toast. UniFFI's own description prints
/// the Swift case name.
func userMessage(_ error: Error) -> String {
    guard let error = error as? RayError else { return error.localizedDescription }
    return switch error {
    case .NotStarted: "Turn Rayfish on first"
    case .BadCode(let detail): "That code is not valid: \(detail)"
    case .JoinFailed(let detail): "Could not join: \(detail)"
    case .PairFailed(let detail): "Could not pair: \(detail)"
    case .Network(let detail): detail
    case .BadBackup: "Wrong password, or the backup is damaged"
    case .IdentityExists: "This device already has an identity"
    case .NodeRunning: "Turn Rayfish off first"
    }
}
