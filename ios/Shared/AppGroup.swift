import Foundation
import OSLog

enum RayfishLog {
    static let app = Logger(subsystem: "xyz.rayfish.ios", category: "app")
    static let tunnel = Logger(subsystem: "xyz.rayfish.ios", category: "tunnel")
}

/// Storage the app and its packet tunnel share. The node's identity and config
/// live here, so either process can read them while the other one runs.
enum AppGroup {
    static let identifier = "group.xyz.rayfish.ios"

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

    /// On unless the user turned it off.
    static var crashReporting: Bool {
        get { AppGroup.defaults.object(forKey: "crashReporting") as? Bool ?? true }
        set { AppGroup.defaults.set(newValue, forKey: "crashReporting") }
    }

    /// A random id that ties one install's reports together and nothing else.
    static var installId: String {
        if let id = AppGroup.defaults.string(forKey: "installId") { return id }
        let id = UUID().uuidString.lowercased()
        AppGroup.defaults.set(id, forKey: "installId")
        return id
    }
}

enum AppGroupError: LocalizedError {
    case unavailable

    var errorDescription: String? { "Rayfish shared storage is unavailable" }
}

/// The core's error message, capitalized to stand alone in a toast.
func userMessage(_ error: Error) -> String {
    guard let error = error as? RayError else { return error.localizedDescription }
    return errorMessage(error: error)
}

func formatSize(_ bytes: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(clamping: bytes), countStyle: .file)
}
