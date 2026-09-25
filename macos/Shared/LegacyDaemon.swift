import Darwin
import Foundation

/// Resolve the old launchd service's state, never the GUI user's home directory.
struct LegacyDaemon {
    static let label = "com.rayfish.vpn"
    static let plistURL = URL(fileURLWithPath: "/Library/LaunchDaemons/com.rayfish.vpn.plist")
    static let migrationMarker = ".legacy-state-migrated"

    let stateDirectory: URL

    static var isInstalled: Bool {
        FileManager.default.fileExists(atPath: plistURL.path)
    }

    static func discover(at url: URL = plistURL) throws -> LegacyDaemon? {
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch let error as NSError where error.domain == NSCocoaErrorDomain
            && error.code == NSFileReadNoSuchFileError {
            return nil
        }
        guard let plist = try PropertyListSerialization.propertyList(from: data, format: nil)
            as? [String: Any], plist["Label"] as? String == label else {
            throw LegacyMigrationError.invalidService
        }
        let environment = plist["EnvironmentVariables"] as? [String: String] ?? [:]
        let configured = environment["RAYFISH_CONFIG_DIR"] ?? ""
        let directory: URL
        if configured.isEmpty {
            directory = URL(fileURLWithPath: "/var/root/Library/Application Support/rayfish")
        } else {
            let workingDirectory = URL(fileURLWithPath: plist["WorkingDirectory"] as? String ?? "/")
            directory = URL(fileURLWithPath: configured, relativeTo: workingDirectory).standardizedFileURL
        }
        return LegacyDaemon(stateDirectory: directory)
    }

    /// The provider calls this before opening any stores. A failed copy restores
    /// the service; a successful copy leaves launchd disabled across reboots.
    func migrateIfNeeded(
        to destination: URL,
        service: LegacyServiceControlling = LaunchdLegacyService(),
        copy: (URL) throws -> Void
    ) throws {
        let files = FileManager.default
        let imported = files.fileExists(atPath: destination.appendingPathComponent(Self.migrationMarker).path)
        if !imported {
            if files.fileExists(atPath: destination.path),
               !(try files.contentsOfDirectory(atPath: destination.path)).isEmpty {
                throw LegacyMigrationError.existingState
            }
            // Reading rather than fileExists distinguishes protected state from
            // a missing installation. Never start with a new identity on failure.
            let identity = stateDirectory.appendingPathComponent("secret_key")
            let values = try identity.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true else {
                throw LegacyMigrationError.missingIdentity
            }
        }

        let previous = try service.snapshot()
        do {
            try service.stop()
            if !imported {
                try copy(stateDirectory)
            }
        } catch {
            do {
                try service.restore(previous)
            } catch let restoreError {
                throw LegacyMigrationError.recoveryFailed(error, restoreError)
            }
            throw error
        }
    }
}

struct LegacyServiceState {
    let loaded: Bool
    let disabled: Bool
    let processID: pid_t?
}

protocol LegacyServiceControlling {
    func snapshot() throws -> LegacyServiceState
    func stop() throws
    func restore(_ state: LegacyServiceState) throws
}

struct LaunchdLegacyService: LegacyServiceControlling {
    private let target = "system/\(LegacyDaemon.label)"
    let execute: ([String]) throws -> CommandResult

    init(execute: @escaping ([String]) throws -> CommandResult = LaunchdLegacyService.run) {
        self.execute = execute
    }

    func snapshot() throws -> LegacyServiceState {
        let service = try execute(["print", target])
        if service.status != 0 && !service.output.contains("Could not find service") {
            throw LegacyMigrationError.service(service.output)
        }
        let overrides = try checked(["print-disabled", "system"])
        let disabled = overrides.split(separator: "\n").contains {
            $0.contains("\"\(LegacyDaemon.label)\"")
                && ($0.contains("=> true") || $0.contains("=> disabled"))
        }
        let processID = service.output.split(separator: "\n").compactMap { line -> pid_t? in
            let line = line.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("pid = ") else { return nil }
            guard let pid = pid_t(line.dropFirst(6)), pid > 1 else { return nil }
            return pid
        }.first
        return LegacyServiceState(loaded: service.status == 0, disabled: disabled, processID: processID)
    }

    func stop() throws {
        let previous = try snapshot()
        _ = try checked(["disable", target])
        if previous.loaded {
            _ = try checked(["bootout", target])
        }
        // bootout can return before the daemon has closed its stores and DNS.
        let deadline = Date().addingTimeInterval(30)
        while let pid = previous.processID, kill(pid, 0) == 0 || errno != ESRCH {
            guard Date() < deadline else { throw LegacyMigrationError.stopTimedOut }
            Thread.sleep(forTimeInterval: 0.1)
        }
        guard !(try snapshot()).loaded else { throw LegacyMigrationError.stopTimedOut }
    }

    func restore(_ state: LegacyServiceState) throws {
        _ = try checked([state.disabled ? "disable" : "enable", target])
        if state.loaded, !(try snapshot()).loaded {
            // A loaded service can have a disabled override. Temporarily enable
            // it to bootstrap, then restore the original override.
            if state.disabled { _ = try checked(["enable", target]) }
            let bootstrap = Result { try checked(["bootstrap", "system", LegacyDaemon.plistURL.path]) }
            if state.disabled { _ = try checked(["disable", target]) }
            _ = try bootstrap.get()
        }
    }

    struct CommandResult {
        let status: Int32
        let output: String
    }

    private func checked(_ arguments: [String]) throws -> String {
        let result = try execute(arguments)
        guard result.status == 0 else { throw LegacyMigrationError.service(result.output) }
        return result.output
    }

    static func run(_ arguments: [String]) throws -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return CommandResult(status: process.terminationStatus, output: String(decoding: data, as: UTF8.self))
    }
}

enum LegacyMigrationError: LocalizedError {
    case invalidService
    case existingState
    case missingIdentity
    case stopTimedOut
    case service(String)
    case recoveryFailed(Error, Error)

    var errorDescription: String? {
        switch self {
        case .invalidService:
            "The installed Rayfish service configuration is invalid."
        case .existingState:
            "The app already has saved Rayfish data. The old service was left unchanged to avoid replacing your identity."
        case .missingIdentity:
            "The old Rayfish installation has no readable identity to import."
        case .stopTimedOut:
            "The old Rayfish service did not stop. Your data has not been imported."
        case let .service(message):
            "Could not manage the old Rayfish service: \(message.trimmingCharacters(in: .whitespacesAndNewlines))"
        case let .recoveryFailed(migration, recovery):
            "Import failed: \(migration.localizedDescription) Restoring the old service also failed: \(recovery.localizedDescription)"
        }
    }
}
