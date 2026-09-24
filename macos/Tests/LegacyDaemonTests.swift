import Foundation

private enum TestFailure: Error { case expected, assertion(String) }

private func check(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
    if try !condition() { throw TestFailure.assertion(message) }
}

private final class FakeService: LegacyServiceControlling {
    let original = LegacyServiceState(loaded: true, disabled: false, processID: 123)
    var stopped = false
    var restored = false
    var failStop = false
    var failRestore = false

    func snapshot() throws -> LegacyServiceState { original }
    func stop() throws {
        stopped = true
        if failStop { throw TestFailure.expected }
    }
    func restore(_ state: LegacyServiceState) throws {
        try check(state.loaded == original.loaded && state.disabled == original.disabled,
                  "restore must receive the original service state")
        restored = true
        if failRestore { throw TestFailure.expected }
    }
}

@main
private struct LegacyDaemonTests {
    static func main() throws {
        try discoversServiceState()
        try importsAfterStopping()
        try repeatLaunchDoesNotImportAgain()
        try refusesExistingAppData()
        try missingIdentityDoesNotStopService()
        try failedCopyRestoresService()
        try failedStopNeverCopies()
        try reportsRecoveryFailure()
        try stopsAndRestoresLaunchd()
        try stoppedInstallStaysStoppedOnRecovery()
        print("10 macOS migration tests passed")
    }

    static func withFixture(_ test: (URL, URL, URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let source = root.appendingPathComponent("legacy")
        let destination = root.appendingPathComponent("extension")
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try Data("original identity".utf8).write(to: source.appendingPathComponent("secret_key"))
        defer { try? FileManager.default.removeItem(at: root) }
        try test(root, source, destination)
    }

    static func discoversServiceState() throws {
        try withFixture { root, source, _ in
            let plistURL = root.appendingPathComponent("daemon.plist")
            try check(try LegacyDaemon.discover(at: plistURL) == nil, "missing service must not create state")
            func write(_ values: [String: Any]) throws {
                try PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0)
                    .write(to: plistURL)
            }
            try write(["Label": LegacyDaemon.label])
            try check(try LegacyDaemon.discover(at: plistURL)?.stateDirectory.path
                == "/var/root/Library/Application Support/rayfish", "default must use the daemon home")
            try write(["Label": LegacyDaemon.label,
                       "EnvironmentVariables": ["RAYFISH_CONFIG_DIR": source.path]])
            try check(try LegacyDaemon.discover(at: plistURL)?.stateDirectory.path == source.path,
                      "custom launchd state directory must be honored")
            try write(["Label": LegacyDaemon.label, "WorkingDirectory": root.path,
                       "EnvironmentVariables": ["RAYFISH_CONFIG_DIR": "legacy"]])
            try check(try LegacyDaemon.discover(at: plistURL)?.stateDirectory.path == source.path,
                      "relative override must use launchd working directory")
            try write(["Label": LegacyDaemon.label,
                       "EnvironmentVariables": ["RAYFISH_CONFIG_DIR": ""]])
            try check(try LegacyDaemon.discover(at: plistURL)?.stateDirectory.path
                == "/var/root/Library/Application Support/rayfish", "empty override must use the default")
            try write(["Label": "some.other.service"])
            do {
                _ = try LegacyDaemon.discover(at: plistURL)
                throw TestFailure.assertion("wrong service must be rejected")
            } catch LegacyMigrationError.invalidService {}
        }
    }

    static func importsAfterStopping() throws {
        try withFixture { _, source, destination in
            let service = FakeService()
            try LegacyDaemon(stateDirectory: source).migrateIfNeeded(to: destination, service: service) { detected in
                try check(service.stopped, "service must stop before copying")
                try check(detected == source, "copy must receive the detected directory")
                try FileManager.default.copyItem(at: detected, to: destination)
            }
            try check(!service.restored, "successful import must leave old service stopped")
            let original = try Data(contentsOf: source.appendingPathComponent("secret_key"))
            let imported = try Data(contentsOf: destination.appendingPathComponent("secret_key"))
            try check(original == imported, "identity must be copied without changing source")
        }
    }

    static func repeatLaunchDoesNotImportAgain() throws {
        try withFixture { _, source, destination in
            try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
            try Data().write(to: destination.appendingPathComponent(LegacyDaemon.migrationMarker))
            try Data("new app state".utf8).write(to: destination.appendingPathComponent("secret_key"))
            try FileManager.default.removeItem(at: source)
            let service = FakeService()
            try LegacyDaemon(stateDirectory: source).migrateIfNeeded(to: destination, service: service) { _ in
                throw TestFailure.assertion("completed migration must not recopy old state")
            }
            try check(service.stopped, "old service must stay disabled even on repeat connections")
            let identity = try String(contentsOf: destination.appendingPathComponent("secret_key"), encoding: .utf8)
            try check(identity == "new app state", "new app state must survive repeat connections")
        }
    }

    static func refusesExistingAppData() throws {
        try withFixture { _, source, destination in
            try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
            try Data("different identity".utf8).write(to: destination.appendingPathComponent("secret_key"))
            let service = FakeService()
            do {
                try LegacyDaemon(stateDirectory: source).migrateIfNeeded(to: destination, service: service) { _ in
                    throw TestFailure.assertion("existing state must not be overwritten")
                }
                throw TestFailure.assertion("existing state must be reported")
            } catch LegacyMigrationError.existingState {}
            try check(!service.stopped, "existing state must be checked before stopping service")
        }
    }

    static func missingIdentityDoesNotStopService() throws {
        try withFixture { _, source, destination in
            try FileManager.default.removeItem(at: source.appendingPathComponent("secret_key"))
            let service = FakeService()
            do {
                try LegacyDaemon(stateDirectory: source).migrateIfNeeded(to: destination, service: service) { _ in
                    throw TestFailure.assertion("missing identity must not be copied")
                }
                throw TestFailure.assertion("missing identity must be reported")
            } catch is CocoaError {}
            try check(!service.stopped, "missing identity must leave the service alone")
        }
    }

    static func failedCopyRestoresService() throws {
        try withFixture { _, source, destination in
            let service = FakeService()
            do {
                try LegacyDaemon(stateDirectory: source).migrateIfNeeded(to: destination, service: service) { _ in
                    throw TestFailure.expected
                }
                throw TestFailure.assertion("copy failure must propagate")
            } catch TestFailure.expected {}
            try check(service.stopped && service.restored, "failed copy must restore the previous service")
            try check(FileManager.default.fileExists(atPath: source.appendingPathComponent("secret_key").path),
                      "failed copy must retain old identity")
        }
    }

    static func failedStopNeverCopies() throws {
        try withFixture { _, source, destination in
            let service = FakeService()
            service.failStop = true
            do {
                try LegacyDaemon(stateDirectory: source).migrateIfNeeded(to: destination, service: service) { _ in
                    throw TestFailure.assertion("must not copy while the old daemon is running")
                }
                throw TestFailure.assertion("stop failure must propagate")
            } catch TestFailure.expected {}
            try check(service.restored, "failed stop must restore the previous service configuration")
        }
    }

    static func reportsRecoveryFailure() throws {
        try withFixture { _, source, destination in
            let service = FakeService()
            service.failRestore = true
            do {
                try LegacyDaemon(stateDirectory: source).migrateIfNeeded(to: destination, service: service) { _ in
                    throw TestFailure.expected
                }
                throw TestFailure.assertion("recovery failure must propagate")
            } catch LegacyMigrationError.recoveryFailed {}
        }
    }

    static func stopsAndRestoresLaunchd() throws {
        var loaded = true
        var disabled = false
        var commands: [[String]] = []
        let service = LaunchdLegacyService { arguments in
            commands.append(arguments)
            switch arguments.first {
            case "print":
                return .init(status: loaded ? 0 : 113, output: loaded ? "state = waiting" : "Could not find service")
            case "print-disabled":
                return .init(status: 0, output: "\"com.rayfish.vpn\" => \(disabled)")
            case "disable": disabled = true
            case "enable": disabled = false
            case "bootout":
                try check(disabled, "disable launchd before stopping so it cannot restart")
                loaded = false
            case "bootstrap":
                try check(!disabled, "enable launchd before restoring the old service")
                loaded = true
            default: throw TestFailure.assertion("unexpected launchctl command")
            }
            return .init(status: 0, output: "")
        }
        let previous = try service.snapshot()
        try check(previous.loaded && !previous.disabled, "snapshot must preserve launchd state")
        try service.stop()
        try check(!loaded && disabled, "successful stop must disable restart across reboots")
        try service.restore(previous)
        try check(loaded && !disabled, "rollback must restore loaded and enabled state")
        try check(commands.contains(["bootout", "system/com.rayfish.vpn"]), "stop must target only Rayfish")
        try check(commands.contains(["bootstrap", "system", LegacyDaemon.plistURL.path]),
                  "recovery must use the installed service plist")
    }

    static func stoppedInstallStaysStoppedOnRecovery() throws {
        var commands: [[String]] = []
        let service = LaunchdLegacyService { arguments in
            commands.append(arguments)
            if arguments.first == "print" {
                return .init(status: 113, output: "Could not find service")
            }
            return .init(status: 0, output: "\"com.rayfish.vpn\" => disabled")
        }
        let previous = try service.snapshot()
        try service.stop()
        try service.restore(previous)
        try check(previous.disabled && !previous.loaded, "installed but stopped service must be detected")
        try check(!commands.contains(where: { $0.first == "bootstrap" || $0.first == "enable" }),
                  "a previously disabled service must not be started during recovery")
    }
}
