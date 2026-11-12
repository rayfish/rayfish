import Darwin
import Foundation

/// Moves received files from where the network extension saves them to where
/// they belong.
///
/// macOS privacy controls keep the extension, though it runs as root, out of
/// the user's Downloads, Desktop and Documents. It saves every file under
/// `root/<uid>/`, and the app, running as the user, moves each one on: files
/// in `auto/` (auto-accepted) to Downloads, files in an accept's own directory
/// to the folder that accept named. Keep `root` in step with `INCOMING` in
/// `ray-apple/src/handoff.rs`.
actor FileHandoff {
    static let root = URL(fileURLWithPath: "/Library/Application Support/Rayfish/Incoming", isDirectory: true)
    private static let targetsKey = "fileHandoffTargets"
    private static let deliveredKey = "fileHandoffDelivered"
    private static let deliveredLimit = 100

    struct Target: Codable, Equatable {
        var directory: String
        var replace: Bool
    }

    /// A file moved out of the staging directory.
    struct Delivered: Codable, Equatable {
        var staged: String
        var final: String
    }

    struct Pass {
        /// Every file moved so far, newest last.
        var delivered: [Delivered]
        var movedAny: Bool
        /// Files that could not be moved, reported once each.
        var errors: [String]
    }

    nonisolated let incoming: URL
    private let downloads: URL
    // UserDefaults is thread-safe.
    private nonisolated(unsafe) let defaults: UserDefaults
    private var reported: Set<String> = []

    init(root: URL = FileHandoff.root, uid: uid_t = getuid(), downloads: URL? = nil,
         defaults: UserDefaults = .standard) {
        incoming = root.appendingPathComponent(String(uid), isDirectory: true)
        self.downloads = downloads
            ?? FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
        self.defaults = defaults
    }

    /// A new directory for one accept to save into, remembered with the
    /// folder its file goes to.
    func stagingDirectory(for directory: URL, replace: Bool) -> URL {
        let token = UUID().uuidString
        var targets = loadTargets()
        targets[token] = Target(directory: directory.path, replace: replace)
        save(targets, as: Self.targetsKey)
        return incoming.appendingPathComponent(token, isDirectory: true)
    }

    /// Drop a staging directory whose accept failed before anything was saved.
    func forget(_ staging: URL) {
        var targets = loadTargets()
        targets[staging.lastPathComponent] = nil
        save(targets, as: Self.targetsKey)
    }

    nonisolated func savedDelivered() -> [Delivered] {
        load([Delivered].self, from: Self.deliveredKey) ?? []
    }

    /// Move every finished file out of the staging directory.
    func deliver() -> Pass {
        let files = FileManager.default
        var targets = loadTargets()
        var delivered = savedDelivered()
        var movedAny = false
        var errors: [String] = []
        // Paths are built from `incoming` rather than taken from the listing,
        // which resolves links, so they match the destinations the core reports.
        let tokens = (try? files.contentsOfDirectory(atPath: incoming.path)) ?? []
        for token in tokens {
            let directory = incoming.appendingPathComponent(token, isDirectory: true)
            var isDirectory: ObjCBool = false
            guard files.fileExists(atPath: directory.path, isDirectory: &isDirectory), isDirectory.boolValue else { continue }
            let target = targets[token]
            let destination = target.map { URL(fileURLWithPath: $0.directory, isDirectory: true) } ?? downloads
            let names = (try? files.contentsOfDirectory(atPath: directory.path)) ?? []
            var movedHere = false
            for name in names where !Self.isPartial(name) {
                let item = directory.appendingPathComponent(name)
                do {
                    let final = try Self.move(item, into: destination, replace: target?.replace ?? false)
                    delivered.append(Delivered(staged: item.path, final: final.path))
                    movedHere = true
                    reported.remove(item.path)
                } catch {
                    if reported.insert(item.path).inserted {
                        errors.append("Could not move \(item.lastPathComponent) to \(destination.path): \(error.localizedDescription)")
                    }
                }
            }
            movedAny = movedAny || movedHere
            // An accept's directory holds one file. Only remove it once that
            // file is out: an empty one may be a receive about to start.
            if movedHere, token != "auto", ((try? files.contentsOfDirectory(atPath: directory.path)) ?? ["?"]).isEmpty {
                try? files.removeItem(at: directory)
                targets[token] = nil
            }
        }
        if movedAny {
            delivered = Array(delivered.suffix(Self.deliveredLimit))
            save(delivered, as: Self.deliveredKey)
            save(targets, as: Self.targetsKey)
        }
        return Pass(delivered: delivered, movedAny: movedAny, errors: errors)
    }

    /// `status` as the user should see it: a received file still in the
    /// staging directory is not received yet, and one moved out is where it
    /// was moved to.
    nonisolated static func present(_ status: ProviderStatus?, delivered: [Delivered], incoming: URL) -> ProviderStatus? {
        guard var status, let files = status.files else { return status }
        let prefix = incoming.path + "/"
        let moved = Dictionary(delivered.map { ($0.staged, $0.final) }, uniquingKeysWith: { _, last in last })
        status.files = files.map { file in
            guard file.state == .received, let staged = file.destination, staged.hasPrefix(prefix) else { return file }
            var shown = file
            if let final = moved[staged] {
                shown.destination = final
            } else {
                shown.state = .transferring
                shown.transferred = file.size
                shown.destination = nil
            }
            return shown
        }
        return status
    }

    /// The receive's temporary name, `.rayfish-<hex>.part`.
    nonisolated static func isPartial(_ name: String) -> Bool {
        name.hasPrefix(".rayfish-") && name.hasSuffix(".part")
    }

    /// `report.pdf`, then `report (1).pdf`, `report (2).pdf`, as the core
    /// names a file whose name is taken.
    nonisolated static func numberedName(_ name: String, attempt: Int) -> String {
        guard attempt > 0 else { return name }
        if let dot = name.lastIndex(of: "."), dot > name.startIndex {
            return "\(name[..<dot]) (\(attempt))\(name[dot...])"
        }
        return "\(name) (\(attempt))"
    }

    private static func move(_ item: URL, into directory: URL, replace: Bool) throws -> URL {
        let files = FileManager.default
        try files.createDirectory(at: directory, withIntermediateDirectories: true)
        let name = item.lastPathComponent
        let named = directory.appendingPathComponent(name)
        if replace, files.fileExists(atPath: named.path) {
            _ = try files.replaceItemAt(named, withItemAt: item)
            return named
        }
        for attempt in 0..<10_000 {
            let candidate = directory.appendingPathComponent(numberedName(name, attempt: attempt))
            do {
                try files.moveItem(at: item, to: candidate)
                return candidate
            } catch CocoaError.fileWriteFileExists {
                continue
            }
        }
        throw CocoaError(.fileWriteFileExists)
    }

    private func loadTargets() -> [String: Target] {
        load([String: Target].self, from: Self.targetsKey) ?? [:]
    }

    private nonisolated func load<T: Decodable>(_ type: T.Type, from key: String) -> T? {
        defaults.data(forKey: key).flatMap { try? JSONDecoder().decode(type, from: $0) }
    }

    private func save<T: Encodable>(_ value: T, as key: String) {
        if let data = try? JSONEncoder().encode(value) { defaults.set(data, forKey: key) }
    }
}
