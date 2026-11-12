import Foundation

@main
struct FileHandoffTests {
    static func main() async throws {
        let files = FileManager.default
        let root = files.temporaryDirectory.appendingPathComponent("handoff-\(UUID().uuidString)")
        defer { try? files.removeItem(at: root) }
        let downloads = root.appendingPathComponent("Downloads")
        let chosen = root.appendingPathComponent("Chosen")
        let suite = "handoff-tests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let handoff = FileHandoff(root: root.appendingPathComponent("Incoming"), uid: 501,
                                  downloads: downloads, defaults: defaults)
        let incoming = handoff.incoming

        precondition(FileHandoff.numberedName("report.pdf", attempt: 0) == "report.pdf")
        precondition(FileHandoff.numberedName("report.pdf", attempt: 2) == "report (2).pdf")
        precondition(FileHandoff.numberedName(".profile", attempt: 1) == ".profile (1)")
        precondition(FileHandoff.isPartial(".rayfish-0123456789abcdef0123456789abcdef.part"))
        precondition(!FileHandoff.isPartial(".profile"))
        print("PASS: numbered and temporary names match the core")

        // An auto-accepted file goes to Downloads, next to one of the same name.
        let auto = incoming.appendingPathComponent("auto")
        try files.createDirectory(at: auto, withIntermediateDirectories: true)
        try files.createDirectory(at: downloads, withIntermediateDirectories: true)
        try Data("old".utf8).write(to: downloads.appendingPathComponent("photo.jpg"))
        try Data("new".utf8).write(to: auto.appendingPathComponent("photo.jpg"))
        try Data("partial".utf8).write(to: auto.appendingPathComponent(".rayfish-00000000000000000000000000000000.part"))
        var pass = await handoff.deliver()
        precondition(pass.movedAny && pass.errors.isEmpty)
        precondition(try String(contentsOf: downloads.appendingPathComponent("photo (1).jpg"), encoding: .utf8) == "new")
        precondition(files.fileExists(atPath: auto.appendingPathComponent(".rayfish-00000000000000000000000000000000.part").path))
        precondition(files.fileExists(atPath: auto.path))
        print("PASS: auto-accepted files move to Downloads, unfinished ones stay")

        // A manual accept goes to its folder, replacing when asked.
        try files.createDirectory(at: chosen, withIntermediateDirectories: true)
        try Data("old".utf8).write(to: chosen.appendingPathComponent("notes.txt"))
        let staging = await handoff.stagingDirectory(for: chosen, replace: true)
        precondition(staging.deletingLastPathComponent().path == incoming.path)
        try files.createDirectory(at: staging, withIntermediateDirectories: true)
        let staged = staging.appendingPathComponent("notes.txt")
        try Data("new".utf8).write(to: staged)
        pass = await handoff.deliver()
        precondition(try String(contentsOf: chosen.appendingPathComponent("notes.txt"), encoding: .utf8) == "new")
        precondition(!files.fileExists(atPath: staging.path))
        precondition(pass.delivered.last == FileHandoff.Delivered(staged: staged.path,
                                                                  final: chosen.appendingPathComponent("notes.txt").path))
        precondition(handoff.savedDelivered() == pass.delivered)
        precondition(!(await handoff.deliver()).movedAny)
        print("PASS: accepted files move to their folder and their staging directory goes")

        // The app shows a staged file as still arriving, a moved one where it went.
        let status = ProviderStatus(active: true, ipv6: "200::1", networks: [], pendingRequests: [], connectionRequests: [], files: [
            ProviderFile(transferId: 1, peer: "friend", filename: "notes.txt", size: 3, state: .received, destination: staged.path),
            ProviderFile(transferId: 2, peer: "friend", filename: "late.txt", size: 9, state: .received,
                         destination: auto.appendingPathComponent("late.txt").path),
            ProviderFile(transferId: 3, peer: "friend", filename: "cli.txt", size: 1, state: .received, destination: "/path/to/work/cli.txt")
        ])
        let shown = FileHandoff.present(status, delivered: pass.delivered, incoming: incoming)?.files ?? []
        precondition(shown[0].state == .received && shown[0].destination == chosen.appendingPathComponent("notes.txt").path)
        precondition(shown[1].state == .transferring && shown[1].transferred == 9 && shown[1].destination == nil)
        precondition(shown[2] == status.files?[2])
        print("PASS: status shows files where they were moved")
    }
}
