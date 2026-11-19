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
        print("PASS: numbered names match the core")

        // An auto-accepted file goes to Downloads, next to one of the same name.
        let auto = incoming.appendingPathComponent("auto")
        let first = auto.appendingPathComponent(".rayfish-11111111111111111111111111111111.part")
        let unfinished = auto.appendingPathComponent(".rayfish-00000000000000000000000000000000.part")
        try files.createDirectory(at: first, withIntermediateDirectories: true)
        try files.createDirectory(at: unfinished, withIntermediateDirectories: true)
        try files.createDirectory(at: downloads, withIntermediateDirectories: true)
        try Data("old".utf8).write(to: downloads.appendingPathComponent("photo.jpg"))
        let firstFile = first.appendingPathComponent("photo.jpg")
        let partial = unfinished.appendingPathComponent(unfinished.lastPathComponent)
        try Data("new".utf8).write(to: firstFile)
        try Data("partial".utf8).write(to: partial)
        var pass = await handoff.deliver()
        precondition(pass.movedAny && pass.errors.isEmpty)
        let renamed = try String(contentsOf: downloads.appendingPathComponent("photo (1).jpg"), encoding: .utf8)
        precondition(renamed == "new")
        precondition(files.fileExists(atPath: partial.path))
        precondition(!files.fileExists(atPath: first.path))
        precondition(files.fileExists(atPath: auto.path))
        print("PASS: auto-accepted files move to Downloads, unfinished ones stay")

        // A manual accept goes to its folder, replacing when asked.
        try files.createDirectory(at: chosen, withIntermediateDirectories: true)
        try Data("old".utf8).write(to: chosen.appendingPathComponent("notes.txt"))
        let staging = await handoff.stagingDirectory(for: chosen, replace: true)
        precondition(staging.deletingLastPathComponent().path == incoming.path)
        let manual = staging.appendingPathComponent(".rayfish-22222222222222222222222222222222.part")
        try files.createDirectory(at: manual, withIntermediateDirectories: true)
        let staged = manual.appendingPathComponent("notes.txt")
        try Data("new".utf8).write(to: staged)
        pass = await handoff.deliver()
        let replaced = try String(contentsOf: chosen.appendingPathComponent("notes.txt"), encoding: .utf8)
        precondition(replaced == "new")
        precondition(!files.fileExists(atPath: staging.path))
        precondition(pass.delivered.last == FileHandoff.Delivered(staged: staged.path,
                                                                  final: chosen.appendingPathComponent("notes.txt").path))
        precondition(handoff.savedDelivered() == pass.delivered)
        let again = await handoff.deliver()
        precondition(!again.movedAny)
        print("PASS: accepted files move to their folder and their staging directory goes")

        // The app shows a staged file as still arriving, a moved one where it went.
        let status = ProviderStatus(active: true, ipv6: "200::1", networks: [], pendingRequests: [], connectionRequests: [], files: [
            ProviderFile(transferId: 1, peer: "friend", filename: "notes.txt", size: 3, state: .received, destination: staged.path),
            ProviderFile(transferId: 2, peer: "friend", filename: "late.txt", size: 9, state: .received,
                         destination: unfinished.appendingPathComponent("late.txt").path),
            ProviderFile(transferId: 3, peer: "friend", filename: "cli.txt", size: 1, state: .received, destination: "/path/to/work/cli.txt")
        ])
        let shown = FileHandoff.present(status, delivered: pass.delivered, incoming: incoming)?.files ?? []
        precondition(shown[0].state == .received && shown[0].destination == chosen.appendingPathComponent("notes.txt").path)
        precondition(shown[1].state == .transferring && shown[1].transferred == 9 && shown[1].destination == nil)
        precondition(shown[2] == status.files?[2])
        print("PASS: status shows files where they were moved")

        // A second auto-accept with the same filename gets its own receipt.
        let second = auto.appendingPathComponent(".rayfish-33333333333333333333333333333333.part")
        try files.createDirectory(at: second, withIntermediateDirectories: true)
        let secondFile = second.appendingPathComponent("photo.jpg")
        try Data("another".utf8).write(to: secondFile)
        var repeated = status
        repeated.files = [
            ProviderFile(transferId: 4, peer: "friend", filename: "photo.jpg", size: 3, state: .received, destination: firstFile.path),
            ProviderFile(transferId: 5, peer: "friend", filename: "photo.jpg", size: 7, state: .received, destination: secondFile.path)
        ]
        let before = FileHandoff.present(repeated, delivered: pass.delivered, incoming: incoming)?.files
        precondition(before?[0].destination == downloads.appendingPathComponent("photo (1).jpg").path)
        precondition(before?[1].state == .transferring)
        pass = await handoff.deliver()
        let after = FileHandoff.present(repeated, delivered: pass.delivered, incoming: incoming)?.files
        precondition(after?[0].destination == before?[0].destination)
        precondition(after?[1].destination == downloads.appendingPathComponent("photo (2).jpg").path)
        print("PASS: repeated filenames keep separate deliveries")

        for name in [".rayfish-preview.part", unfinished.lastPathComponent] {
            let complete = auto.appendingPathComponent(".rayfish-44444444444444444444444444444444.part")
            try files.createDirectory(at: complete, withIntermediateDirectories: true)
            try Data("complete".utf8).write(to: complete.appendingPathComponent(name))
            let delivery = await handoff.deliver()
            precondition(delivery.movedAny && delivery.errors.isEmpty)
            precondition(files.fileExists(atPath: downloads.appendingPathComponent(name).path))
            precondition(files.fileExists(atPath: partial.path))
        }
        print("PASS: completed files with temporary-looking names are delivered")
    }
}
