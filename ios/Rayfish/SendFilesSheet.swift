import SwiftUI
import UniformTypeIdentifiers

/// Pick a peer, then the files to send it. The picked files are copied into
/// the shared container first: the tunnel cannot read the app's sandbox or
/// security-scoped URLs.
struct SendFilesSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    /// Nil offers every peer in every network.
    var peers: [PeerInfo]?
    @State private var target: PeerInfo?
    @State private var picking = false

    var body: some View {
        NavigationStack {
            List {
                if choices.isEmpty {
                    Text("No peers to send to yet.").font(Rf.text()).foregroundStyle(Rf.muted)
                        .listRowBackground(Rf.card)
                }
                ForEach(choices) { peer in
                    Button {
                        target = peer
                        picking = true
                    } label: {
                        HStack(spacing: 10) {
                            Dot(color: peer.state.color)
                            VStack(alignment: .leading, spacing: 2) {
                                RowTitle(peer.displayName)
                                RowSubtitle("\(peer.nodeId.prefix(8)) · \(peer.state)")
                            }
                        }
                    }
                    .listRowBackground(Rf.card)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Rf.sheet)
            .navigationTitle("Send to")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            .fileImporter(isPresented: $picking, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
                guard let target, case .success(let urls) = result, !urls.isEmpty else { return }
                send(urls, to: target)
            }
        }
        .preferredColorScheme(.dark)
        .tint(Rf.rose400)
    }

    /// One row per device, reachable ones first.
    private var choices: [PeerInfo] {
        var seen = Set<String>()
        let all = peers ?? model.snapshot.networks.flatMap(\.peers)
        let rank: [PeerConnState: Int] = [.active: 0, .idle: 1, .offline: 2]
        return all.filter { seen.insert($0.nodeId).inserted }
            .sorted { (rank[$0.state] ?? 3, $0.displayName) < (rank[$1.state] ?? 3, $1.displayName) }
    }

    /// Copying can take a while for a large file, so it runs off the main thread
    /// after the sheet closes.
    private func send(_ urls: [URL], to peer: PeerInfo) {
        dismiss()
        Task {
            do {
                let paths = try await Task.detached(priority: .userInitiated) { try Outbox.stage(urls) }.value
                let noun = paths.count == 1 ? "file" : "\(paths.count) files"
                await model.perform(.sendFiles(paths: paths, peer: peer.nodeId),
                                    success: "Sending \(noun) to \(peer.displayName)")
            } catch {
                model.toast = "Could not read the file: \(error.localizedDescription)"
            }
        }
    }
}

enum Outbox {
    /// Copy picked files where the tunnel can read them.
    static func stage(_ urls: [URL]) throws -> [String] {
        let folder = try AppGroup.outbox().appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return try urls.map { url in
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            let target = FileNames.unique(url.lastPathComponent, in: folder)
            try FileManager.default.copyItem(at: url, to: target)
            return target.path
        }
    }

    /// Drop staged copies a week old. A send still queued that long has been
    /// given up on, and the copies would otherwise pile up.
    static func prune() {
        let manager = FileManager.default
        guard let outbox = try? AppGroup.outbox(),
              let folders = try? manager.contentsOfDirectory(at: outbox, includingPropertiesForKeys: [.creationDateKey]) else { return }
        let cutoff = Date().addingTimeInterval(-7 * 24 * 3600)
        for folder in folders {
            let created = (try? folder.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast
            if created < cutoff { try? manager.removeItem(at: folder) }
        }
    }
}
