import AppKit
import SwiftUI

struct FilesView: View {
    @ObservedObject var controller: TunnelController
    @State private var trustedPeer = ""
    @State private var replacement: FileDestination?
    @State private var showReplaceConfirmation = false

    private struct FileDestination {
        var file: ProviderFile
        var directory: URL
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Files").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)

            let files = controller.status?.files ?? []
            if files.isEmpty {
                EmptyState(
                    title: "No file transfers yet.",
                    description: "Incoming files offered by peers appear here so you can save or decline them."
                )
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(files.enumerated()), id: \.element.id) { index, file in
                        if index > 0 { Rectangle().fill(RayfishTheme.line).frame(height: 1) }
                        let isReceiving = file.state == .transferring
                            || (file.state == .pending && controller.receivingFileIDs.contains(file.transferId))
                        HStack(spacing: 14) {
                            VStack(alignment: .leading, spacing: 5) {
                                Text(file.filename).font(RayfishTheme.heading(14)).foregroundColor(RayfishTheme.ink)
                                Text("From \(file.peer) · \(ByteCountFormatter.string(fromByteCount: Int64(clamping: file.size), countStyle: .file))")
                                    .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.muted)
                                if isReceiving {
                                    let received = ByteCountFormatter.string(fromByteCount: Int64(clamping: file.transferred), countStyle: .file)
                                    let percent = file.size == 0 ? 0 : Int(Double(min(file.transferred, file.size)) / Double(file.size) * 100)
                                    ProgressView(value: Double(file.transferred), total: Double(max(file.size, 1)))
                                        .progressViewStyle(.linear)
                                        .tint(RayfishTheme.accent)
                                        .frame(width: 200)
                                    Text("\(received) received (\(percent)%)")
                                        .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.muted)
                                }
                            }
                            Spacer()
                            if file.state == .pending && !isReceiving {
                                Button("Decline", role: .destructive) { Task { await controller.rejectFile(file) } }
                                    .buttonStyle(RayfishButtonStyle(kind: .danger, size: .compact))
                                Button("Save to folder...") { chooseFolder(for: file) }
                                    .buttonStyle(RayfishButtonStyle(kind: .primary, size: .compact))
                            } else if file.state == .received {
                                RayfishBadge(text: "RECEIVED", tone: .success)
                                if let destination = file.destination {
                                    Button("Show in Finder") {
                                        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: destination)])
                                    }
                                    .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .compact))
                                }
                            }
                        }
                        .padding(16)
                    }
                }
                .rayfishCard()
            }

            VStack(alignment: .leading, spacing: 12) {
                Text("Auto-accept from trusted peers").font(RayfishTheme.heading(15)).foregroundColor(RayfishTheme.ink)
                Text("Files from these exact devices save to your Downloads folder automatically while Rayfish is open.")
                    .font(RayfishTheme.text(13))
                    .foregroundColor(RayfishTheme.muted)
                let trusted = controller.status?.fileAutoAcceptPeers ?? []
                if trusted.isEmpty {
                    Text("No auto-accept peers configured.")
                        .font(RayfishTheme.text(13))
                        .foregroundColor(RayfishTheme.faint)
                }
                ForEach(trusted, id: \.self) { peer in
                    HStack {
                        Text(peerLabel(peer)).font(RayfishTheme.mono(11)).textSelection(.enabled)
                        Spacer()
                        Button("Remove", role: .destructive) {
                            Task { _ = await controller.setFileAutoAccept(peer: peer, allow: false) }
                        }
                        .buttonStyle(RayfishButtonStyle(kind: .danger, size: .compact))
                    }
                }
                HStack(spacing: 8) {
                    TextField("Peer name or identity", text: $trustedPeer)
                        .textFieldStyle(RayfishFieldStyle())
                        .font(RayfishTheme.mono(12))
                    Menu("Choose peer") {
                        ForEach(controller.status?.networks ?? []) { network in
                            ForEach(network.peers.filter { !$0.isOwnDevice }) { peer in
                                Button("\(peer.hostname) (\(network.name))") { trustedPeer = peer.identity ?? peer.ipv6 }
                            }
                        }
                    }
                    Button("Add") {
                        Task {
                            if await controller.setFileAutoAccept(peer: trustedPeer.trimmingCharacters(in: .whitespacesAndNewlines), allow: true) {
                                trustedPeer = ""
                            }
                        }
                    }
                    .buttonStyle(RayfishButtonStyle(kind: .primary))
                    .disabled(trustedPeer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .padding(18)
            .rayfishCard()
            .disabled(controller.status?.fileAutoAcceptPeers == nil)
        }
        .disabled(controller.isLoading)
        .alert("Replace existing file?", isPresented: $showReplaceConfirmation, presenting: replacement) { destination in
            Button("Replace", role: .destructive) {
                Task { await controller.acceptFile(destination.file, directory: destination.directory, replace: true) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { destination in
            Text("\(destination.file.filename) already exists in \(destination.directory.lastPathComponent). Replacing it will overwrite the existing file.")
        }
    }

    private func peerLabel(_ identity: String) -> String {
        controller.status?.networks.flatMap { $0.peers }.first { $0.identity == identity }?.hostname ?? identity
    }

    private func chooseFolder(for file: ProviderFile) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = true
        panel.prompt = "Save here"
        panel.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        panel.begin { response in
            guard response == .OK, let directory = panel.url else { return }
            Task { @MainActor in
                if FileManager.default.fileExists(atPath: directory.appendingPathComponent(file.filename).path) {
                    replacement = FileDestination(file: file, directory: directory)
                    showReplaceConfirmation = true
                    return
                }
                await controller.acceptFile(file, directory: directory)
            }
        }
    }
}
