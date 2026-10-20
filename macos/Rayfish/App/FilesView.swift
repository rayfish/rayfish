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
        VStack(alignment: .leading, spacing: 14) {
            Text("Files").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
            VStack(alignment: .leading, spacing: 10) {
                Text("Auto-accept from trusted peers").font(RayfishTheme.heading(15))
                Text("Files from these exact devices save to your Downloads folder or configured download directory without asking.")
                    .foregroundColor(RayfishTheme.muted)
                ForEach(controller.status?.fileAutoAcceptPeers ?? [], id: \.self) { peer in
                    HStack {
                        Text(peerLabel(peer)).font(RayfishTheme.mono(11)).textSelection(.enabled)
                        Spacer()
                        Button("Remove") { Task { _ = await controller.setFileAutoAccept(peer: peer, allow: false) } }
                    }
                }
                HStack {
                    TextField("Peer name or identity", text: $trustedPeer)
                    Menu("Choose peer") {
                        ForEach(controller.status?.networks ?? []) { network in
                            ForEach(network.peers) { peer in
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
                    }.disabled(trustedPeer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                if let error = controller.error { Text(error).foregroundColor(RayfishTheme.amber) }
            }.padding(14).rayfishCard().disabled(controller.status?.fileAutoAcceptPeers == nil)
            let files = controller.status?.files ?? []
            if files.isEmpty {
                Text("Incoming files appear here.").foregroundColor(RayfishTheme.muted)
            }
            ForEach(files) { file in
                let isReceiving = file.state == .transferring
                    || (file.state == .pending && controller.receivingFileIDs.contains(file.transferId))
                HStack(spacing: 14) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(file.filename).foregroundColor(RayfishTheme.ink)
                        Text("From \(file.peer) · \(ByteCountFormatter.string(fromByteCount: Int64(clamping: file.size), countStyle: .file))")
                            .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.muted)
                        if isReceiving {
                            let received = ByteCountFormatter.string(fromByteCount: Int64(clamping: file.transferred), countStyle: .file)
                            let percent = file.size == 0 ? 0 : Int(Double(min(file.transferred, file.size)) / Double(file.size) * 100)
                            ProgressView(value: Double(file.transferred), total: Double(max(file.size, 1)))
                                .progressViewStyle(.linear)
                                .tint(RayfishTheme.accent)
                                .frame(width: 180)
                            Text("\(received) received (\(percent)%)")
                                .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.muted)
                        }
                    }
                    Spacer()
                    if file.state == .pending && !isReceiving {
                        Button("Decline") { Task { await controller.rejectFile(file) } }
                        Button("Save to folder...") { chooseFolder(for: file) }
                            .buttonStyle(RayfishButtonStyle(kind: .primary))
                    } else if file.state == .received {
                        Text("Received").foregroundColor(RayfishTheme.green)
                        if let destination = file.destination {
                            Button("Show in Finder") {
                                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: destination)])
                            }
                        }
                    }
                }.padding(14).rayfishCard()
            }
        }.disabled(controller.isLoading)
            .alert("Replace existing file?", isPresented: $showReplaceConfirmation, presenting: replacement) { destination in
                Button("Replace", role: .destructive) {
                    Task { await controller.acceptFile(destination.file, directory: destination.directory) }
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
