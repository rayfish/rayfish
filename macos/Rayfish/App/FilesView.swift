import AppKit
import SwiftUI

struct FilesView: View {
    @ObservedObject var controller: TunnelController

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Files").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
            let files = controller.status?.files ?? []
            if files.isEmpty {
                Text("Incoming files appear here.").foregroundColor(RayfishTheme.muted)
            }
            ForEach(files) { file in
                HStack(spacing: 14) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(file.filename).foregroundColor(RayfishTheme.ink)
                        Text("From \(file.peer) · \(ByteCountFormatter.string(fromByteCount: Int64(clamping: file.size), countStyle: .file))")
                            .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    if file.state == .pending {
                        Button("Decline") { Task { await controller.rejectFile(file) } }
                        Button("Save to folder...") { chooseFolder(for: file) }
                            .buttonStyle(RayfishButtonStyle(kind: .primary))
                    } else {
                        Text("Received").foregroundColor(RayfishTheme.green)
                    }
                }.padding(14).rayfishCard()
            }
        }.disabled(controller.isLoading)
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
                    controller.error = "A file named \(file.filename) already exists in this folder. Choose another folder."
                    return
                }
                await controller.acceptFile(file, directory: directory)
            }
        }
    }
}
