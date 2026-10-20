import SwiftUI
import UniformTypeIdentifiers

struct YouView: View {
    @EnvironmentObject private var model: AppModel
    @State private var editingName = false
    @State private var nameInput = ""
    @State private var pairing: SharedCode?
    @State private var scanning = false
    @State private var confirmUnpair = false
    @State private var backingUp = false
    @State private var restoring = false
    @State private var autoAccept = Preferences.autoAcceptOwnDevices
    @State private var crashReporting = Preferences.crashReporting

    private var snapshot: Snapshot { model.snapshot }

    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                BrandHeader(title: "You")
                device
                pairingCard
                settings
                identity
                about
            }
            .padding(20)
        }
        .rayfishPage()
        .statusBarBackdrop()
        .toolbar(.hidden, for: .navigationBar)
        .alert("Device name", isPresented: $editingName) {
            TextField("Device name", text: $nameInput)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Save") {
                let name = nameInput.trimmingCharacters(in: .whitespaces)
                Task { await model.perform(.setDeviceName(name), success: "Device name set") }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Used as your hostname in networks you join from now on, and in the ones you are connected to.")
        }
        .alert("Unpair this device?", isPresented: $confirmUnpair) {
            Button("Unpair", role: .destructive) {
                Task { await model.perform(.unpair, success: "Device unpaired") }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Your other devices stop treating this one as yours.")
        }
        .sheet(item: $pairing) { CodeSheet(code: $0) }
        .sheet(isPresented: $scanning) {
            QRScannerSheet { code in
                scanning = false
                Task { await model.perform(.submitCode(code.trimmingCharacters(in: .whitespacesAndNewlines))) }
            }
        }
        .sheet(isPresented: $backingUp) { BackupSheet() }
        .sheet(isPresented: $restoring) { RestoreSheet(onRestored: { Task { await model.restart() } }) }
    }

    private var device: some View {
        SectionCard {
            SectionLabel("This device")
            HStack {
                Text("Name").font(Rf.text()).foregroundStyle(Rf.muted)
                Spacer()
                LinkButton("\(snapshot.deviceName.isEmpty ? "Set" : snapshot.deviceName) ✎") {
                    nameInput = snapshot.deviceName
                    editingName = true
                }
            }
            .frame(minHeight: 44)
            if !snapshot.nodeId.isEmpty {
                KeyValueRow(key: "Node id", value: String(snapshot.nodeId.prefix(16)) + "…") {
                    model.copy(snapshot.nodeId, toast: "Node id copied")
                }
            }
            if !snapshot.ipv6.isEmpty {
                KeyValueRow(key: "Address", value: snapshot.ipv6) {
                    model.copy(snapshot.ipv6, toast: "Address copied")
                }
            }
        }
    }

    private var pairingCard: some View {
        SectionCard {
            SectionLabel("Your devices")
            Text(snapshot.paired
                 ? "This device is paired. Your devices share networks and trust each other's files."
                 : "Pair with your other devices so they share networks and send files without asking.")
                .font(Rf.text()).foregroundStyle(Rf.muted)
            HStack(spacing: 8) {
                PillButton("Show pairing code") { Task { await showPairing() } }
                PillButton("Scan", outline: true) { scanning = true }
            }
            .padding(.top, 8)
            .disabled(!snapshot.controlPlane)
            if snapshot.paired {
                LinkButton("Unpair this device") { confirmUnpair = true }.padding(.top, 4)
            }
        }
    }

    private var settings: some View {
        SectionCard {
            SectionLabel("Settings")
            Toggle(isOn: $autoAccept) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Accept files from my devices").font(Rf.text()).foregroundStyle(Rf.body)
                    Text("Saves them without asking").font(Rf.text(13)).foregroundStyle(Rf.faint)
                }
            }
            .padding(.vertical, 6)
            .onChange(of: autoAccept) { _, on in Preferences.autoAcceptOwnDevices = on }
            Toggle(isOn: $crashReporting) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Crash reporting").font(Rf.text()).foregroundStyle(Rf.body)
                    Text(crashReporting ? "on · diagnostics" : "off").font(Rf.text(13)).foregroundStyle(Rf.faint)
                }
            }
            .padding(.vertical, 6)
            .onChange(of: crashReporting) { _, on in
                Preferences.crashReporting = on
                Telemetry.apply()
                // The tunnel runs its own client.
                Task { _ = await model.perform(.reloadTelemetry) }
            }
            if crashReporting {
                PillButton("Send diagnostics", outline: true) {
                    Task { _ = await model.perform(.sendDiagnostics) }
                }
                .padding(.top, 8)
            }
            VStack(alignment: .leading, spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("QUIC engine").font(Rf.text()).foregroundStyle(Rf.body)
                    Text("Changing it restarts the tunnel").font(Rf.text(13)).foregroundStyle(Rf.faint)
                }
                Picker("QUIC engine", selection: Binding(
                    get: { snapshot.quicEngine },
                    set: { engine in
                        Task {
                            if await model.perform(.setQuicEngine(engine), success: "Engine saved, restarting") != nil {
                                await model.restart()
                            }
                        }
                    }
                )) {
                    Text("Standalone").tag(QuicEngine.standalone)
                    Text("FQ-CoDel").tag(QuicEngine.fqCodel)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }
            .padding(.top, 12)
        }
        .tint(Rf.rose400)
    }

    private var identity: some View {
        SectionCard {
            SectionLabel("Identity")
            Text("Your identity is the key your networks know you by. It is kept in iCloud Keychain, so a new phone on your Apple ID can restore it. Back it up to move it anywhere else.")
                .font(Rf.text()).foregroundStyle(Rf.muted)
            HStack(spacing: 8) {
                PillButton("Back up") { backingUp = true }
                PillButton("Restore", outline: true) {
                    if model.tunnelState == .off {
                        restoring = true
                    } else {
                        model.toast = "Turn the tunnel off before restoring"
                    }
                }
            }
            .padding(.top, 8)
        }
    }

    private var about: some View {
        SectionCard {
            SectionLabel("About")
            KeyValueRow(key: "Version", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?")
            Link(destination: URL(string: "https://github.com/rayfish/rayfish")!) {
                Text("Source code").font(Rf.text()).foregroundStyle(Rf.rose400)
            }
            .padding(.top, 6)
        }
    }

    private func showPairing() async {
        if let code = await model.perform(.startPairing)?.code {
            pairing = SharedCode(title: "Scan from your other device", code: code)
        }
    }
}

/// A backup is the identity sealed with a password. It is written to a file
/// the user picks, never shown or shared as text.
struct BackupSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var confirm = ""
    @State private var document: BackupDocument?
    @State private var exporting = false
    @State private var working = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                SectionLabel("Back up your identity")
                Text("Choose a password. You need it, and the file, to restore. Nobody can recover a lost password.")
                    .font(Rf.text()).foregroundStyle(Rf.muted)
                RayfishField("Password", text: $password, secure: true)
                RayfishField("Confirm password", text: $confirm, secure: true)
                if !confirm.isEmpty && password != confirm {
                    Text("The passwords do not match").font(Rf.text(13)).foregroundStyle(Rf.rose400)
                }
                PillButton(working ? "Sealing…" : "Save backup") { Task { await seal() } }
                    .disabled(password.count < 8 || password != confirm || working)
                Text("At least 8 characters.").font(Rf.text(13)).foregroundStyle(Rf.faint)
            }
            .padding(20)
        }
        .rayfishPage()
        .presentationDetents([.medium, .large])
        .fileExporter(isPresented: $exporting, document: document, contentType: .plainText,
                      defaultFilename: document?.filename) { result in
            switch result {
            case .success:
                model.toast = "Backup saved"
                dismiss()
            case .failure(let error):
                model.toast = "Could not save the backup: \(error.localizedDescription)"
            }
        }
    }

    private func seal() async {
        working = true
        defer { working = false }
        let node = model.tunnel.local.node
        let password = password
        do {
            // Key derivation is deliberately slow; keep it off the main thread.
            let backup = try await Task.detached { try node.backupIdentity(password: password) }.value
            document = BackupDocument(text: backup.code + "\n", filename: "rayfish-identity-\(backup.publicKey.prefix(8)).txt")
            exporting = true
        } catch {
            model.toast = userMessage(error)
        }
    }
}

struct BackupDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.plainText] }
    var text: String
    var filename = "rayfish-identity.txt"

    init(text: String, filename: String) {
        self.text = text
        self.filename = filename
    }

    init(configuration: ReadConfiguration) throws {
        text = configuration.file.regularFileContents.flatMap { String(data: $0, encoding: .utf8) } ?? ""
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}

/// Restores an identity from a backup file or pasted code. Only while the node
/// is stopped: its endpoint is bound to the current key.
struct RestoreSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    var onRestored: () -> Void = {}
    @State private var code = ""
    @State private var password = ""
    @State private var importing = false
    @State private var existing: String?
    @State private var working = false
    @State private var keychain: [KeychainBackup] = []

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                SectionLabel("Restore an identity")
                Text("Open the backup file, or paste its contents, then enter the backup's password.")
                    .font(Rf.text()).foregroundStyle(Rf.muted)
                HStack(spacing: 8) {
                    PillButton("Open file", outline: true) { importing = true }
                    PillButton("Paste", outline: true) {
                        if let text = UIPasteboard.general.string { code = text.trimmingCharacters(in: .whitespacesAndNewlines) }
                    }
                }
                if !code.isEmpty {
                    Text("Backup loaded · \(code.count) characters").font(Rf.text(13)).foregroundStyle(Rf.emerald)
                }
                RayfishField("Password", text: $password, secure: true)
                PillButton(working ? "Restoring…" : "Restore") { Task { await restore(replace: false) } }
                    .disabled(code.isEmpty || password.isEmpty || working)
                if !keychain.isEmpty {
                    KeychainRestoreCard(backups: keychain) {
                        dismiss()
                        onRestored()
                    }
                    .padding(.top, 14)
                }
            }
            .padding(20)
        }
        .task { keychain = await Task.detached { IdentityKeychain.list() }.value }
        .rayfishPage()
        .presentationDetents([.medium, .large])
        .fileImporter(isPresented: $importing, allowedContentTypes: [.plainText, .data]) { result in
            guard case .success(let url) = result else { return }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            if let text = try? String(contentsOf: url, encoding: .utf8) {
                code = text.trimmingCharacters(in: .whitespacesAndNewlines)
            } else {
                model.toast = "Could not read that file"
            }
        }
        .alert("Replace this identity?", isPresented: Binding(get: { existing != nil }, set: { if !$0 { existing = nil } })) {
            Button("Replace", role: .destructive) { Task { await restore(replace: true) } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This device is \(existing?.prefix(8) ?? "")…. Replacing it drops that identity and every network it joined, unless you backed it up.")
        }
    }

    private func restore(replace: Bool) async {
        working = true
        defer { working = false }
        switch await IdentityRestore.run(model: model, code: code, password: password, replace: replace) {
        case .restored:
            dismiss()
            onRestored()
        case .exists(let key):
            existing = key
        case .failed:
            break
        }
    }
}

enum IdentityRestore {
    enum Outcome { case restored, exists(String), failed }

    /// Restore off the main thread. A different identity already on the device
    /// comes back as `exists`, for the caller to confirm before replacing it.
    @MainActor
    static func run(model: AppModel, code: String, password: String, replace: Bool) async -> Outcome {
        let node = model.tunnel.local.node
        do {
            let key = try await Task.detached {
                try node.restoreIdentity(code: code, password: password, replaceExisting: replace)
            }.value
            model.toast = "Restored \(key.prefix(8))…"
            model.hasIdentity = true
            return .restored
        } catch RayError.IdentityExists(let key) {
            return .exists(key)
        } catch {
            model.toast = userMessage(error)
            return .failed
        }
    }
}

/// Backups found in iCloud Keychain.
struct KeychainRestoreCard: View {
    @EnvironmentObject private var model: AppModel
    var backups: [KeychainBackup]
    var onRestored: () -> Void = {}
    @State private var replacing: KeychainBackup?

    var body: some View {
        SectionCard {
            SectionLabel("In iCloud Keychain")
            VStack(alignment: .leading, spacing: 12) {
                ForEach(backups) { backup in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            RowTitle(backup.deviceName)
                            RowSubtitle("\(backup.publicKey.prefix(8)) · \(backup.saved.formatted(date: .abbreviated, time: .omitted))")
                        }
                        Spacer()
                        LinkButton("Restore") { Task { await restore(backup, replace: false) } }
                    }
                }
            }
            .padding(.top, 10)
        }
        .alert("Replace this identity?", isPresented: Binding(get: { replacing != nil }, set: { if !$0 { replacing = nil } })) {
            Button("Replace", role: .destructive) {
                if let backup = replacing { Task { await restore(backup, replace: true) } }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This device's current identity, and every network it joined, is dropped unless you backed it up.")
        }
    }

    private func restore(_ backup: KeychainBackup, replace: Bool) async {
        switch await IdentityRestore.run(model: model, code: backup.code, password: backup.password, replace: replace) {
        case .restored: onRestored()
        case .exists: replacing = backup
        case .failed: break
        }
    }
}
