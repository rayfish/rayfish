import SwiftUI

enum NetworkAction: String, Identifiable {
    case create = "Create", join = "Join"
    var id: Self { self }
}

/// Form errors belong to this submission, not the controller's status polling.
@MainActor
final class NetworkForm: ObservableObject {
    let action: NetworkAction
    @Published var input = "" { didSet { error = nil } }
    @Published var hostname = "" { didSet { error = nil } }
    @Published private(set) var error: String?
    @Published private(set) var isSubmitting = false
    @Published private(set) var isConnecting = false
    private var isCancelled = false

    init(action: NetworkAction) { self.action = action }

    // Keep this in sync with src/hostname.rs::is_valid_hostname, which the core
    // uses for both network names and hostnames. Empty means automatic here.
    static func nameError(_ name: String) -> String? {
        guard !name.isEmpty else { return nil }
        let bytes = name.utf8
        let valid = bytes.count <= 63 && bytes.first != 45 && bytes.last != 45
            && bytes.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
        return valid ? nil : "Use 1–63 lowercase letters (a–z), digits, or hyphens. No hyphen at either end."
    }

    var networkNameError: String? { action == .create ? Self.nameError(input) : nil }
    var hostnameError: String? { Self.nameError(hostname) }
    var canSubmit: Bool {
        !isCancelled && !isSubmitting && networkNameError == nil && hostnameError == nil
            && (action == .create || !input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
    }
    var canCancel: Bool { !isSubmitting || isConnecting }

    func cancel() {
        guard canCancel else { return }
        isCancelled = true
    }

    func submit(using controller: TunnelController) async -> Bool {
        guard canSubmit, !controller.isLoading else { return false }
        isSubmitting = true
        error = nil
        defer { isSubmitting = false }

        if controller.status == nil {
            isConnecting = true
            await controller.connect()
            isConnecting = false
        }
        // Extension approval can outlive the sheet. Cancelling the form must
        // prevent a create/join request when that connection eventually finishes.
        guard !isCancelled else { return false }
        guard controller.status != nil else {
            error = controller.error ?? "Could not connect to Rayfish. Try again."
            return false
        }

        let requestedHostname = hostname.isEmpty ? nil : hostname
        let succeeded: Bool
        switch action {
        case .create:
            succeeded = await controller.create(name: input.isEmpty ? nil : input, hostname: requestedHostname)
        case .join:
            succeeded = await controller.join(code: input, hostname: requestedHostname)
        }
        if !succeeded {
            error = controller.error ?? "Could not \(action.rawValue.lowercased()) the network. Try again."
        }
        return succeeded
    }
}

struct NetworkSheet: View {
    @ObservedObject var controller: TunnelController
    @StateObject private var form: NetworkForm
    @Environment(\.dismiss) private var dismiss

    init(controller: TunnelController, action: NetworkAction) {
        self.controller = controller
        _form = StateObject(wrappedValue: NetworkForm(action: action))
    }

    private var isBusy: Bool { controller.isLoading || form.isSubmitting }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("\(form.action.rawValue) a network").font(RayfishTheme.heading(18))
            Text(form.action == .create ? "Only people you invite can join." : "Paste the invite code you received.")
                .foregroundColor(RayfishTheme.muted)
            if form.action == .create {
                VStack(alignment: .leading, spacing: 6) {
                    TextField("Network name (optional)", text: $form.input)
                        .accessibilityLabel("Network name (optional)")
                    nameHint(form.networkNameError, fallback: "Leave blank to generate a network name.")
                }.disabled(isBusy)
            } else {
                TextEditor(text: $form.input)
                    .accessibilityLabel("Invite code")
                    .font(RayfishTheme.mono(12)).scrollContentBackground(.hidden)
                    .padding(8).frame(height: 100).background(RayfishTheme.deep)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(RayfishTheme.border))
                    .disabled(isBusy)
            }
            VStack(alignment: .leading, spacing: 6) {
                TextField("This Mac's name (optional)", text: $form.hostname)
                    .accessibilityLabel("This Mac's name (optional)")
                nameHint(form.hostnameError, fallback: "Leave blank to use this Mac's default hostname.")
            }.disabled(isBusy)
            if form.isConnecting, let activity = controller.activity {
                Text(activity).foregroundColor(RayfishTheme.muted).font(RayfishTheme.text(13))
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let error = form.error {
                Text(error).foregroundColor(RayfishTheme.amber).font(RayfishTheme.text(13))
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            HStack {
                if form.isSubmitting { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") {
                    form.cancel()
                    dismiss()
                }.disabled(!form.canCancel)
                Button(form.action.rawValue) {
                    Task {
                        if await form.submit(using: controller) { dismiss() }
                    }
                }.buttonStyle(RayfishButtonStyle(kind: .primary))
                    .disabled(isBusy || !form.canSubmit)
            }
        }.rayfishSheet().frame(width: form.action == .create ? 440 : 460)
            .interactiveDismissDisabled(!form.canCancel)
            .onDisappear { form.cancel() }
    }

    private func nameHint(_ error: String?, fallback: String) -> some View {
        Text(error ?? fallback)
            .foregroundColor(error == nil ? RayfishTheme.muted : RayfishTheme.amber)
            .font(RayfishTheme.text(13))
            .fixedSize(horizontal: false, vertical: true)
    }
}
