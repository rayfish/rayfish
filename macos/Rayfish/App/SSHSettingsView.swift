import SwiftUI

struct SSHSettingsView: View {
    @ObservedObject var controller: TunnelController
    @State private var editing: ProviderSSHRule?
    @State private var removing: ProviderSSHRule?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Mesh SSH").font(RayfishTheme.heading(15))
                Spacer()
                Toggle("Mesh SSH", isOn: Binding(
                    get: { controller.status?.sshEnabled ?? false },
                    set: { enabled in Task { await controller.setSetting(.ssh, enabled: enabled) } }
                )).labelsHidden().toggleStyle(.switch)
            }
            Text("Allow trusted Rayfish peers to sign in to this Mac. Access is limited to the networks, peers, and local accounts below.")
                .foregroundColor(RayfishTheme.muted)
            let rules = controller.status?.sshRules ?? []
            if rules.isEmpty {
                Text("No peers have SSH access. Add a rule to allow someone.").foregroundColor(RayfishTheme.faint)
            }
            ForEach(rules) { rule in
                HStack {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("\(peerLabel(rule)) on \(rule.network)").foregroundColor(RayfishTheme.ink)
                        Text(rule.accounts).font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    Button("Edit") { editing = rule }
                    Button("Remove", role: .destructive) { removing = rule }
                }
            }
            Button("Add access rule") {
                editing = ProviderSSHRule(network: controller.status?.networks.first?.name ?? "",
                                          peer: "", users: [NSUserName()])
            }.disabled(controller.status?.networks.isEmpty != false)
            if controller.status == nil {
                Text("Connect to manage SSH access.").foregroundColor(RayfishTheme.faint)
            } else if controller.status?.sshEnabled != true && !rules.isEmpty {
                Text("SSH is off. These rules take effect when you enable it.").foregroundColor(RayfishTheme.faint)
            }
        }
        .padding(18).rayfishCard()
        .disabled(controller.isLoading || controller.status?.sshEnabled == nil)
        .sheet(item: $editing) { rule in SSHRuleEditor(controller: controller, rule: rule) }
        .confirmationDialog("Remove SSH access?", isPresented: Binding(
            get: { removing != nil }, set: { if !$0 { removing = nil } }
        )) {
            Button("Remove access", role: .destructive) {
                if let rule = removing { Task { _ = await controller.setSSHRule(rule, allow: false) } }
                removing = nil
            }
        } message: {
            Text("Other matching rules can still grant access to this peer.")
        }
    }

    private func peerLabel(_ rule: ProviderSSHRule) -> String {
        if rule.peer == "*" { return "All peers" }
        return controller.status?.networks.first { $0.name == rule.network }?.peers
            .first { $0.identity == rule.peer }?.hostname ?? rule.peer
    }
}

private struct SSHRuleEditor: View {
    private enum Accounts: String, CaseIterable {
        case specific = "Specific accounts", nonRoot = "Any account except root", all = "Any account, including root"
    }
    @ObservedObject var controller: TunnelController
    @Environment(\.dismiss) private var dismiss
    private let original: ProviderSSHRule
    @State private var network: String
    @State private var peer: String
    @State private var accounts: Accounts
    @State private var usernames: String

    init(controller: TunnelController, rule: ProviderSSHRule) {
        self.controller = controller
        original = rule
        _network = State(initialValue: rule.network)
        _peer = State(initialValue: rule.peer)
        _accounts = State(initialValue: rule.users.isEmpty ? .nonRoot : (rule.users.contains("*") ? .all : .specific))
        _usernames = State(initialValue: rule.users.filter { $0 != "*" }.joined(separator: ", "))
    }

    private var users: [String] {
        switch accounts {
        case .all: ["*"]
        case .nonRoot: []
        case .specific: usernames.split { $0 == "," || $0.isWhitespace }.map(String.init)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(original.peer.isEmpty ? "Allow SSH access" : "Edit SSH access").font(RayfishTheme.heading(18))
            Picker("Network", selection: $network) {
                ForEach(controller.status?.networks ?? []) { network in Text(network.name).tag(network.name) }
            }.disabled(!original.peer.isEmpty)
            HStack {
                TextField("Peer name, IP, identity, or * for all peers", text: $peer)
                Menu("Choose peer") {
                    Button("All peers on this network") { peer = "*" }
                    ForEach(controller.status?.networks.first { $0.name == network }?.peers ?? []) { item in
                        Button(item.hostname) { peer = item.identity ?? item.ipv6 }
                    }
                }
            }.disabled(!original.peer.isEmpty)
            Picker("Local accounts", selection: $accounts) {
                ForEach(Accounts.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }
            if accounts == .specific {
                TextField("Local usernames, separated by commas", text: $usernames)
            }
            Text("Rules apply to the peer's identity, including its paired devices. An all-peers rule also covers future members of this network.")
                .foregroundColor(RayfishTheme.muted)
            if let error = controller.error { Text(error).foregroundColor(RayfishTheme.amber) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.disabled(controller.isLoading)
                Button("Save") {
                    Task {
                        let rule = ProviderSSHRule(network: network,
                                                   peer: peer.trimmingCharacters(in: .whitespacesAndNewlines), users: users)
                        if await controller.setSSHRule(rule, allow: true) { dismiss() }
                    }
                }.buttonStyle(RayfishButtonStyle(kind: .primary))
                    .disabled(controller.isLoading || network.isEmpty || peer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                              || (accounts == .specific && (users.isEmpty || users.contains("*"))))
            }
        }.rayfishSheet().frame(width: 560).interactiveDismissDisabled(controller.isLoading)
    }
}
