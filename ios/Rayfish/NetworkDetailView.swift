import SwiftUI

struct NetworkDetailView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    var name: String
    @State private var firewall: FirewallStateInfo?
    @State private var invite: SharedCode?
    @State private var confirmLeave = false
    @State private var editingHostname = false
    @State private var hostnameInput = ""
    @State private var addingRule = false
    @State private var prefillPeer: String?
    @State private var sending = false

    var body: some View {
        Group {
            if let network = model.snapshot.networks.first(where: { $0.name == name }) {
                content(network)
            } else {
                Color.clear.onAppear { dismiss() }
            }
        }
        .rayfishPage()
        .task(id: name) {
            await loadFirewall()
        }
        .onChange(of: model.snapshot) { _, _ in
            Task { await loadFirewall() }
        }
    }

    private func loadFirewall() async {
        // Quietly absent while the node is off, as on Android.
        firewall = try? await model.tunnel.send(.firewall).firewall
    }

    private func content(_ network: NetworkDetail) -> some View {
        ScrollView {
            VStack(spacing: 12) {
                SectionCard {
                    HStack {
                        Text("Hostname").font(Rf.semibold(14)).foregroundStyle(Rf.heading)
                        Spacer()
                        LinkButton("\(network.hostname.isEmpty ? "Set" : network.hostname) ✎") {
                            hostnameInput = network.hostname
                            editingHostname = true
                        }
                        .font(Rf.mono(14))
                    }
                    if let domain = network.domain {
                        KeyValueRow(key: "Your address", value: domain) { model.copy(domain) }
                    }
                    KeyValueRow(key: "Role", value: network.isCoordinator ? "coordinator" : "member")
                    switch network.state {
                    case .connecting: KeyValueRow(key: "Status", value: "connecting…")
                    case .notConnected: KeyValueRow(key: "Status", value: network.reason ?? "not connected")
                    case .connected: EmptyView()
                    }
                }
                peers(network)
                PillButton("Send files") { sending = true }
                    .disabled(!model.snapshot.controlPlane || network.peers.isEmpty)
                if let firewall {
                    let pendingRules = FirewallRules.pending(forNetwork: network.name, in: firewall)
                    if !pendingRules.isEmpty || network.pendingSuggestions > 0 {
                        suggestionsCard(pendingRules, network: network)
                    }
                    firewallCard(firewall, network: network)
                }
            }
            .padding(20)
        }
        .navigationTitle(network.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            Menu {
                Button("Invite") { Task { invite = await model.invite(name) } }
                Button("Leave network", role: .destructive) { confirmLeave = true }
            } label: {
                Image(systemName: "ellipsis.circle").foregroundStyle(Rf.muted)
            }
        }
        .alert("Leave \(network.name)?", isPresented: $confirmLeave) {
            Button("Leave", role: .destructive) {
                Task {
                    if await model.perform(.leave(network: network.name), success: "Left \(network.name)") != nil {
                        dismiss()
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("You'll lose your address and stop reaching its peers. You can rejoin later with an invite.")
        }
        .alert("Hostname on \(network.name)", isPresented: $editingHostname) {
            TextField("Hostname", text: $hostnameInput)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Save") {
                let hostname = hostnameInput.trimmingCharacters(in: .whitespaces)
                Task { await model.perform(.setHostname(network: network.name, hostname: hostname), success: "Hostname set") }
            }
            Button("Cancel", role: .cancel) {}
        }
        .sheet(item: $invite) { CodeSheet(code: $0) }
        .sheet(isPresented: $addingRule) {
            AddFirewallRuleSheet(initialNetwork: network.name, prefillPeer: prefillPeer) { firewall = $0 }
        }
        .sheet(isPresented: $sending) { SendFilesSheet(peers: network.peers) }
    }

    private func peers(_ network: NetworkDetail) -> some View {
        SectionCard {
            SectionLabel("Peers · \(network.peersOnline) online")
            if network.peers.isEmpty {
                Text("No peers yet").font(Rf.text()).foregroundStyle(Rf.faint)
            }
            ForEach(network.peers) { peer in
                let domain = peer.domain(in: network)
                Button {
                    model.copy(domain ?? peer.ipv6)
                } label: {
                    HStack(spacing: 8) {
                        Dot(color: peer.state.color, size: 6)
                        Text(peer.displayName).font(Rf.text(16)).foregroundStyle(Rf.body)
                        Spacer()
                        Text(peer.nodeId.prefix(8)).font(Rf.mono(12)).foregroundStyle(Rf.faint)
                    }
                    .padding(.top, 9)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .contextMenu {
                    Button("Copy address") {
                        model.copy(domain ?? peer.ipv6, toast: "Address copied")
                    }
                    Button("Add firewall rule") {
                        prefillPeer = peer.nodeId
                        addingRule = true
                    }
                }
            }
        }
    }

    private func suggestionsCard(_ pendingRules: [FirewallRuleInfo], network: NetworkDetail) -> some View {
        let count = max(Int(network.pendingSuggestions), pendingRules.count)
        return SectionCard {
            HStack(spacing: 8) {
                Dot(color: Rf.amber, size: 8)
                SectionLabel("Coordinator suggestions · \(count)").padding(.bottom, -8)
            }
            .padding(.bottom, 8)
            Text("Suggested firewall rules for \(network.name). Review before accepting.")
                .font(Rf.text(13)).foregroundStyle(Rf.muted)
            ForEach(Array(pendingRules.enumerated()), id: \.offset) { offset, rule in
                FirewallRuleRow(
                    item: IndexedFirewallRule(index: UInt32(offset), rule: rule),
                    networks: model.snapshot.networks,
                    scopedNetwork: network.name,
                    onRemove: nil
                )
            }
            HStack(spacing: 12) {
                LinkButton("Accept all", color: Rf.emerald) {
                    Task {
                        if let updated = await model.perform(
                            .acceptFirewallSuggestions(network: network.name),
                            success: "Accepted rules for \(network.name)"
                        )?.firewall {
                            firewall = updated
                        }
                    }
                }
                LinkButton("Dismiss") {
                    Task {
                        if let updated = await model.perform(
                            .denyFirewallSuggestions(network: network.name),
                            success: "Dismissed rules for \(network.name)"
                        )?.firewall {
                            firewall = updated
                        }
                    }
                }
            }
            .padding(.top, 8)
        }
    }

    private func firewallCard(_ firewall: FirewallStateInfo, network: NetworkDetail) -> some View {
        let scopedRules = FirewallRules.forNetwork(network.name, in: firewall)
        let autoAccept = FirewallRules.autoAccept(
            forNetwork: network.name,
            in: firewall,
            fallback: network.autoAcceptFirewall
        )
        return SectionCard {
            SectionLabel("Firewall · \(network.name)")
            if scopedRules.isEmpty {
                Text("No rules specific to \(network.name).")
                    .font(Rf.text(13)).foregroundStyle(Rf.faint).padding(.top, 2)
            } else {
                ForEach(scopedRules) { item in
                    FirewallRuleRow(
                        item: item,
                        networks: model.snapshot.networks,
                        scopedNetwork: network.name,
                        onRemove: {
                            Task {
                                if let updated = await model.perform(
                                    .removeFirewallRule(index: item.index),
                                    success: "Rule removed"
                                )?.firewall {
                                    self.firewall = updated
                                }
                            }
                        }
                    )
                }
            }

            LinkButton("+ Add rule") {
                prefillPeer = nil
                addingRule = true
            }
            .padding(.top, 6)

            Toggle(isOn: Binding(
                get: { autoAccept },
                set: { enabled in
                    Task {
                        if let updated = await model.perform(
                            .setNetworkFirewallAutoAccept(network: network.name, enabled: enabled),
                            success: enabled ? "Auto-accept enabled" : "Auto-accept disabled"
                        )?.firewall {
                            self.firewall = updated
                        }
                    }
                }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Auto-accept suggested rules").font(Rf.text()).foregroundStyle(Rf.body)
                    Text("Apply rules published by \(network.name)'s coordinator automatically")
                        .font(Rf.text(12)).foregroundStyle(Rf.faint)
                }
            }
            .tint(Rf.rose500)
            .padding(.top, 10)

            VStack(alignment: .leading, spacing: 4) {
                Text("General rules also apply · inbound default \(firewall.defaultInbound)")
                    .font(Rf.mono(12)).foregroundStyle(Rf.faint)
                NavigationLink {
                    FirewallView()
                } label: {
                    HStack(spacing: 4) {
                        Text("General firewall rules").font(Rf.semibold(13)).foregroundStyle(Rf.rose400)
                        Image(systemName: "chevron.right").font(.system(size: 11)).foregroundStyle(Rf.rose400)
                    }
                    .padding(.vertical, 4)
                }
                .buttonStyle(.plain)
            }
            .padding(.top, 10)
        }
    }
}
