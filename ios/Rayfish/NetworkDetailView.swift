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
            // Quietly absent while the node is off, as on Android.
            firewall = try? await model.tunnel.send(.firewall).firewall
        }
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
                if let firewall { firewallCard(firewall, network: network) }
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
            AllowInboundSheet(network: network) { firewall = $0 }
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
                    if let domain { model.copy(domain) }
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
                .disabled(domain == nil)
            }
        }
    }

    private func firewallCard(_ firewall: FirewallStateInfo, network: NetworkDetail) -> some View {
        SectionCard {
            SectionLabel("Firewall")
            HStack {
                Text("Inbound default").font(Rf.text()).foregroundStyle(Rf.muted)
                Spacer()
                LinkButton("\(firewall.defaultInbound) ✎") {
                    let next = firewall.defaultInbound == "deny" ? "allow" : "deny"
                    Task {
                        if let updated = await model.perform(.setDefaultInbound(next), success: "Inbound default: \(next)")?.firewall {
                            self.firewall = updated
                        }
                    }
                }
                .font(Rf.mono(14))
            }
            KeyValueRow(key: "Outbound default", value: firewall.defaultOutbound)
            // Removal takes a rule's position in the node's full list.
            let inbound = firewall.rules.enumerated().filter { $0.element.direction == "in" }
            if inbound.isEmpty {
                Text("No inbound rules").font(Rf.text()).foregroundStyle(Rf.faint).padding(.top, 6)
            }
            ForEach(inbound, id: \.offset) { index, rule in
                HStack {
                    // `allow`, `deny` and the protocol stay in the node's own words,
                    // the ones `ray firewall` prints.
                    Text(rule.port == "*" ? "\(rule.action) \(rule.protocol)" : "\(rule.action) \(rule.protocol):\(rule.port)")
                        .font(Rf.mono(14)).foregroundStyle(Rf.body)
                    Spacer()
                    Text(peerName(rule.peer, in: network)).font(Rf.text(13)).foregroundStyle(Rf.faint)
                    LinkButton("Remove") {
                        Task {
                            if let updated = await model.perform(.removeFirewallRule(index: UInt32(index)), success: "Rule removed")?.firewall {
                                self.firewall = updated
                            }
                        }
                    }
                    .font(Rf.mono(12))
                }
                .padding(.top, 8)
            }
            LinkButton("+ Allow inbound") { addingRule = true }.padding(.top, 4)
        }
    }

    /// The node prints a rule's peer as a short id; name it when a peer matches.
    private func peerName(_ id: String, in network: NetworkDetail) -> String {
        if id == "any" { return "any peer" }
        return network.peers.first { $0.nodeId.hasPrefix(id) && !$0.hostname.isEmpty }?.hostname ?? id
    }
}

struct AllowInboundSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    var network: NetworkDetail
    var updated: (FirewallStateInfo) -> Void
    @State private var peer: String?
    @State private var protocolName = "tcp"
    @State private var port = ""

    var body: some View {
        NavigationStack {
            Form {
                Picker("Peer", selection: $peer) {
                    Text("any peer").tag(String?.none)
                    ForEach(network.peers) { peer in
                        Text("\(peer.displayName) · \(peer.nodeId.prefix(4))").tag(String?.some(peer.nodeId))
                    }
                }
                Picker("Protocol", selection: $protocolName) {
                    ForEach(["tcp", "udp", "icmp", "any"], id: \.self) { Text($0) }
                }
                TextField("Port (blank for any)", text: $port)
                    .keyboardType(.numbersAndPunctuation)
            }
            .scrollContentBackground(.hidden)
            .background(Rf.sheet)
            .font(Rf.text())
            .navigationTitle("Allow inbound")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add rule") {
                        let port = port.trimmingCharacters(in: .whitespaces)
                        Task {
                            let command = Command.allowInbound(network: network.name, protocolName: protocolName,
                                                               port: port.isEmpty ? nil : port, peer: peer)
                            if let firewall = await model.perform(command, success: "Rule added")?.firewall {
                                updated(firewall)
                                dismiss()
                            }
                        }
                    }
                }
            }
        }
        .preferredColorScheme(.dark)
        .tint(Rf.rose400)
        .presentationDetents([.medium])
    }
}
