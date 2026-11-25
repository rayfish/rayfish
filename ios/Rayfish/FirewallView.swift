import SwiftUI

struct IndexedFirewallRule: Identifiable, Equatable {
    let index: UInt32
    let rule: FirewallRuleInfo

    var id: String {
        "\(index):\(rule.direction):\(rule.action):\(rule.protocol):\(rule.port):\(rule.peer):\(rule.network)"
    }
}

/// Partitioning and formatting helpers that preserve each rule's exact position
/// in `firewall.rules` so `removeFirewallRule(index:)` always targets the right entry.
enum FirewallRules {
    static func isWildcard(_ value: String) -> Bool {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return normalized.isEmpty || normalized == "*" || normalized == "any"
    }

    static func indexed(_ rules: [FirewallRuleInfo]) -> [IndexedFirewallRule] {
        rules.enumerated().map { index, rule in
            IndexedFirewallRule(index: UInt32(index), rule: rule)
        }
    }

    static func forNetwork(_ name: String, in firewall: FirewallStateInfo) -> [IndexedFirewallRule] {
        indexed(firewall.rules).filter { $0.rule.network == name }
    }

    static func general(in firewall: FirewallStateInfo, activeNetworks: Set<String>) -> [IndexedFirewallRule] {
        indexed(firewall.rules).filter { item in
            isWildcard(item.rule.network) || !activeNetworks.contains(item.rule.network)
        }
    }

    static func pending(forNetwork name: String, in firewall: FirewallStateInfo) -> [FirewallRuleInfo] {
        firewall.networks.first { $0.network == name }?.pendingRules ?? []
    }

    static func autoAccept(forNetwork name: String, in firewall: FirewallStateInfo, fallback: Bool) -> Bool {
        firewall.networks.first { $0.network == name }?.autoAccept ?? fallback
    }

    static func directionLabel(for rule: FirewallRuleInfo) -> String {
        rule.direction == "out" ? "Outbound" : "Inbound"
    }

    static func trafficSummary(for rule: FirewallRuleInfo) -> String {
        let proto = rule.protocol.lowercased()
        switch proto {
        case "any", "*":
            return "all protocols"
        case "icmp":
            return "ICMP"
        default:
            let upper = proto.uppercased()
            if isWildcard(rule.port) || rule.port == "0-65535" {
                return "\(upper) · all ports"
            }
            return "\(upper) · port \(rule.port)"
        }
    }

    static func peerLabel(for selector: String, in networks: [NetworkDetail], scopedNetwork: String? = nil) -> String {
        if isWildcard(selector) {
            return "any peer"
        }
        if selector.hasPrefix("any except ") {
            return selector
        }
        let candidates = scopedNetwork.map { name in networks.filter { $0.name == name } } ?? networks
        for network in candidates {
            for peer in network.peers where !peer.hostname.isEmpty {
                if peer.nodeId == selector || peer.ipv6 == selector
                    || peer.nodeId.hasPrefix(selector) || selector.hasPrefix(peer.nodeId) {
                    return "\(peer.hostname) (\(selector.prefix(8)))"
                }
            }
        }
        for network in networks {
            for peer in network.peers where !peer.hostname.isEmpty {
                if peer.nodeId == selector || peer.ipv6 == selector
                    || peer.nodeId.hasPrefix(selector) || selector.hasPrefix(peer.nodeId) {
                    return "\(peer.hostname) (\(selector.prefix(8)))"
                }
            }
        }
        return selector.count > 12 ? String(selector.prefix(8)) : selector
    }

    static func originTag(for rule: FirewallRuleInfo) -> String? {
        guard let origin = rule.suggestedBy, !origin.isEmpty else { return nil }
        return origin == "ssh" ? "SSH" : "SUGGESTED"
    }
}

struct FirewallView: View {
    @EnvironmentObject private var model: AppModel
    @State private var firewall: FirewallStateInfo?
    @State private var addingRule = false
    @State private var confirmAllowInbound = false
    @State private var confirmDenyOutbound = false

    private var networks: [NetworkDetail] { model.snapshot.networks }
    private var activeNetworkNames: Set<String> { Set(networks.map(\.name)) }

    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                if let firewall {
                    if firewall.disabled {
                        pausedBanner
                    }
                    defaultPostureCard(firewall)
                    generalRulesCard(firewall)
                    perNetworkRulesCard(firewall)
                } else {
                    SectionCard {
                        Text(model.snapshot.controlPlane
                             ? "Loading firewall settings…"
                             : "Start the tunnel to view and manage firewall rules.")
                            .font(Rf.text()).foregroundStyle(Rf.muted)
                        if model.snapshot.controlPlane {
                            LinkButton("Retry") { Task { await reload() } }.padding(.top, 4)
                        }
                    }
                }
            }
            .padding(20)
        }
        .rayfishPage()
        .navigationTitle("Firewall")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.visible, for: .navigationBar)
        .toolbar {
            if firewall != nil {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        addingRule = true
                    } label: {
                        Image(systemName: "plus").foregroundStyle(Rf.rose400)
                    }
                    .accessibilityLabel("Add general rule")
                }
            }
        }
        .task { await reload() }
        .onChange(of: model.snapshot) { _, _ in
            Task { await reload() }
        }
        .alert("Allow inbound traffic by default?", isPresented: $confirmAllowInbound) {
            Button("Allow inbound", role: .destructive) {
                Task { await applyDefaultInbound("allow") }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Allowing inbound traffic by default exposes listening ports on this device to mesh peers unless blocked by a rule.")
        }
        .alert("Deny outbound traffic by default?", isPresented: $confirmDenyOutbound) {
            Button("Deny outbound", role: .destructive) {
                Task { await applyDefaultOutbound("deny") }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Denying outbound traffic by default blocks connections started from this device to mesh peers unless allowed by a rule.")
        }
        .sheet(isPresented: $addingRule) {
            AddFirewallRuleSheet(initialNetwork: nil, prefillPeer: nil) { updated in
                firewall = updated
            }
        }
    }

    private var pausedBanner: some View {
        SectionCard {
            HStack(spacing: 12) {
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: 18))
                    .foregroundStyle(Rf.amber)
                VStack(alignment: .leading, spacing: 2) {
                    RowTitle("Mesh firewall is paused")
                    RowSubtitle("All mesh traffic is allowed regardless of rules or defaults.")
                }
                Spacer(minLength: 8)
                LinkButton("Resume", color: Rf.amber) {
                    Task {
                        if let updated = await model.perform(.setFirewallEnabled(true), success: "Firewall resumed")?.firewall {
                            firewall = updated
                        }
                    }
                }
            }
        }
    }

    private func defaultPostureCard(_ firewall: FirewallStateInfo) -> some View {
        SectionCard {
            SectionLabel("Default posture")
            Text("Return traffic for connections started from this device is allowed automatically.")
                .font(Rf.text(13)).foregroundStyle(Rf.muted)
                .padding(.bottom, 6)

            Toggle(isOn: Binding(
                get: { !firewall.disabled },
                set: { enabled in
                    Task {
                        if let updated = await model.perform(
                            .setFirewallEnabled(enabled),
                            success: enabled ? "Firewall enabled" : "Firewall paused"
                        )?.firewall {
                            self.firewall = updated
                        }
                    }
                }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Enforce mesh firewall").font(Rf.text()).foregroundStyle(Rf.body)
                    Text("Evaluate rules and defaults on mesh packets").font(Rf.text(13)).foregroundStyle(Rf.faint)
                }
            }
            .tint(Rf.rose500)
            .padding(.vertical, 6)

            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Inbound default").font(Rf.text()).foregroundStyle(Rf.body)
                    Text("Incoming traffic when no rule matches").font(Rf.text(13)).foregroundStyle(Rf.faint)
                }
                Spacer()
                LinkButton("\(firewall.defaultInbound) ✎") {
                    if firewall.defaultInbound == "deny" {
                        confirmAllowInbound = true
                    } else {
                        Task { await applyDefaultInbound("deny") }
                    }
                }
                .font(Rf.mono(14))
            }
            .padding(.vertical, 6)

            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Outbound default").font(Rf.text()).foregroundStyle(Rf.body)
                    Text("Outgoing traffic when no rule matches").font(Rf.text(13)).foregroundStyle(Rf.faint)
                }
                Spacer()
                LinkButton("\(firewall.defaultOutbound) ✎") {
                    if firewall.defaultOutbound == "allow" {
                        confirmDenyOutbound = true
                    } else {
                        Task { await applyDefaultOutbound("allow") }
                    }
                }
                .font(Rf.mono(14))
            }
            .padding(.vertical, 6)

            Toggle(isOn: Binding(
                get: { firewall.reject },
                set: { reject in
                    Task {
                        if let updated = await model.perform(
                            .setFirewallReject(reject),
                            success: reject ? "Rejecting blocked traffic" : "Dropping blocked traffic silently"
                        )?.firewall {
                            self.firewall = updated
                        }
                    }
                }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Reject blocked traffic").font(Rf.text()).foregroundStyle(Rf.body)
                    Text("Send TCP reset or ICMP unreachable instead of silent drop")
                        .font(Rf.text(13)).foregroundStyle(Rf.faint)
                }
            }
            .tint(Rf.rose500)
            .padding(.top, 6)
        }
    }

    private func generalRulesCard(_ firewall: FirewallStateInfo) -> some View {
        let general = FirewallRules.general(in: firewall, activeNetworks: activeNetworkNames)
        return SectionCard {
            SectionLabel("General rules")
            Text("Cross-network rules evaluated in order, first match wins.")
                .font(Rf.text(13)).foregroundStyle(Rf.muted)
            if general.isEmpty {
                Text("No general rules. Unmatched traffic uses your default posture above.")
                    .font(Rf.text(13)).foregroundStyle(Rf.faint)
                    .padding(.top, 8)
            } else {
                ForEach(general) { item in
                    FirewallRuleRow(
                        item: item,
                        networks: networks,
                        scopedNetwork: nil,
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
            LinkButton("+ Add general rule") {
                addingRule = true
            }
            .padding(.top, 8)
        }
    }

    private func perNetworkRulesCard(_ firewall: FirewallStateInfo) -> some View {
        SectionCard {
            SectionLabel("Per-network rules")
            if networks.isEmpty {
                Text("No networks joined yet. Per-network rules appear once you join or create a network.")
                    .font(Rf.text(13)).foregroundStyle(Rf.faint)
            } else {
                ForEach(networks) { network in
                    let ruleCount = FirewallRules.forNetwork(network.name, in: firewall).count
                    let pendingCount = max(
                        Int(network.pendingSuggestions),
                        FirewallRules.pending(forNetwork: network.name, in: firewall).count
                    )
                    NavigationLink {
                        NetworkDetailView(name: network.name)
                    } label: {
                        HStack(spacing: 10) {
                            VStack(alignment: .leading, spacing: 2) {
                                RowTitle(network.name)
                                RowSubtitle("\(ruleCount) rule\(ruleCount == 1 ? "" : "s") · \(network.peers.count) peer\(network.peers.count == 1 ? "" : "s")")
                            }
                            Spacer()
                            if pendingCount > 0 {
                                HStack(spacing: 4) {
                                    Dot(color: Rf.amber, size: 6)
                                    Text("\(pendingCount) suggested")
                                        .font(Rf.mono(11))
                                        .foregroundStyle(Rf.amber)
                                }
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3)
                                .background(Rf.amber.opacity(0.12))
                                .clipShape(Capsule())
                            }
                            Image(systemName: "chevron.right")
                                .font(.system(size: 13))
                                .foregroundStyle(Rf.faint)
                        }
                        .padding(.vertical, 8)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private func reload() async {
        firewall = try? await model.tunnel.send(.firewall).firewall
    }

    private func applyDefaultInbound(_ action: String) async {
        if let updated = await model.perform(.setDefaultInbound(action), success: "Inbound default: \(action)")?.firewall {
            firewall = updated
        }
    }

    private func applyDefaultOutbound(_ action: String) async {
        if let updated = await model.perform(.setDefaultOutbound(action), success: "Outbound default: \(action)")?.firewall {
            firewall = updated
        }
    }
}

struct FirewallRuleRow: View {
    let item: IndexedFirewallRule
    let networks: [NetworkDetail]
    let scopedNetwork: String?
    var onRemove: (() -> Void)?

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            FirewallActionPill(action: item.rule.action)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(FirewallRules.directionLabel(for: item.rule))
                        .font(Rf.semibold(13))
                        .foregroundStyle(Rf.heading)
                    Text(FirewallRules.trafficSummary(for: item.rule))
                        .font(Rf.mono(12))
                        .foregroundStyle(Rf.body)
                    if let tag = FirewallRules.originTag(for: item.rule) {
                        Text(tag)
                            .font(Rf.mono(10))
                            .foregroundStyle(Rf.muted)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Rf.cardBorder.opacity(0.35))
                            .clipShape(Capsule())
                    }
                }
                HStack(spacing: 6) {
                    Text(FirewallRules.peerLabel(for: item.rule.peer, in: networks, scopedNetwork: scopedNetwork))
                        .font(Rf.text(12))
                        .foregroundStyle(Rf.faint)
                    if scopedNetwork == nil && !FirewallRules.isWildcard(item.rule.network) {
                        Text("· \(item.rule.network) (inactive)")
                            .font(Rf.mono(11))
                            .foregroundStyle(Rf.amber)
                    }
                }
            }

            Spacer(minLength: 4)

            if let onRemove {
                if item.rule.suggestedBy == "ssh" {
                    Text("Managed by SSH")
                        .font(Rf.mono(11))
                        .foregroundStyle(Rf.faint)
                } else {
                    LinkButton("Remove", action: onRemove)
                        .font(Rf.mono(12))
                }
            }
        }
        .padding(.top, 10)
    }
}

struct FirewallActionPill: View {
    let action: String

    private var isAllow: Bool { action.lowercased() == "allow" }

    var body: some View {
        let color = isAllow ? Rf.emerald : Rf.rose400
        Text(action.uppercased())
            .font(Rf.mono(11))
            .foregroundStyle(color)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.14))
            .clipShape(Capsule())
            .overlay(Capsule().stroke(color.opacity(0.35)))
    }
}

struct AddFirewallRuleSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    var initialNetwork: String?
    var prefillPeer: String?
    var updated: (FirewallStateInfo) -> Void

    @State private var selectedNetwork: String
    @State private var action = "allow"
    @State private var direction = "in"
    @State private var protocolName = "tcp"
    @State private var port = ""
    @State private var selectedPeer: String

    init(initialNetwork: String? = nil, prefillPeer: String? = nil, updated: @escaping (FirewallStateInfo) -> Void) {
        self.initialNetwork = initialNetwork
        self.prefillPeer = prefillPeer
        self.updated = updated
        _selectedNetwork = State(initialValue: initialNetwork ?? "")
        _selectedPeer = State(initialValue: prefillPeer ?? "")
    }

    private struct PeerOption: Identifiable {
        let id: String
        let label: String
    }

    private var usesPorts: Bool {
        protocolName == "tcp" || protocolName == "udp"
    }

    private var peerOptions: [PeerOption] {
        peerOptions(forNetwork: selectedNetwork)
    }

    private func peerOptions(forNetwork scope: String) -> [PeerOption] {
        var labelsByNodeId: [String: Set<String>] = [:]
        for network in model.snapshot.networks {
            if !scope.isEmpty && network.name != scope { continue }
            for peer in network.peers {
                let label = scope.isEmpty
                    ? "\(peer.displayName) · \(network.name)"
                    : peer.displayName
                labelsByNodeId[peer.nodeId, default: []].insert(label)
            }
        }
        var options = labelsByNodeId.keys.sorted().compactMap { nodeId -> PeerOption? in
            guard let names = labelsByNodeId[nodeId] else { return nil }
            return PeerOption(id: nodeId, label: "\(names.sorted().joined(separator: ", ")) · \(nodeId.prefix(4))")
        }
        if !selectedPeer.isEmpty && !options.contains(where: { $0.id == selectedPeer }) {
            options.append(PeerOption(id: selectedPeer, label: String(selectedPeer.prefix(8))))
        }
        return [PeerOption(id: "", label: "any peer")] + options
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Quick presets") {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            presetButton("Web 80, 443") {
                                direction = "in"; action = "allow"; protocolName = "tcp"; port = "80,443"
                            }
                            presetButton("SSH 22") {
                                direction = "in"; action = "allow"; protocolName = "tcp"; port = "22"
                            }
                            presetButton("All TCP") {
                                direction = "in"; action = "allow"; protocolName = "tcp"; port = ""
                            }
                            presetButton("Block peer") {
                                direction = "in"; action = "deny"; protocolName = "any"; port = ""
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }

                Section("Rule") {
                    Picker("Scope", selection: Binding(
                        get: { selectedNetwork },
                        set: { next in
                            selectedNetwork = next
                            if !peerOptions(forNetwork: next).contains(where: { $0.id == selectedPeer }) {
                                selectedPeer = ""
                            }
                        }
                    )) {
                        Text("All networks (general)").tag("")
                        ForEach(model.snapshot.networks) { network in
                            Text(network.name).tag(network.name)
                        }
                    }

                    Picker("Action", selection: $action) {
                        Text("allow").tag("allow")
                        Text("deny").tag("deny")
                    }

                    Picker("Direction", selection: $direction) {
                        Text("in (inbound)").tag("in")
                        Text("out (outbound)").tag("out")
                    }

                    Picker("Protocol", selection: $protocolName) {
                        ForEach(["tcp", "udp", "icmp", "any"], id: \.self) { proto in
                            Text(proto).tag(proto)
                        }
                    }

                    if usesPorts {
                        TextField("Port (blank for any, or 22, 80,443, 8000-9000)", text: $port)
                            .keyboardType(.numbersAndPunctuation)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }

                    Picker("Peer", selection: $selectedPeer) {
                        ForEach(peerOptions) { option in
                            Text(option.label).tag(option.id)
                        }
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(Rf.sheet)
            .font(Rf.text())
            .navigationTitle(selectedNetwork.isEmpty ? "Add general rule" : "Add rule for \(selectedNetwork)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add rule") {
                        let trimmedPort = usesPorts ? port.trimmingCharacters(in: .whitespacesAndNewlines) : ""
                        let portArg = trimmedPort.isEmpty ? nil : trimmedPort
                        let peerArg = selectedPeer.isEmpty ? nil : selectedPeer
                        let networkArg = selectedNetwork.isEmpty ? nil : selectedNetwork
                        Task {
                            let command = Command.addFirewallRule(
                                direction: direction,
                                action: action,
                                protocolName: protocolName,
                                port: portArg,
                                peer: peerArg,
                                network: networkArg
                            )
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
        .presentationDetents([.medium, .large])
    }

    private func presetButton(_ title: String, apply: @escaping () -> Void) -> some View {
        Button(title, action: apply)
            .font(Rf.semibold(13))
            .padding(.vertical, 6)
            .buttonStyle(PillStyle(outline: true))
    }
}
