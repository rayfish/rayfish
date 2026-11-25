import SwiftUI

enum FirewallScope: Hashable {
    case general
    case network(String)
}

struct IndexedFirewallRule: Identifiable, Equatable {
    let index: UInt32
    let rule: ProviderFirewallRule

    var id: String { "\(index):\(rule.id)" }
}

struct FirewallPeerOption: Identifiable, Equatable {
    let id: String
    let label: String
}

/// Pure helpers for partitioning and formatting firewall state so per-network
/// and general views stay consistent and keep exact daemon rule indices.
enum FirewallModel {
    static func isWildcard(_ value: String) -> Bool {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return normalized.isEmpty || normalized == "*" || normalized == "any"
    }

    static func canonicalPeerSelector(
        _ rawPeer: String,
        forNetwork selectedNetwork: String,
        in networks: [ProviderNetwork]
    ) -> String {
        let trimmed = rawPeer.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !isWildcard(trimmed) else { return "" }
        let candidateNetworks = selectedNetwork.isEmpty ? networks : networks.filter { $0.name == selectedNetwork }
        for net in candidateNetworks {
            for item in net.peers where !item.isOwnDevice {
                let canonical = item.identity ?? item.ipv6
                if canonical == trimmed || item.ipv6 == trimmed || item.hostname == trimmed {
                    return canonical
                }
                if let identity = item.identity, identity.hasPrefix(trimmed) || trimmed.hasPrefix(identity) {
                    return canonical
                }
            }
        }
        return trimmed
    }

    static func peerOptions(
        forNetwork selectedNetwork: String,
        in networks: [ProviderNetwork],
        selectedPeer: String = ""
    ) -> [FirewallPeerOption] {
        var labelsByIdentity: [String: Set<String>] = [:]
        for net in networks {
            if !selectedNetwork.isEmpty && net.name != selectedNetwork { continue }
            for item in net.peers where !item.isOwnDevice {
                let identity = item.identity ?? item.ipv6
                let name = item.hostname.isEmpty ? item.ipv6 : item.hostname
                let label = selectedNetwork.isEmpty ? "\(name) · \(net.name)" : name
                labelsByIdentity[identity, default: []].insert(label)
            }
        }
        var peers = labelsByIdentity.keys.sorted().compactMap { identity -> FirewallPeerOption? in
            guard let labels = labelsByIdentity[identity] else { return nil }
            return FirewallPeerOption(
                id: identity,
                label: "\(labels.sorted().joined(separator: ", ")) (\(identity.prefix(6)))"
            )
        }
        let trimmedPeer = selectedPeer.trimmingCharacters(in: .whitespacesAndNewlines)
        if !isWildcard(trimmedPeer) && !peers.contains(where: { $0.id == trimmedPeer }) {
            let label = peerLabel(
                for: trimmedPeer,
                in: networks,
                scopedNetwork: selectedNetwork.isEmpty ? nil : selectedNetwork
            )
            peers.append(FirewallPeerOption(id: trimmedPeer, label: label))
        }
        return [FirewallPeerOption(id: "", label: "Any peer")] + peers
    }

    static func indexedRules(_ rules: [ProviderFirewallRule]) -> [IndexedFirewallRule] {
        rules.enumerated().map { index, rule in
            IndexedFirewallRule(index: UInt32(index), rule: rule)
        }
    }

    static func rules(forNetwork name: String, in state: ProviderFirewallState?) -> [IndexedFirewallRule] {
        guard let state else { return [] }
        return indexedRules(state.rules).filter { $0.rule.network == name }
    }

    /// Rules not bound to a currently joined network: global ("any") rules plus
    /// rules referencing a network this Mac is not currently on.
    static func generalRules(in state: ProviderFirewallState?, activeNetworks: Set<String>) -> [IndexedFirewallRule] {
        guard let state else { return [] }
        return indexedRules(state.rules).filter { item in
            isWildcard(item.rule.network) || !activeNetworks.contains(item.rule.network)
        }
    }

    static func pendingRules(forNetwork name: String, in state: ProviderFirewallState?) -> [ProviderFirewallRule] {
        state?.networks.first { $0.network == name }?.pendingRules ?? []
    }

    static func autoAccept(forNetwork name: String, in state: ProviderFirewallState?, fallback: Bool = false) -> Bool {
        state?.networks.first { $0.network == name }?.autoAccept ?? fallback
    }

    static func trafficSummary(for rule: ProviderFirewallRule) -> String {
        let proto = rule.protocolName.lowercased()
        switch proto {
        case "any":
            return "All protocols and ports"
        case "icmp":
            return "ICMP (ping and diagnostics)"
        default:
            let upper = proto.uppercased()
            if isWildcard(rule.port) || rule.port == "0-65535" {
                return "\(upper) · all ports"
            }
            return "\(upper) · port \(rule.port)"
        }
    }

    static func directionLabel(for rule: ProviderFirewallRule) -> String {
        rule.direction == "out" ? "Outbound" : "Inbound"
    }

    static func peerLabel(for peerSelector: String, in networks: [ProviderNetwork], scopedNetwork: String? = nil) -> String {
        if isWildcard(peerSelector) {
            return "Any peer"
        }
        if peerSelector.hasPrefix("any except ") {
            return peerSelector.replacingOccurrences(of: "any except ", with: "Any peer except ")
        }
        let candidateNetworks = scopedNetwork.map { name in networks.filter { $0.name == name } } ?? networks
        for network in candidateNetworks {
            for peer in network.peers where !peer.hostname.isEmpty {
                if peer.identity == peerSelector || peer.ipv6 == peerSelector {
                    return "\(peer.hostname) (\(peerSelector.prefix(8)))"
                }
                if let identity = peer.identity, identity.hasPrefix(peerSelector) || peerSelector.hasPrefix(identity) {
                    return "\(peer.hostname) (\(peerSelector))"
                }
            }
        }
        for network in networks {
            for peer in network.peers where !peer.hostname.isEmpty {
                if let identity = peer.identity, identity.hasPrefix(peerSelector) || peerSelector == identity {
                    return "\(peer.hostname) (\(peerSelector.prefix(8)))"
                }
            }
        }
        return "Peer \(peerSelector)"
    }

    static func originLabel(for rule: ProviderFirewallRule) -> String? {
        guard let origin = rule.suggestedBy, !origin.isEmpty else { return nil }
        if origin == "ssh" { return "MESH SSH" }
        return "SUGGESTED"
    }
}

struct FirewallDraftRule: Identifiable {
    let id = UUID()
    var network: String
    var peer: String = ""
    var lockNetwork: Bool = false
}

struct FirewallPageView: View {
    @ObservedObject var controller: TunnelController
    @State private var networkFilter = ""
    @State private var draftRule: FirewallDraftRule?
    @State private var removingRule: IndexedFirewallRule?
    @State private var pendingDefaultChange: DefaultPolicyChange?

    private struct DefaultPolicyChange: Identifiable {
        let id = UUID()
        let direction: String
        let nextAction: String
    }

    private var networks: [ProviderNetwork] { controller.status?.networks ?? [] }
    private var activeNetworkNames: Set<String> { Set(networks.map(\.name)) }

    private var filteredNetworks: [ProviderNetwork] {
        let query = networkFilter.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !query.isEmpty else { return networks }
        return networks.filter { $0.name.lowercased().contains(query) || $0.hostname.lowercased().contains(query) }
    }

    private var generalRules: [IndexedFirewallRule] {
        FirewallModel.generalRules(in: controller.firewall, activeNetworks: activeNetworkNames)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            topBar
            if !controller.isConnected {
                EmptyState(
                    title: "Connect to view and manage firewall rules.",
                    description: "Your saved per-network and general rules take effect automatically when connected."
                )
            } else {
                HStack(alignment: .top, spacing: 18) {
                    scopeSidebar
                        .frame(width: 228)
                    detailPane
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .task {
            if controller.isConnected && controller.firewall == nil {
                await controller.loadFirewall()
            }
            if case let .network(name) = controller.firewallScope,
               controller.status != nil,
               !activeNetworkNames.contains(name) {
                controller.firewallScope = .general
            }
        }
        .sheet(item: $draftRule) { draft in
            AddFirewallRuleSheet(controller: controller, draft: draft)
        }
        .confirmationDialog(
            "Remove firewall rule?",
            isPresented: Binding(get: { removingRule != nil }, set: { if !$0 { removingRule = nil } }),
            presenting: removingRule
        ) { item in
            Button("Remove rule", role: .destructive) {
                Task { await controller.removeFirewallRule(at: item.index) }
                removingRule = nil
            }
        } message: { item in
            Text("\(item.rule.action.capitalized) \(FirewallModel.directionLabel(for: item.rule).lowercased()) \(FirewallModel.trafficSummary(for: item.rule))")
        }
        .confirmationDialog(
            pendingDefaultChange.map { "Set default \($0.direction) policy to \($0.nextAction)?" } ?? "Change default policy?",
            isPresented: Binding(get: { pendingDefaultChange != nil }, set: { if !$0 { pendingDefaultChange = nil } }),
            presenting: pendingDefaultChange
        ) { change in
            Button("Set to \(change.nextAction)", role: change.nextAction == "allow" && change.direction == "inbound" ? .destructive : nil) {
                Task {
                    if change.direction == "inbound" {
                        await controller.setFirewallDefaultInbound(change.nextAction)
                    } else {
                        await controller.setFirewallDefaultOutbound(change.nextAction)
                    }
                }
                pendingDefaultChange = nil
            }
        } message: { change in
            if change.direction == "inbound" && change.nextAction == "allow" {
                Text("Allowing inbound traffic by default exposes listening ports on this Mac to peers unless blocked by a rule.")
            } else if change.direction == "outbound" && change.nextAction == "deny" {
                Text("Denying outbound traffic by default blocks connections started from this Mac to peers unless allowed by a rule.")
            } else {
                Text("Applies to mesh packets when no explicit rule matches.")
            }
        }
    }

    private var topBar: some View {
        HStack(spacing: 12) {
            if controller.firewallReturnToNetworks {
                Button {
                    controller.firewallReturnToNetworks = false
                    controller.page = .networks
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "chevron.left").font(.system(size: 11, weight: .semibold))
                        Text("Networks")
                    }
                }
                .buttonStyle(RayfishButtonStyle(kind: .subtle, size: .compact))
            }
            Text("Firewall").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
            if let firewall = controller.firewall {
                RayfishBadge(
                    text: firewall.disabled ? "PAUSED" : "ENFORCING",
                    tone: firewall.disabled ? .warning : .success
                )
            }
            Spacer()
            Button("Refresh") { Task { await controller.loadFirewall() } }
                .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .compact))
                .disabled(controller.isLoading || !controller.isConnected)
            Button(primaryAddButtonTitle) {
                switch controller.firewallScope {
                case .general:
                    draftRule = FirewallDraftRule(network: "", lockNetwork: false)
                case let .network(name):
                    draftRule = FirewallDraftRule(network: name, lockNetwork: false)
                }
            }
            .buttonStyle(RayfishButtonStyle(kind: .primary, size: .compact))
            .disabled(controller.isLoading || !controller.isConnected)
        }
    }

    private var primaryAddButtonTitle: String {
        switch controller.firewallScope {
        case .general: "Add general rule"
        case let .network(name): "Add rule for \(name)"
        }
    }

    private var scopeSidebar: some View {
        VStack(alignment: .leading, spacing: 10) {
            scopeButton(
                title: "General",
                subtitle: "Defaults & other rules",
                icon: "shield.lefthalf.filled",
                count: generalRules.count,
                hasPending: false,
                isSelected: controller.firewallScope == .general
            ) {
                controller.firewallScope = .general
            }

            Rectangle().fill(RayfishTheme.line).frame(height: 1)
                .padding(.vertical, 2)

            HStack {
                Text("PER NETWORK")
                    .font(RayfishTheme.mono(10))
                    .tracking(1.1)
                    .foregroundColor(RayfishTheme.faint)
                Spacer()
                Text("\(networks.count)")
                    .font(RayfishTheme.mono(10))
                    .foregroundColor(RayfishTheme.faint)
            }
            .padding(.horizontal, 6)

            if networks.count > 5 {
                RayfishSearchField(prompt: "Filter networks...", text: $networkFilter)
            }

            if networks.isEmpty {
                Text("Join a network to configure per-network rules.")
                    .font(RayfishTheme.text(13))
                    .foregroundColor(RayfishTheme.faint)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 8)
            } else if filteredNetworks.isEmpty {
                Text("No matching networks.")
                    .font(RayfishTheme.text(13))
                    .foregroundColor(RayfishTheme.faint)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 8)
            } else {
                VStack(spacing: 3) {
                    ForEach(filteredNetworks) { network in
                        let count = FirewallModel.rules(forNetwork: network.name, in: controller.firewall).count
                        let pending = max(
                            network.pendingSuggestions,
                            FirewallModel.pendingRules(forNetwork: network.name, in: controller.firewall).count
                        )
                        scopeButton(
                            title: network.name,
                            subtitle: "\(network.peers.count) peer\(network.peers.count == 1 ? "" : "s")",
                            icon: "network",
                            count: count,
                            hasPending: pending > 0,
                            isSelected: controller.firewallScope == .network(network.name)
                        ) {
                            controller.firewallScope = .network(network.name)
                        }
                    }
                }
            }
        }
        .padding(12)
        .rayfishCard()
    }

    private func scopeButton(
        title: String,
        subtitle: String,
        icon: String,
        count: Int,
        hasPending: Bool,
        isSelected: Bool,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(isSelected ? RayfishTheme.rose : RayfishTheme.muted)
                    .frame(width: 18)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(RayfishTheme.heading(13))
                        .foregroundColor(isSelected ? RayfishTheme.ink : RayfishTheme.body)
                        .lineLimit(1)
                    Text(subtitle)
                        .font(RayfishTheme.mono(10))
                        .foregroundColor(RayfishTheme.faint)
                        .lineLimit(1)
                }
                Spacer(minLength: 4)
                if hasPending {
                    Circle().fill(RayfishTheme.amber).frame(width: 7, height: 7)
                        .help("Suggested rules waiting for review")
                }
                if count > 0 {
                    Text("\(count)")
                        .font(RayfishTheme.mono(10))
                        .foregroundColor(isSelected ? RayfishTheme.ink : RayfishTheme.muted)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.white.opacity(isSelected ? 0.1 : 0.04))
                        .clipShape(Capsule())
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(isSelected ? RayfishTheme.accent.opacity(0.12) : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 7))
            .overlay(
                RoundedRectangle(cornerRadius: 7)
                    .stroke(isSelected ? RayfishTheme.rose.opacity(0.35) : Color.clear, lineWidth: 1)
            )
            .contentShape(RoundedRectangle(cornerRadius: 7))
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder
    private var detailPane: some View {
        if let firewall = controller.firewall {
            switch controller.firewallScope {
            case .general:
                generalDetail(firewall: firewall)
            case let .network(name):
                networkDetail(name: name, firewall: firewall)
            }
        } else {
            HStack(spacing: 10) {
                ProgressView().controlSize(.small)
                Text("Loading firewall configuration...")
                    .foregroundColor(RayfishTheme.muted)
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
            .rayfishCard()
        }
    }

    private func generalDetail(firewall: ProviderFirewallState) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            if firewall.disabled {
                HStack(spacing: 12) {
                    Image(systemName: "exclamationmark.shield")
                        .foregroundColor(RayfishTheme.amber)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Mesh firewall is paused")
                            .font(RayfishTheme.heading(14))
                            .foregroundColor(RayfishTheme.ink)
                        Text("All mesh traffic is currently allowed regardless of rules or default policies.")
                            .font(RayfishTheme.text(13))
                            .foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    Button("Resume firewall") {
                        Task { await controller.setFirewallEnabled(true) }
                    }
                    .buttonStyle(RayfishButtonStyle(kind: .primary, size: .compact))
                    .disabled(controller.isLoading)
                }
                .padding(14)
                .background(RayfishTheme.amber.opacity(0.06))
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(RayfishTheme.amber.opacity(0.3)))
            }

            VStack(alignment: .leading, spacing: 14) {
                Text("Default posture").font(RayfishTheme.heading(15)).foregroundColor(RayfishTheme.ink)
                Text("Rules filter Rayfish mesh traffic alongside your Mac's system firewall. Return traffic for connections started from this Mac is allowed automatically.")
                    .font(RayfishTheme.text(13))
                    .lineSpacing(2)
                    .foregroundColor(RayfishTheme.muted)

                Rectangle().fill(RayfishTheme.line).frame(height: 1)

                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Enforce mesh firewall").foregroundColor(RayfishTheme.ink)
                        Text("Evaluate rules and defaults on every mesh packet.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    Toggle("Enforce mesh firewall", isOn: Binding(
                        get: { !firewall.disabled },
                        set: { enabled in Task { await controller.setFirewallEnabled(enabled) } }
                    ))
                    .labelsHidden()
                    .toggleStyle(.switch)
                }

                Rectangle().fill(RayfishTheme.line).frame(height: 1)

                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Inbound default").foregroundColor(RayfishTheme.ink)
                        Text("Unsolicited incoming traffic from peers when no rule matches.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    Picker("Inbound default", selection: Binding(
                        get: { firewall.defaultInbound },
                        set: { next in
                            guard next != firewall.defaultInbound else { return }
                            if next == "allow" {
                                pendingDefaultChange = DefaultPolicyChange(direction: "inbound", nextAction: next)
                            } else {
                                Task { await controller.setFirewallDefaultInbound(next) }
                            }
                        }
                    )) {
                        Text("Deny (recommended)").tag("deny")
                        Text("Allow").tag("allow")
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                    .frame(width: 175)
                }

                Rectangle().fill(RayfishTheme.line).frame(height: 1)

                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Outbound default").foregroundColor(RayfishTheme.ink)
                        Text("Outgoing connections started from this Mac when no rule matches.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    Picker("Outbound default", selection: Binding(
                        get: { firewall.defaultOutbound },
                        set: { next in
                            guard next != firewall.defaultOutbound else { return }
                            if next == "deny" {
                                pendingDefaultChange = DefaultPolicyChange(direction: "outbound", nextAction: next)
                            } else {
                                Task { await controller.setFirewallDefaultOutbound(next) }
                            }
                        }
                    )) {
                        Text("Allow (recommended)").tag("allow")
                        Text("Deny").tag("deny")
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                    .frame(width: 175)
                }

                Rectangle().fill(RayfishTheme.line).frame(height: 1)

                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Reject blocked traffic immediately").foregroundColor(RayfishTheme.ink)
                        Text("Reply with TCP reset or ICMP unreachable instead of dropping silently.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    Toggle("Reject blocked traffic immediately", isOn: Binding(
                        get: { firewall.reject },
                        set: { reject in Task { await controller.setFirewallReject(reject) } }
                    ))
                    .labelsHidden()
                    .toggleStyle(.switch)
                }
            }
            .disabled(controller.isLoading)
            .padding(18)
            .rayfishCard()

            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("General rules").font(RayfishTheme.heading(15)).foregroundColor(RayfishTheme.ink)
                        Text("Cross-network rules evaluated in order, first match wins.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    Button("Add rule") {
                        draftRule = FirewallDraftRule(network: "", lockNetwork: false)
                    }
                    .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .compact))
                    .disabled(controller.isLoading)
                }
                .padding(16)

                if generalRules.isEmpty {
                    Rectangle().fill(RayfishTheme.line).frame(height: 1)
                    VStack(spacing: 6) {
                        Text("No general rules configured.")
                            .font(RayfishTheme.text(14)).foregroundColor(RayfishTheme.muted)
                        Text("Traffic not matched by a network rule uses your default policies above.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.faint)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 26)
                } else {
                    ForEach(generalRules) { item in
                        Rectangle().fill(RayfishTheme.line).frame(height: 1)
                        FirewallRuleRow(
                            item: item,
                            networks: networks,
                            scopedNetwork: nil,
                            isDisabled: controller.isLoading,
                            onRemove: { removingRule = item }
                        )
                    }
                }
            }
            .rayfishCard()

            let scopedCount = firewall.rules.count - generalRules.count
            if scopedCount > 0 {
                HStack(spacing: 10) {
                    Image(systemName: "network").foregroundColor(RayfishTheme.faint)
                    Text("\(scopedCount) network-specific rule\(scopedCount == 1 ? "" : "s") configured. Select a network on the left to inspect or edit them.")
                        .font(RayfishTheme.text(13))
                        .foregroundColor(RayfishTheme.muted)
                    Spacer()
                }
                .padding(14)
                .rayfishCard()
            }
        }
    }

    private func networkDetail(name: String, firewall: ProviderFirewallState) -> some View {
        let network = networks.first { $0.name == name }
        let scopedRules = FirewallModel.rules(forNetwork: name, in: firewall)
        let pendingRules = FirewallModel.pendingRules(forNetwork: name, in: firewall)
        let autoAccept = FirewallModel.autoAccept(
            forNetwork: name,
            in: firewall,
            fallback: network?.autoAcceptFirewall ?? false
        )

        return VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .center, spacing: 10) {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(name).font(RayfishTheme.heading(18)).foregroundColor(RayfishTheme.ink)
                        if let role = network?.role {
                            RayfishBadge(
                                text: role.uppercased(),
                                tone: role == "coordinator" ? .accent : .neutral
                            )
                        }
                    }
                    if let network {
                        Text("\(network.hostname).\(network.name).ray · \(network.peers.count) peer\(network.peers.count == 1 ? "" : "s")")
                            .font(RayfishTheme.mono(11))
                            .foregroundColor(RayfishTheme.faint)
                    }
                }
                Spacer()
                Button("Add rule") {
                    draftRule = FirewallDraftRule(network: name, lockNetwork: true)
                }
                .buttonStyle(RayfishButtonStyle(kind: .primary, size: .compact))
                .disabled(controller.isLoading)
            }
            .padding(16)
            .rayfishCard()

            if !pendingRules.isEmpty {
                VStack(alignment: .leading, spacing: 0) {
                    HStack(spacing: 10) {
                        Image(systemName: "sparkles").foregroundColor(RayfishTheme.amber)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Coordinator suggested \(pendingRules.count) rule\(pendingRules.count == 1 ? "" : "s")")
                                .font(RayfishTheme.heading(14)).foregroundColor(RayfishTheme.ink)
                            Text("Review before accepting. Accepted rules open or restrict ports for peers on \(name).")
                                .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                        }
                        Spacer()
                        Button("Dismiss", role: .destructive) {
                            Task { await controller.denyFirewallSuggestions(network: name) }
                        }
                        .buttonStyle(RayfishButtonStyle(kind: .danger, size: .compact))
                        .disabled(controller.isLoading)
                        Button("Accept all") {
                            Task { await controller.acceptFirewallSuggestions(network: name) }
                        }
                        .buttonStyle(RayfishButtonStyle(kind: .primary, size: .compact))
                        .disabled(controller.isLoading)
                    }
                    .padding(14)

                    ForEach(Array(pendingRules.enumerated()), id: \.offset) { offset, rule in
                        Rectangle().fill(RayfishTheme.line).frame(height: 1)
                        FirewallRuleRow(
                            item: IndexedFirewallRule(index: UInt32(offset), rule: rule),
                            networks: networks,
                            scopedNetwork: name,
                            isDisabled: true,
                            onRemove: nil
                        )
                    }
                }
                .background(RayfishTheme.amber.opacity(0.04))
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(RayfishTheme.amber.opacity(0.3)))
            }

            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Rules on \(name)").font(RayfishTheme.heading(15)).foregroundColor(RayfishTheme.ink)
                        Text("Only match peers sharing \(name). Evaluated in order.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                }
                .padding(16)

                if scopedRules.isEmpty {
                    Rectangle().fill(RayfishTheme.line).frame(height: 1)
                    VStack(spacing: 8) {
                        Text("No rules specific to \(name).")
                            .font(RayfishTheme.text(14)).foregroundColor(RayfishTheme.muted)
                        Text("Traffic with peers on \(name) follows your general rules and the \(firewall.defaultInbound) inbound default.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.faint)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.horizontal, 20)
                    .padding(.vertical, 28)
                } else {
                    ForEach(scopedRules) { item in
                        Rectangle().fill(RayfishTheme.line).frame(height: 1)
                        FirewallRuleRow(
                            item: item,
                            networks: networks,
                            scopedNetwork: name,
                            isDisabled: controller.isLoading,
                            onRemove: { removingRule = item }
                        )
                    }
                }
            }
            .rayfishCard()

            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Auto-accept suggested rules").foregroundColor(RayfishTheme.ink)
                        Text("Automatically install firewall rules published by \(name)'s coordinator without manual review.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    Toggle("Auto-accept suggested rules", isOn: Binding(
                        get: { autoAccept },
                        set: { enabled in Task { await controller.setNetworkFirewallAutoAccept(network: name, enabled: enabled) } }
                    ))
                    .labelsHidden()
                    .toggleStyle(.switch)
                    .disabled(controller.isLoading)
                }

                Rectangle().fill(RayfishTheme.line).frame(height: 1)

                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("General rules also apply")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.body)
                        Text("\(generalRules.count) cross-network rule\(generalRules.count == 1 ? "" : "s") · inbound default \(firewall.defaultInbound) · outbound default \(firewall.defaultOutbound)")
                            .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.faint)
                    }
                    Spacer()
                    Button("View general rules") {
                        controller.firewallScope = .general
                    }
                    .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .compact))
                }
            }
            .padding(16)
            .rayfishCard()
        }
    }
}

struct FirewallRuleRow: View {
    let item: IndexedFirewallRule
    let networks: [ProviderNetwork]
    let scopedNetwork: String?
    let isDisabled: Bool
    let onRemove: (() -> Void)?

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            RayfishBadge(
                text: item.rule.action.uppercased(),
                tone: item.rule.action == "allow" ? .success : .accent
            )
            .frame(width: 64, alignment: .leading)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(FirewallModel.directionLabel(for: item.rule))
                        .font(RayfishTheme.heading(13))
                        .foregroundColor(RayfishTheme.ink)
                    Text(FirewallModel.trafficSummary(for: item.rule))
                        .font(RayfishTheme.mono(12))
                        .foregroundColor(RayfishTheme.body)
                    if let origin = FirewallModel.originLabel(for: item.rule) {
                        RayfishBadge(text: origin, tone: .neutral)
                    }
                }
                HStack(spacing: 8) {
                    Text(FirewallModel.peerLabel(for: item.rule.peer, in: networks, scopedNetwork: scopedNetwork))
                        .font(RayfishTheme.mono(11))
                        .foregroundColor(RayfishTheme.muted)
                    if scopedNetwork == nil && !FirewallModel.isWildcard(item.rule.network) {
                        Text("· network \(item.rule.network) (inactive)")
                            .font(RayfishTheme.mono(11))
                            .foregroundColor(RayfishTheme.amber)
                    }
                }
            }

            Spacer(minLength: 8)

            if let onRemove {
                if item.rule.suggestedBy == "ssh" {
                    Text("Managed by SSH")
                        .font(RayfishTheme.mono(11))
                        .foregroundColor(RayfishTheme.faint)
                } else {
                    Button("Remove", role: .destructive, action: onRemove)
                        .buttonStyle(RayfishButtonStyle(kind: .danger, size: .compact))
                        .disabled(isDisabled)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }
}

struct AddFirewallRuleSheet: View {
    @ObservedObject var controller: TunnelController
    let draft: FirewallDraftRule
    @Environment(\.dismiss) private var dismiss

    @State private var direction = "in"
    @State private var action = "allow"
    @State private var protocolName = "tcp"
    @State private var port = ""
    @State private var peer: String
    @State private var network: String
    @State private var localError: String?

    init(controller: TunnelController, draft: FirewallDraftRule, initialPeer: String = "") {
        self.controller = controller
        self.draft = draft
        let rawPeer = draft.peer.isEmpty ? initialPeer : draft.peer
        let resolvedPeer = FirewallModel.canonicalPeerSelector(
            rawPeer,
            forNetwork: draft.network,
            in: controller.status?.networks ?? []
        )
        _peer = State(initialValue: resolvedPeer)
        _network = State(initialValue: draft.network)
    }

    private var peerOptions: [FirewallPeerOption] {
        peerOptions(forNetwork: network)
    }

    private func peerOptions(forNetwork selectedNetwork: String) -> [FirewallPeerOption] {
        FirewallModel.peerOptions(
            forNetwork: selectedNetwork,
            in: controller.status?.networks ?? [],
            selectedPeer: peer
        )
    }

    private var networkOptions: [FirewallPeerOption] {
        [FirewallPeerOption(id: "", label: "All networks (general rule)")] +
            (controller.status?.networks ?? []).map { FirewallPeerOption(id: $0.name, label: $0.name) }
    }

    private var usesPorts: Bool {
        protocolName == "tcp" || protocolName == "udp"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text(draft.lockNetwork && !network.isEmpty ? "Add rule for \(network)" : "Add firewall rule")
                    .font(RayfishTheme.heading(18))
                    .foregroundColor(RayfishTheme.ink)
                Text(network.isEmpty
                     ? "Applies across every network on this Mac."
                     : "Applies only to peers sharing \(network).")
                    .font(RayfishTheme.text(13))
                    .foregroundColor(RayfishTheme.muted)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Quick presets")
                    .font(RayfishTheme.mono(10))
                    .tracking(0.8)
                    .foregroundColor(RayfishTheme.faint)
                HStack(spacing: 8) {
                    presetButton("Allow web (80, 443)") {
                        direction = "in"; action = "allow"; protocolName = "tcp"; port = "80,443"
                    }
                    presetButton("Allow SSH (22)") {
                        direction = "in"; action = "allow"; protocolName = "tcp"; port = "22"
                    }
                    presetButton("Allow all TCP") {
                        direction = "in"; action = "allow"; protocolName = "tcp"; port = ""
                    }
                    presetButton("Block peer") {
                        direction = "in"; action = "deny"; protocolName = "any"; port = ""
                    }
                }
            }

            Rectangle().fill(RayfishTheme.line).frame(height: 1)

            if !draft.lockNetwork {
                fieldRow("Scope") {
                    Picker("Scope", selection: Binding(
                        get: { network },
                        set: { next in
                            network = next
                            if !peerOptions(forNetwork: next).contains(where: { $0.id == peer }) {
                                peer = ""
                            }
                        }
                    )) {
                        ForEach(networkOptions) { option in Text(option.label).tag(option.id) }
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                }
            }

            fieldRow("Action") {
                Picker("Action", selection: $action) {
                    Text("Allow").tag("allow")
                    Text("Deny").tag("deny")
                }
                .labelsHidden()
                .pickerStyle(.segmented)
                .frame(width: 200)
            }

            fieldRow("Direction") {
                Picker("Direction", selection: $direction) {
                    Text("Inbound").tag("in")
                    Text("Outbound").tag("out")
                }
                .labelsHidden()
                .pickerStyle(.segmented)
                .frame(width: 200)
            }

            fieldRow("Protocol") {
                Picker("Protocol", selection: $protocolName) {
                    Text("TCP").tag("tcp")
                    Text("UDP").tag("udp")
                    Text("ICMP").tag("icmp")
                    Text("Any").tag("any")
                }
                .labelsHidden()
                .pickerStyle(.segmented)
                .frame(width: 260)
            }

            fieldRow("Ports") {
                if usesPorts {
                    TextField("All ports, or 22, 80,443, 8000-9000", text: $port)
                        .font(RayfishTheme.mono(12))
                } else {
                    Text(protocolName == "icmp" ? "Not used for ICMP" : "Covers all ports")
                        .font(RayfishTheme.text(13))
                        .foregroundColor(RayfishTheme.faint)
                        .padding(.vertical, 6)
                }
            }

            fieldRow("Peer") {
                Picker("Peer", selection: $peer) {
                    ForEach(peerOptions) { option in Text(option.label).tag(option.id) }
                }
                .labelsHidden()
                .pickerStyle(.menu)
            }

            if let localError {
                Text(localError).font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.amber)
            }

            HStack {
                if controller.isLoading { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }
                    .disabled(controller.isLoading)
                Button("Add rule") {
                    Task {
                        localError = nil
                        let trimmedPort = usesPorts ? port.trimmingCharacters(in: .whitespacesAndNewlines) : ""
                        let ok = await controller.addFirewallRule(
                            direction: direction,
                            action: action,
                            protocolName: protocolName,
                            port: trimmedPort,
                            peer: peer.isEmpty ? nil : peer,
                            network: network.isEmpty ? nil : network
                        )
                        if ok {
                            dismiss()
                        } else {
                            localError = controller.error
                        }
                    }
                }
                .buttonStyle(RayfishButtonStyle(kind: .primary))
                .disabled(controller.isLoading)
            }
        }
        .rayfishSheet()
        .frame(width: 540)
    }

    private func presetButton(_ label: String, apply: @escaping () -> Void) -> some View {
        Button(label, action: apply)
            .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .compact))
    }

    private func fieldRow<Field: View>(_ title: String, @ViewBuilder field: () -> Field) -> some View {
        HStack(alignment: .center, spacing: 16) {
            Text(title)
                .font(RayfishTheme.text(14))
                .foregroundColor(RayfishTheme.muted)
                .frame(width: 90, alignment: .leading)
            field().frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
