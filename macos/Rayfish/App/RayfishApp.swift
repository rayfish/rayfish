import AppKit
import Sparkle
import SwiftUI

@main
struct RayfishApp: App {
    @NSApplicationDelegateAdaptor(RayfishAppDelegate.self) private var appDelegate

    init() { RayfishTheme.registerFonts() }

    var body: some Scene {
        Settings { EmptyView() }
        .commands {
            CommandGroup(replacing: .appSettings) {
                Button("Settings...") { appDelegate.openSettings() }
                    .keyboardShortcut(",", modifiers: .command)
            }
            CommandGroup(replacing: .newItem) {
                Button("Open Rayfish") { appDelegate.openMainWindow() }
                    .keyboardShortcut("o", modifiers: .command)
            }
            CommandGroup(after: .appInfo) {
                if appDelegate.canCheckForUpdates {
                    Button("Check for Updates...") { appDelegate.checkForUpdates() }
                }
            }
        }
    }
}

@MainActor
final class RayfishAppDelegate: NSObject, NSApplicationDelegate, @preconcurrency SPUUpdaterDelegate {
    private lazy var updaterController: SPUStandardUpdaterController? = {
        guard let feed = Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String,
              feed.hasPrefix("https://") else { return nil }
        return SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: self, userDriverDelegate: nil)
    }()
    private let controller = TunnelController()
    private var mainWindow: RayfishWindow?
    private var statusMenu: RayfishMenu?
    private var isTerminating = false
    private var updateVersion: String?
    private var installUpdate: (() -> Void)?
    private var updateRestartRequested = false

    var canCheckForUpdates: Bool { updaterController != nil }

    func checkForUpdates() { updaterController?.checkForUpdates(nil) }

    func openSettings() {
        controller.page = .settings
        openMainWindow()
    }

    func updater(_ updater: SPUUpdater, willInstallUpdateOnQuit item: SUAppcastItem,
                 immediateInstallationBlock immediateInstallHandler: @escaping () -> Void) -> Bool {
        updateVersion = item.displayVersionString
        installUpdate = immediateInstallHandler
        controller.notifications.showUpdateReady(version: item.displayVersionString)
        return true
    }

    private func restartToUpdate() {
        guard !updateRestartRequested, !isTerminating, let installUpdate else { return }
        updateRestartRequested = true
        installUpdate()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        _ = updaterController
        controller.notifications.install()
        controller.notifications.onOpen = { [weak self] page in
            self?.controller.page = page
            self?.openMainWindow()
        }
        controller.notifications.onOpenFirewallNetwork = { [weak self] network in
            self?.controller.openFirewall(for: network)
            self?.openMainWindow()
        }
        controller.notifications.onRevealFile = { url in
            NSWorkspace.shared.activateFileViewerSelecting([url])
        }
        controller.notifications.onRestartUpdate = { [weak self] in self?.restartToUpdate() }
        controller.notifications.onInvitation = { [weak self] id, response in
            guard let controller = self?.controller else { return }
            Task {
                switch response {
                case .join: await controller.acceptInvitation(id: id)
                case .decline: await controller.declineInvitation(id: id)
                }
            }
        }
        statusMenu = RayfishMenu(controller: controller,
                                 updateReady: { [weak self] in self?.updateVersion },
                                 restartUpdate: { [weak self] in self?.restartToUpdate() }) { [weak self] in
            self?.openMainWindow()
        }
        openMainWindow()
    }

    func openMainWindow() {
        if mainWindow == nil {
            mainWindow = RayfishWindow(content: NSHostingView(rootView: ContentView(
                controller: controller, updater: updaterController?.updater)))
        }
        mainWindow?.show()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !isTerminating else { return .terminateLater }
        isTerminating = true
        Task {
            let stopped = await controller.prepareToQuit(forUpdate: updateRestartRequested)
            isTerminating = false
            if !stopped {
                updateRestartRequested = false
                openMainWindow()
            }
            sender.reply(toApplicationShouldTerminate: stopped)
        }
        return .terminateLater
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openMainWindow()
        return true
    }
}

private struct ContentView: View {
    @ObservedObject var controller: TunnelController
    let updater: SPUUpdater?

    private var connected: Bool { controller.isConnected }

    var body: some View {
        ZStack(alignment: .bottom) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    header
                    if let status = controller.status {
                        StatusStrip(controller: controller, status: status)
                        if let warning = status.connectionWarning {
                            BannerRow(icon: "wifi.exclamationmark", text: warning, color: RayfishTheme.amber)
                        }
                    }
                    if let activity = controller.activity {
                        HStack(spacing: 10) {
                            ProgressView().controlSize(.small)
                            Text(activity)
                        }
                        .font(RayfishTheme.text(14))
                        .foregroundColor(RayfishTheme.muted)
                    }
                    if let error = controller.error {
                        BannerRow(
                            icon: "exclamationmark.triangle",
                            text: error,
                            color: RayfishTheme.amber,
                            onDismiss: { controller.error = nil }
                        )
                    }
                    switch controller.page {
                    case .networks:
                        NetworksView(controller: controller)
                    case .devices:
                        DevicesView(controller: controller)
                    case .firewall:
                        FirewallPageView(controller: controller)
                    case .files:
                        FilesView(controller: controller)
                    case .settings:
                        SettingsView(controller: controller, updater: updater)
                    }
                    Spacer(minLength: 32)
                }
                .padding(28)
                .frame(maxWidth: 976)
                .frame(maxWidth: .infinity)
            }

            if let toast = controller.toastMessage {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 12))
                        .foregroundColor(RayfishTheme.green)
                    Text(toast)
                        .font(RayfishTheme.mono(12))
                        .foregroundColor(RayfishTheme.ink)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 9)
                .background(RayfishTheme.deep)
                .clipShape(Capsule())
                .overlay(Capsule().stroke(RayfishTheme.border, lineWidth: 1))
                .shadow(color: .black.opacity(0.35), radius: 10, y: 4)
                .padding(.bottom, 20)
                .transition(.opacity)
                .allowsHitTesting(false)
            }
        }
        .animation(.easeOut(duration: 0.16), value: controller.toastMessage)
        .background(RayfishTheme.background)
        .font(RayfishTheme.text())
        .foregroundColor(RayfishTheme.body)
        .buttonStyle(RayfishButtonStyle())
        .tint(RayfishTheme.accent)
        .preferredColorScheme(.dark)
        .frame(minWidth: 820, minHeight: 560)
        .task {
            await controller.startup()
        }
    }

    private var header: some View {
        VStack(spacing: 18) {
            HStack(spacing: 14) {
                Image("Logo").resizable().scaledToFit().frame(width: 34, height: 34)
                    .accessibilityHidden(true)
                (Text("rayf") + Text("i").foregroundColor(RayfishTheme.rose) + Text("sh"))
                    .font(RayfishTheme.logo)
                    .foregroundColor(RayfishTheme.ink)
                    .accessibilityLabel("Rayfish")
                HStack(spacing: 6) {
                    Circle().fill(connected ? RayfishTheme.green : RayfishTheme.faint)
                        .frame(width: 7, height: 7)
                    Text(controller.connectionLabel)
                }
                .font(RayfishTheme.mono(11))
                .foregroundColor(connected ? RayfishTheme.green : RayfishTheme.faint)
                .padding(.horizontal, 9)
                .padding(.vertical, 4)
                .background(Color.white.opacity(0.03))
                .clipShape(Capsule())
                Spacer()
                Button(connected ? "Disconnect" : "Connect") {
                    Task {
                        if connected { await controller.disconnect() }
                        else { await controller.connect() }
                    }
                }
                .buttonStyle(RayfishButtonStyle(kind: connected ? .connected : .primary))
                .disabled(controller.isLoading)
            }
            HStack(spacing: 24) {
                ForEach(RayfishPage.allCases, id: \.self) { item in
                    TabBarButton(
                        title: item.rawValue,
                        isSelected: controller.page == item,
                        badgeDotColor: tabBadgeColor(for: item)
                    ) {
                        if item == .firewall && controller.page != .firewall {
                            controller.firewallReturnToNetworks = false
                        }
                        controller.page = item
                    }
                }
                Spacer()
                Text("PRIVATE MESH").font(RayfishTheme.mono(10)).tracking(1.4)
                    .foregroundColor(RayfishTheme.faint).padding(.bottom, 10)
            }
            .overlay(alignment: .bottom) { Rectangle().fill(RayfishTheme.line).frame(height: 1) }
        }
    }

    private func tabBadgeColor(for item: RayfishPage) -> Color? {
        guard let status = controller.status else { return nil }
        switch item {
        case .networks:
            let hasAttn = !status.pendingRequests.isEmpty || !(status.invitations ?? []).isEmpty
            return hasAttn ? RayfishTheme.accent : nil
        case .devices:
            return status.connectionRequests.isEmpty ? nil : RayfishTheme.accent
        case .firewall:
            let hasSuggested = status.networks.contains { $0.pendingSuggestions > 0 }
                || (controller.firewall?.networks.contains { !$0.pendingRules.isEmpty } ?? false)
            return hasSuggested ? RayfishTheme.amber : nil
        case .files:
            let hasPending = (status.files ?? []).contains { $0.state == .pending }
            return hasPending ? RayfishTheme.accent : nil
        case .settings:
            return nil
        }
    }
}

private struct TabBarButton: View {
    let title: String
    let isSelected: Bool
    let badgeDotColor: Color?
    let action: () -> Void
    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Text(title)
                    .font(RayfishTheme.heading(14))
                    .foregroundColor(isSelected ? RayfishTheme.ink : (isHovered ? RayfishTheme.body : RayfishTheme.faint))
                if let badgeDotColor {
                    Circle().fill(badgeDotColor).frame(width: 6, height: 6)
                }
            }
            .padding(.bottom, 10)
            .overlay(alignment: .bottom) {
                Rectangle().fill(isSelected ? RayfishTheme.accent : .clear).frame(height: 2)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }
}

private struct BannerRow: View {
    let icon: String
    let text: String
    let color: Color
    var onDismiss: (() -> Void)? = nil

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .padding(.top, 2)
            Text(text)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            if let onDismiss {
                Button(action: onDismiss) {
                    Image(systemName: "xmark")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(RayfishTheme.muted)
                }
                .buttonStyle(.plain)
                .help("Dismiss")
            }
        }
        .font(RayfishTheme.text(14))
        .foregroundColor(color)
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.05))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(color.opacity(0.28)))
    }
}

private struct StatusStrip: View {
    @ObservedObject var controller: TunnelController
    let status: ProviderStatus
    @State private var ipHovered = false

    private var totalPeers: Int {
        status.networks.reduce(0) { $0 + $1.peers.count }
    }

    private var activePeers: Int {
        status.networks.reduce(0) { count, net in
            count + net.peers.filter { $0.state == "direct" || $0.state == "relay" }.count
        }
    }

    private var activeExitLabel: String? {
        guard let active = status.exitNodes.first(where: { $0.using != nil }),
              let selected = active.using else { return nil }
        let peerName = status.networks
            .first { $0.name == active.network }?
            .peers.first { $0.identity == selected }?.hostname ?? selected
        return "\(peerName) (\(active.network))"
    }

    private var hasExitChoices: Bool {
        status.exitSelected || status.exitNodes.contains { !$0.available.isEmpty }
    }

    var body: some View {
        HStack(spacing: 16) {
            Button {
                controller.copyToClipboard(status.ipv6, label: "Copied IPv6 address")
            } label: {
                HStack(spacing: 7) {
                    Text(status.ipv6)
                        .foregroundColor(ipHovered ? RayfishTheme.ink : RayfishTheme.body)
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 11))
                        .foregroundColor(ipHovered ? RayfishTheme.rose : RayfishTheme.faint)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .onHover { ipHovered = $0 }
            .help("Click to copy this Mac's mesh IPv6 address")
            .accessibilityLabel("Copy this Mac's IP address")

            Text("·").foregroundColor(RayfishTheme.border)
            Text("\(status.networks.count) network\(status.networks.count == 1 ? "" : "s")")
            Text("·").foregroundColor(RayfishTheme.border)
            if activePeers > 0 {
                Text("\(activePeers) active of \(totalPeers) peer\(totalPeers == 1 ? "" : "s")")
            } else {
                Text("\(totalPeers) peer\(totalPeers == 1 ? "" : "s")")
            }

            Spacer()

            if hasExitChoices {
                ExitNodeMenu(controller: controller, status: status, activeLabel: activeExitLabel)
            }
        }
        .font(RayfishTheme.mono(12))
        .foregroundColor(RayfishTheme.muted)
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(RayfishTheme.panel.opacity(0.65))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(RayfishTheme.line))
    }
}

private struct ExitNodeMenu: View {
    @ObservedObject var controller: TunnelController
    let status: ProviderStatus
    let activeLabel: String?

    var body: some View {
        Menu {
            Button {
                let currentNet = status.exitNodes.first { $0.using != nil }?.network ?? status.exitNodes.first?.network ?? ""
                if !currentNet.isEmpty {
                    Task { await controller.selectExitNode(network: currentNet, peer: nil) }
                }
            } label: {
                if !status.exitSelected {
                    Label("Direct connection", systemImage: "checkmark")
                } else {
                    Text("Direct connection")
                }
            }
            .disabled(!status.exitSelected || controller.isLoading)

            ForEach(status.exitNodes.filter { !$0.available.isEmpty }, id: \.network) { exitNet in
                Divider()
                Text(exitNet.network)
                ForEach(exitNet.available.filter { !exitNet.refused.contains($0) }, id: \.self) { peer in
                    let isSelected: Bool = {
                        guard let selected = exitNet.using else { return false }
                        return status.networks.first { $0.name == exitNet.network }?.peers.contains {
                            $0.hostname == peer && $0.identity == selected
                        } == true
                    }()
                    Button {
                        Task { await controller.selectExitNode(network: exitNet.network, peer: peer) }
                    } label: {
                        if isSelected {
                            Label(peer, systemImage: "checkmark")
                        } else {
                            Text(peer)
                        }
                    }
                    .disabled(controller.isLoading)
                }
            }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: activeLabel == nil ? "arrow.up.right.circle" : "globe")
                    .font(.system(size: 11))
                Text(activeLabel.map { "Exit: \($0)" } ?? "Exit: Direct")
                    .font(RayfishTheme.mono(11))
            }
            .foregroundColor(activeLabel == nil ? RayfishTheme.muted : RayfishTheme.green)
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
    }
}

private struct NetworksView: View {
    @ObservedObject var controller: TunnelController
    @State private var networkAction: NetworkAction?
    @State private var inviteCode: String?
    @State private var leavingNetwork: ProviderNetwork?
    @State private var renamingNetwork: ProviderNetwork?
    @State private var sendingInvite: ProviderNetwork?
    @State private var peerFirewallDraft: FirewallDraftRule?
    @State private var searchQuery = ""
    @State private var collapsedNetworks: Set<String> = []

    private var networks: [ProviderNetwork] { controller.status?.networks ?? [] }
    private var totalPeers: Int { networks.reduce(0) { $0 + $1.peers.count } }
    private var trimmedQuery: String { searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }

    private var displayedNetworks: [(network: ProviderNetwork, peers: [ProviderPeer])] {
        guard !trimmedQuery.isEmpty else {
            return networks.map { ($0, $0.peers) }
        }
        return networks.compactMap { net in
            let netMatches = net.name.lowercased().contains(trimmedQuery)
                || "\(net.hostname).\(net.name).ray".lowercased().contains(trimmedQuery)
            let matchingPeers = net.peers.filter { peer in
                peer.hostname.lowercased().contains(trimmedQuery)
                    || peer.ipv6.lowercased().contains(trimmedQuery)
                    || peer.domain(in: net.name).lowercased().contains(trimmedQuery)
            }
            if netMatches {
                return (net, matchingPeers.isEmpty ? net.peers : matchingPeers)
            }
            if !matchingPeers.isEmpty {
                return (net, matchingPeers)
            }
            return nil
        }
    }

    private var allCollapsed: Bool {
        !networks.isEmpty && networks.allSatisfy { collapsedNetworks.contains($0.name) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            attentionSection
            toolbar
            if let status = controller.status, !status.networks.isEmpty {
                if displayedNetworks.isEmpty {
                    EmptyState(
                        title: "No matching networks or peers.",
                        description: "Try a different network name, peer hostname, or IPv6 address."
                    )
                } else {
                    ForEach(displayedNetworks, id: \.network.id) { entry in
                        let net = entry.network
                        let ruleCount = FirewallModel.rules(forNetwork: net.name, in: controller.firewall).count
                        let pendingFw = max(
                            net.pendingSuggestions,
                            FirewallModel.pendingRules(forNetwork: net.name, in: controller.firewall).count
                        )
                        NetworkCard(
                            network: net,
                            visiblePeers: entry.peers,
                            isCollapsed: trimmedQuery.isEmpty && collapsedNetworks.contains(net.name),
                            firewallRuleCount: ruleCount,
                            pendingFirewallCount: pendingFw,
                            toggleCollapsed: {
                                if collapsedNetworks.contains(net.name) {
                                    collapsedNetworks.remove(net.name)
                                } else {
                                    collapsedNetworks.insert(net.name)
                                }
                            },
                            openFirewall: { controller.openFirewall(for: net.name) },
                            invite: { Task { inviteCode = await controller.invite(network: net.name) } },
                            sendInvite: { sendingInvite = net },
                            leave: { leavingNetwork = net },
                            rename: { renamingNetwork = net },
                            copyText: { value, label in controller.copyToClipboard(value, label: label) },
                            addPeerFirewallRule: { peer in
                                peerFirewallDraft = FirewallDraftRule(
                                    network: net.name,
                                    peer: peer.identity ?? peer.ipv6,
                                    lockNetwork: true
                                )
                            }
                        )
                    }
                }
            } else if controller.status == nil {
                EmptyState(title: controller.isConnected ? "Waiting for network status..." : "Connect to see your networks.",
                           description: controller.isConnected ? "Your saved networks will appear when the tunnel responds." : "Your saved identity and networks are kept while disconnected.")
            } else {
                EmptyState(title: "No networks yet.",
                           description: "Create a private network or join one with an invite code.")
            }
        }
        .alert("Invite code", isPresented: Binding(get: { inviteCode != nil }, set: { if !$0 { inviteCode = nil } })) {
            Button("Copy") {
                if let inviteCode {
                    controller.copyToClipboard(inviteCode, label: "Copied invite code")
                }
            }
            Button("Done", role: .cancel) {}
        } message: { Text(inviteCode ?? "") }
        .confirmationDialog("Leave \(leavingNetwork?.name ?? "network")?",
                            isPresented: Binding(get: { leavingNetwork != nil }, set: { if !$0 { leavingNetwork = nil } })) {
            Button("Leave network", role: .destructive) {
                if let leavingNetwork { Task { await controller.leave(network: leavingNetwork.name) } }
                leavingNetwork = nil
            }
        } message: { Text("This Mac will lose access to the network until it joins again.") }
        .sheet(item: $renamingNetwork) { network in RenameHostSheet(controller: controller, network: network) }
        .sheet(item: $sendingInvite) { network in SendInviteSheet(controller: controller, network: network) }
        .sheet(item: $networkAction) { action in NetworkSheet(controller: controller, action: action) }
        .sheet(item: $peerFirewallDraft) { draft in AddFirewallRuleSheet(controller: controller, draft: draft) }
    }

    @ViewBuilder
    private var attentionSection: some View {
        let invitations = controller.status?.invitations ?? []
        let requests = controller.status?.pendingRequests ?? []
        let firewallNetworks = networks.filter { net in
            net.pendingSuggestions > 0 || !FirewallModel.pendingRules(forNetwork: net.name, in: controller.firewall).isEmpty
        }
        if !invitations.isEmpty || !requests.isEmpty || !firewallNetworks.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                Text("Needs attention").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
                VStack(spacing: 0) {
                    ForEach(Array(invitations.enumerated()), id: \.element.id) { index, invitation in
                        if index > 0 { Rectangle().fill(RayfishTheme.line).frame(height: 1) }
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("You are invited to join \(invitation.network)").foregroundColor(RayfishTheme.ink)
                                Text("From \(invitation.coordinator)")
                                    .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.faint)
                                    .lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                            Button("Decline and block", role: .destructive) { Task { await controller.declineInvitation(id: invitation.id) } }
                                .buttonStyle(RayfishButtonStyle(kind: .danger, size: .compact))
                                .help("Decline and block the sender. Unblock it in Settings.")
                            Button("Join") { Task { await controller.acceptInvitation(id: invitation.id) } }
                                .buttonStyle(RayfishButtonStyle(kind: .primary, size: .compact))
                        }
                        .padding(14)
                    }

                    ForEach(Array(requests.enumerated()), id: \.element.id) { index, request in
                        if index > 0 || !invitations.isEmpty {
                            Rectangle().fill(RayfishTheme.line).frame(height: 1)
                        }
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("\(request.hostname ?? request.id) wants to join \(request.network)")
                                    .foregroundColor(RayfishTheme.ink)
                                Text("Waiting \(request.waitingSecs)s")
                                    .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.faint)
                            }
                            Spacer()
                            Button("Deny", role: .destructive) { Task { await controller.deny(request: request) } }
                                .buttonStyle(RayfishButtonStyle(kind: .danger, size: .compact))
                            Button("Approve") { Task { await controller.accept(request: request) } }
                                .buttonStyle(RayfishButtonStyle(kind: .primary, size: .compact))
                        }
                        .padding(14)
                    }

                    ForEach(Array(firewallNetworks.enumerated()), id: \.element.id) { index, net in
                        if index > 0 || !invitations.isEmpty || !requests.isEmpty {
                            Rectangle().fill(RayfishTheme.line).frame(height: 1)
                        }
                        let count = max(net.pendingSuggestions, FirewallModel.pendingRules(forNetwork: net.name, in: controller.firewall).count)
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("Suggested firewall rules for \(net.name)")
                                    .foregroundColor(RayfishTheme.ink)
                                Text("\(count) rule\(count == 1 ? "" : "s") waiting for review before ports open to peers")
                                    .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.faint)
                            }
                            Spacer()
                            Button("Review in Firewall") {
                                controller.openFirewall(for: net.name)
                            }
                            .buttonStyle(RayfishButtonStyle(kind: .primary, size: .compact))
                        }
                        .padding(14)
                    }
                }
                .rayfishCard()
            }
        }
    }

    private var toolbar: some View {
        VStack(spacing: 10) {
            HStack(spacing: 8) {
                Text("Networks").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
                Spacer()
                if networks.count >= 2 && trimmedQuery.isEmpty {
                    Button(allCollapsed ? "Expand all" : "Collapse all") {
                        if allCollapsed {
                            collapsedNetworks.removeAll()
                        } else {
                            collapsedNetworks = Set(networks.map(\.name))
                        }
                    }
                    .buttonStyle(RayfishButtonStyle(kind: .subtle, size: .compact))
                }
                Button("Join with a code") { networkAction = .join }
                Button("Create a network") { networkAction = .create }
                    .buttonStyle(RayfishButtonStyle(kind: .primary))
            }
            .disabled(controller.isLoading)

            if networks.count >= 2 || totalPeers >= 5 {
                RayfishSearchField(prompt: "Filter networks, peers, or IPv6 addresses...", text: $searchQuery)
            }
        }
    }
}

private struct NetworkCard: View {
    let network: ProviderNetwork
    let visiblePeers: [ProviderPeer]
    let isCollapsed: Bool
    let firewallRuleCount: Int
    let pendingFirewallCount: Int
    let toggleCollapsed: () -> Void
    let openFirewall: () -> Void
    let invite: () -> Void
    let sendInvite: () -> Void
    let leave: () -> Void
    let rename: () -> Void
    let copyText: (String, String) -> Void
    let addPeerFirewallRule: (ProviderPeer) -> Void
    @State private var domainHovered = false

    private var myDomain: String { "\(network.hostname).\(network.name).ray" }

    private var peerSummary: String {
        let total = network.peers.count
        guard total > 0 else { return "No peers yet" }
        let active = network.peers.filter { $0.state == "direct" || $0.state == "relay" }.count
        if active > 0 {
            return "\(active) active · \(total) peer\(total == 1 ? "" : "s")"
        }
        return "\(total) peer\(total == 1 ? "" : "s")"
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 8) {
                        Button(action: toggleCollapsed) {
                            HStack(spacing: 7) {
                                Image(systemName: isCollapsed ? "chevron.right" : "chevron.down")
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundColor(RayfishTheme.faint)
                                    .frame(width: 12)
                                Text(network.name)
                                    .font(RayfishTheme.heading(16))
                                    .foregroundColor(RayfishTheme.ink)
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .help(isCollapsed ? "Expand peer list" : "Collapse peer list")

                        RayfishBadge(
                            text: network.role.uppercased(),
                            tone: network.role == "coordinator" ? .accent : .neutral
                        )

                        Text(peerSummary)
                            .font(RayfishTheme.mono(11))
                            .foregroundColor(RayfishTheme.faint)
                    }

                    Button {
                        copyText(myDomain, "Copied \(myDomain)")
                    } label: {
                        HStack(spacing: 5) {
                            Text(myDomain)
                                .font(RayfishTheme.mono(11))
                                .foregroundColor(domainHovered ? RayfishTheme.rose : RayfishTheme.muted)
                            Image(systemName: "doc.on.doc")
                                .font(.system(size: 9))
                                .foregroundColor(domainHovered ? RayfishTheme.rose : RayfishTheme.faint.opacity(0.7))
                        }
                        .padding(.leading, 19)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .onHover { domainHovered = $0 }
                    .help("Click to copy \(myDomain)")
                }

                Spacer(minLength: 12)

                HStack(spacing: 8) {
                    Button(action: openFirewall) {
                        HStack(spacing: 6) {
                            Image(systemName: "shield.lefthalf.filled")
                                .font(.system(size: 11))
                            Text(firewallRuleCount > 0 ? "Firewall · \(firewallRuleCount)" : "Firewall")
                            if pendingFirewallCount > 0 {
                                Circle().fill(RayfishTheme.amber).frame(width: 6, height: 6)
                            }
                        }
                    }
                    .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .compact))
                    .help("Open firewall rules for \(network.name)")

                    if network.role == "coordinator" {
                        Menu {
                            Button("Create invite code", action: invite)
                            Button("Send invite to identity...", action: sendInvite)
                        } label: {
                            Text("Invite")
                                .font(RayfishTheme.heading(12))
                        }
                        .frame(height: 28)
                        .help("Invite someone to \(network.name)")
                    }

                    Menu {
                        Button("Rename this Mac...", action: rename)
                        Button("Copy \(myDomain)") {
                            copyText(myDomain, "Copied \(myDomain)")
                        }
                        Button("Copy IPv6 address") {
                            copyText(network.ipv6, "Copied IPv6 address")
                        }
                        Divider()
                        Button("Leave network...", role: .destructive, action: leave)
                    } label: {
                        Image(systemName: "ellipsis")
                            .font(.system(size: 12, weight: .semibold))
                            .frame(width: 14, height: 18)
                    }
                    .menuIndicator(.hidden)
                    .frame(width: 30, height: 28)
                    .help("More options for \(network.name)")
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 13)

            if !isCollapsed {
                if visiblePeers.isEmpty {
                    Rectangle().fill(RayfishTheme.line).frame(height: 1)
                    Text("Waiting for peers...")
                        .font(RayfishTheme.mono(12))
                        .foregroundColor(RayfishTheme.faint)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 35)
                        .padding(.vertical, 14)
                } else {
                    ForEach(visiblePeers) { peer in
                        Rectangle().fill(RayfishTheme.line).frame(height: 1)
                        PeerRow(
                            peer: peer,
                            domains: peer.hostname.isEmpty ? [] : [peer.domain(in: network.name)],
                            copyText: copyText,
                            onAddFirewallRule: peer.isOwnDevice ? nil : { addPeerFirewallRule(peer) }
                        )
                    }
                }
            }
        }
        .rayfishCard()
    }
}

private struct PeerRow: View {
    let peer: ProviderPeer
    let domains: [String]
    let copyText: (String, String) -> Void
    var onAddFirewallRule: (() -> Void)? = nil
    @State private var isHovered = false

    private var color: Color {
        peer.state == "direct" ? RayfishTheme.green : peer.state == "relay" ? RayfishTheme.amber : RayfishTheme.faint
    }

    var body: some View {
        HStack(spacing: 12) {
            Circle().fill(color).frame(width: 7, height: 7)
            Text(peer.hostname)
                .foregroundColor(isHovered && !domains.isEmpty ? RayfishTheme.rose : RayfishTheme.ink)
                .frame(minWidth: 120, alignment: .leading)
            if peer.isOwnDevice {
                Text("YOU").font(RayfishTheme.mono(9)).foregroundColor(RayfishTheme.faint)
                    .padding(.horizontal, 5).padding(.vertical, 2)
                    .overlay(RoundedRectangle(cornerRadius: 4).stroke(RayfishTheme.border))
            }
            Text(peer.ipv6).foregroundColor(RayfishTheme.muted).lineLimit(1)
            Spacer(minLength: 8)
            if isHovered, let domain = domains.first {
                Text("click to copy")
                    .font(RayfishTheme.mono(10))
                    .foregroundColor(RayfishTheme.faint)
                    .help("Copy \(domain)")
            }
            if isHovered, let onAddFirewallRule {
                Button("+ Rule", action: onAddFirewallRule)
                    .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .compact))
                    .help("Add a firewall rule for \(peer.hostname.isEmpty ? peer.ipv6 : peer.hostname)")
            }
            Text(peer.state).foregroundColor(color)
            if let latency = peer.latencyMs {
                Text("\(latency) ms")
                    .foregroundColor(RayfishTheme.faint)
                    .frame(minWidth: 52, alignment: .trailing)
            }
        }
        .font(RayfishTheme.mono(12))
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(isHovered ? Color.white.opacity(0.025) : Color.clear)
        .contentShape(Rectangle())
        .onHover { isHovered = $0 }
        .onTapGesture {
            if let domain = domains.first {
                copyText(domain, "Copied \(domain)")
            } else {
                copyText(peer.ipv6, "Copied \(peer.ipv6)")
            }
        }
        .contextMenu {
            ForEach(domains, id: \.self) { domain in
                Button("Copy \(domain)") {
                    copyText(domain, "Copied \(domain)")
                }
            }
            Button("Copy IPv6 (\(peer.ipv6))") {
                copyText(peer.ipv6, "Copied IPv6 address")
            }
            if let identity = peer.identity {
                Button("Copy identity") {
                    copyText(identity, "Copied peer identity")
                }
            }
            if let onAddFirewallRule {
                Divider()
                Button("Add firewall rule for \(peer.hostname.isEmpty ? peer.ipv6 : peer.hostname)...") {
                    onAddFirewallRule()
                }
            }
        }
    }
}

private struct DevicesView: View {
    @ObservedObject var controller: TunnelController
    @State private var connectingPeer = false
    @State private var peerFilter = ""
    @State private var activeOnly = false

    private var allPeers: [ProviderPeer] {
        let all = controller.status?.networks.flatMap { $0.peers } ?? []
        return Dictionary(all.map { ($0.ipv6, $0) }, uniquingKeysWith: { first, _ in first })
            .values.sorted { $0.hostname.localizedStandardCompare($1.hostname) == .orderedAscending }
    }

    private var filteredPeers: [ProviderPeer] {
        let query = peerFilter.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return allPeers.filter { peer in
            if activeOnly && peer.state != "direct" && peer.state != "relay" {
                return false
            }
            guard !query.isEmpty else { return true }
            return peer.hostname.lowercased().contains(query)
                || peer.ipv6.lowercased().contains(query)
                || domains(for: peer).contains { $0.lowercased().contains(query) }
        }
    }

    private func domains(for peer: ProviderPeer) -> [String] {
        (controller.status?.networks ?? []).compactMap { network in
            network.peers.first { $0.ipv6 == peer.ipv6 && !$0.hostname.isEmpty }?.domain(in: network.name)
        }.sorted()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Devices").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
                Spacer()
                Button("Connect to a peer") { connectingPeer = true }
                    .buttonStyle(RayfishButtonStyle(kind: .primary))
                    .disabled(!controller.isConnected || controller.isLoading)
            }
            if let identity = controller.status?.identity {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Your identity").font(RayfishTheme.heading(14)).foregroundColor(RayfishTheme.ink)
                        Text(identity).font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.muted)
                            .lineLimit(1).truncationMode(.middle)
                            .textSelection(.enabled)
                    }
                    Spacer()
                    Button("Copy") {
                        controller.copyToClipboard(identity, label: "Copied identity")
                    }
                    .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .compact))
                    .help("Share this ID so another peer can request a connection.")
                }.padding(14).rayfishCard()
            }
            if let requests = controller.status?.connectionRequests, !requests.isEmpty {
                Text("Connection requests").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
                VStack(spacing: 0) {
                    ForEach(Array(requests.enumerated()), id: \.element.id) { index, request in
                        if index > 0 { Rectangle().fill(RayfishTheme.line).frame(height: 1) }
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(request.hostname ?? request.id).foregroundColor(RayfishTheme.ink)
                                Text("\(request.id), waiting \(request.waitingSecs)s")
                                    .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.muted)
                            }
                            Spacer()
                            Button("Block", role: .destructive) { Task { await controller.blockConnection(id: request.id) } }
                                .buttonStyle(RayfishButtonStyle(kind: .danger, size: .compact))
                                .help("Deny and block this identity. Unblock it in Settings.")
                            Button("Deny") { Task { await controller.rejectConnection(id: request.id) } }
                                .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .compact))
                                .help("Deny this request. The peer can ask again.")
                            Button("Approve") { Task { await controller.approveConnection(id: request.id) } }
                                .buttonStyle(RayfishButtonStyle(kind: .primary, size: .compact))
                        }.padding(14)
                    }
                }.rayfishCard().disabled(controller.isLoading)
            }
            HStack {
                Text("Machines you control").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
                Spacer()
                if controller.isRefreshingMachines { ProgressView().controlSize(.small) }
                Button("Refresh") { controller.refreshMachines() }
                    .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .compact))
                    .disabled(!controller.isConnected || controller.isRefreshingMachines || controller.isLoading)
            }
            if let error = controller.machinesError {
                Text(error).foregroundColor(RayfishTheme.amber).textSelection(.enabled)
            }
            if !controller.isConnected {
                EmptyState(title: "Connect to see your machines.", description: "Enrolled machines are kept while disconnected.")
            } else if controller.isRefreshingMachines && controller.machines.isEmpty {
                EmptyState(title: "Checking your machines...", description: "Offline machines may take a few seconds to report.")
            } else if controller.machines.isEmpty && controller.machinesError == nil {
                EmptyState(title: "No enrolled machines.", description: "Use ray machines enroll to add a machine you control.")
            } else if !controller.machines.isEmpty {
                VStack(spacing: 0) {
                    ForEach(Array(controller.machines.enumerated()), id: \.element.id) { index, machine in
                        if index > 0 { Rectangle().fill(RayfishTheme.line).frame(height: 1) }
                        MachineRow(
                            machine: machine,
                            copyText: { value, label in controller.copyToClipboard(value, label: label) }
                        ).padding(14)
                    }
                }.rayfishCard()
            }

            HStack(spacing: 10) {
                Text("Network peers").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
                if !allPeers.isEmpty {
                    Text("\(allPeers.count)")
                        .font(RayfishTheme.mono(11))
                        .foregroundColor(RayfishTheme.faint)
                }
                Spacer()
                if allPeers.count >= 5 {
                    Button(activeOnly ? "Showing active" : "Active only") {
                        activeOnly.toggle()
                    }
                    .buttonStyle(RayfishButtonStyle(kind: activeOnly ? .connected : .secondary, size: .compact))
                }
            }
            if allPeers.count >= 5 {
                RayfishSearchField(prompt: "Filter peers by name, .ray domain, or IPv6...", text: $peerFilter)
            }
            if allPeers.isEmpty {
                EmptyState(title: "No devices to show.", description: "Devices appear here once this Mac joins a network.")
            } else if filteredPeers.isEmpty {
                EmptyState(title: "No matching peers.", description: "Clear the search or active filter to see all devices.")
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(filteredPeers.enumerated()), id: \.element.id) { index, peer in
                        if index > 0 { Rectangle().fill(RayfishTheme.line).frame(height: 1) }
                        PeerRow(
                            peer: peer,
                            domains: domains(for: peer),
                            copyText: { value, label in controller.copyToClipboard(value, label: label) }
                        )
                    }
                }.rayfishCard()
            }
        }
        .sheet(isPresented: $connectingPeer) { ConnectPeerSheet(controller: controller) }
    }
}

private struct MachineRow: View {
    let machine: ProviderMachine
    let copyText: (String, String) -> Void

    private var color: Color {
        switch machine.state {
        case "online": RayfishTheme.green
        case "unauthorized": RayfishTheme.amber
        default: RayfishTheme.faint
        }
    }

    var body: some View {
        HStack(spacing: 12) {
            Circle().fill(color).frame(width: 7, height: 7)
            VStack(alignment: .leading, spacing: 4) {
                Text(machine.hostname).foregroundColor(RayfishTheme.ink)
                Text(machine.ipv6).font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.muted)
                Text(machine.networks.isEmpty ? (machine.state == "online" ? "No networks" : "Networks unavailable") : machine.networks.joined(separator: ", "))
                    .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.faint)
            }
            Spacer()
            Text(machine.state).font(RayfishTheme.mono(12)).foregroundColor(color)
        }
        .contextMenu {
            Button("Copy IP address") { copyText(machine.ipv6, "Copied IPv6 address") }
            Button("Copy identity") { copyText(machine.identity, "Copied machine identity") }
        }
    }
}

private struct ConnectPeerSheet: View {
    @ObservedObject var controller: TunnelController
    @Environment(\.dismiss) private var dismiss
    @State private var peerIdentity = ""
    @State private var hostname = ""
    @State private var message: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Connect to a peer").font(RayfishTheme.heading(18))
            Text("Paste their identity. They must approve the request before a private network is created.")
                .foregroundColor(RayfishTheme.muted)
            TextField("Identity or nearby peer ID", text: $peerIdentity)
                .font(RayfishTheme.mono(12))
                .disabled(controller.isLoading || message != nil)
            TextField("This Mac's name (optional)", text: $hostname)
                .disabled(controller.isLoading || message != nil)
            if let message { Text(message).foregroundColor(RayfishTheme.green) }
            if let error = controller.error { Text(error).foregroundColor(RayfishTheme.amber) }
            HStack {
                if controller.isLoading { ProgressView().controlSize(.small) }
                Spacer()
                Button(message == nil ? "Cancel" : "Done") { dismiss() }
                    .disabled(controller.isLoading)
                if message == nil {
                    Button("Send request") {
                        Task {
                            let name = hostname.trimmingCharacters(in: .whitespacesAndNewlines)
                            message = await controller.connectPeer(
                                id: peerIdentity.trimmingCharacters(in: .whitespacesAndNewlines),
                                hostname: name.isEmpty ? nil : name)
                        }
                    }.buttonStyle(RayfishButtonStyle(kind: .primary))
                        .disabled(peerIdentity.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || controller.isLoading || !controller.isConnected)
                }
            }
        }.rayfishSheet().frame(width: 480)
            .interactiveDismissDisabled(controller.isLoading)
    }
}

private struct SendInviteSheet: View {
    @ObservedObject var controller: TunnelController
    let network: ProviderNetwork
    @Environment(\.dismiss) private var dismiss
    @State private var recipient = ""
    @State private var message: String?

    private var trimmed: String { recipient.trimmingCharacters(in: .whitespacesAndNewlines) }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Invite to \(network.name)").font(RayfishTheme.heading(18))
            Text("Paste their identity. The invite goes straight to their device, and they choose whether to join. If they are offline, Rayfish keeps trying for seven days.")
                .foregroundColor(RayfishTheme.muted)
            TextField("Identity", text: $recipient)
                .font(RayfishTheme.mono(12))
                .disabled(controller.isLoading || message != nil)
            if let message { Text(message).foregroundColor(RayfishTheme.green) }
            if let error = controller.error { Text(error).foregroundColor(RayfishTheme.amber) }
            HStack {
                if controller.isLoading { ProgressView().controlSize(.small) }
                Spacer()
                Button(message == nil ? "Cancel" : "Done") { dismiss() }
                    .disabled(controller.isLoading)
                if message == nil {
                    Button("Send invite") {
                        Task { message = await controller.sendInvite(network: network.name, recipient: trimmed) }
                    }.buttonStyle(RayfishButtonStyle(kind: .primary))
                        .disabled(trimmed.isEmpty || controller.isLoading || !controller.isConnected)
                }
            }
        }.rayfishSheet().frame(width: 480)
            .interactiveDismissDisabled(controller.isLoading)
    }
}

private struct InboundSettingsView: View {
    @ObservedObject var controller: TunnelController
    @State private var blockInput = ""

    private var trimmed: String { blockInput.trimmingCharacters(in: .whitespacesAndNewlines) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Who can reach you").font(RayfishTheme.heading(15)).foregroundColor(RayfishTheme.ink)
                Spacer()
                Picker("Who can reach you", selection: Binding(
                    get: { controller.status?.inboundPolicy ?? .anyone },
                    set: { policy in Task { await controller.setInboundPolicy(policy) } }
                )) {
                    Text("Anyone").tag(ProviderInboundPolicy.anyone)
                    Text("People in my networks").tag(ProviderInboundPolicy.known)
                    Text("Nobody").tag(ProviderInboundPolicy.nobody)
                }
                .labelsHidden()
                .pickerStyle(.menu)
                .frame(width: 200)
            }
            Text("Who may send you connection requests and network invitations. Blocked identities are always refused.")
                .font(RayfishTheme.text(13))
                .foregroundColor(RayfishTheme.muted)
            Rectangle().fill(RayfishTheme.line).frame(height: 1)
            Text("Blocked identities").font(RayfishTheme.heading(14)).foregroundColor(RayfishTheme.ink)
            let blocked = controller.status?.blocked ?? []
            if blocked.isEmpty {
                Text("Nobody is blocked.").font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.faint)
            }
            ForEach(blocked, id: \.self) { identity in
                HStack {
                    Text(identity).font(RayfishTheme.mono(11)).lineLimit(1).truncationMode(.middle)
                        .textSelection(.enabled)
                    Spacer()
                    Button("Unblock") { Task { await controller.unblockPeer(identity) } }
                        .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .compact))
                }
            }
            HStack(spacing: 8) {
                TextField("Identity to block", text: $blockInput)
                    .textFieldStyle(RayfishFieldStyle())
                    .font(RayfishTheme.mono(12))
                Button("Block") {
                    Task {
                        await controller.blockPeer(trimmed)
                        if controller.error == nil { blockInput = "" }
                    }
                }
                .buttonStyle(RayfishButtonStyle(kind: .danger))
                .disabled(trimmed.isEmpty)
            }
            if controller.status == nil {
                Text("Connect to view and change these settings.")
                    .font(RayfishTheme.text(13))
                    .foregroundColor(RayfishTheme.faint)
            }
        }
        .disabled(controller.status == nil || controller.isLoading)
        .padding(18).rayfishCard()
    }
}

private struct SettingsView: View {
    @ObservedObject var controller: TunnelController
    let updater: SPUUpdater?
    @State private var shellCommandResult: Result<URL, Error>?
    @State private var automaticUpdatesEnabled = false
    @State private var engineNeedsReconnect = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Settings").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)

            sectionLabel("GENERAL")
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("Rayfish version").foregroundColor(RayfishTheme.ink)
                    Spacer()
                    Text(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Unknown")
                        .font(RayfishTheme.mono(12)).foregroundColor(RayfishTheme.muted)
                }
                if let updater {
                    Rectangle().fill(RayfishTheme.line).frame(height: 1)
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Automatically update Rayfish").foregroundColor(RayfishTheme.ink)
                            Text("Updates download in the background. Restart when notified, or they install when you quit.")
                                .font(RayfishTheme.text(13))
                                .foregroundColor(RayfishTheme.muted)
                        }
                        Spacer()
                        Toggle("Automatically update Rayfish", isOn: Binding(
                            get: { automaticUpdatesEnabled },
                            set: { enabled in
                                updater.automaticallyChecksForUpdates = enabled
                                updater.automaticallyDownloadsUpdates = enabled
                                automaticUpdatesEnabled = enabled
                            }
                        ))
                        .labelsHidden()
                        .toggleStyle(.switch)
                    }
                }
                Rectangle().fill(RayfishTheme.line).frame(height: 1)
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Start at login").foregroundColor(RayfishTheme.ink)
                        Text("Open Rayfish and connect after you sign in.")
                            .font(RayfishTheme.text(13))
                            .foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    Toggle("Start at login", isOn: Binding(
                        get: { controller.launchAtLoginEnabled },
                        set: { controller.setLaunchAtLogin($0) }
                    ))
                    .labelsHidden()
                    .toggleStyle(.switch)
                }
            }
            .padding(18).rayfishCard()
            .onAppear {
                automaticUpdatesEnabled = updater?.automaticallyChecksForUpdates == true
                    && updater?.automaticallyDownloadsUpdates == true
            }

            sectionLabel("CONNECTION & ROUTING")
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("VPN tunnel").foregroundColor(RayfishTheme.ink)
                        Text("Managed by the Rayfish system extension.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    RayfishBadge(
                        text: controller.connectionLabel.uppercased(),
                        tone: controller.isConnected ? .success : .neutral
                    )
                }
                Rectangle().fill(RayfishTheme.line).frame(height: 1)
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Magic DNS").foregroundColor(RayfishTheme.ink)
                        Text("Resolve device names ending in .ray.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    Toggle("Magic DNS", isOn: Binding(
                        get: { controller.status?.dnsEnabled ?? false },
                        set: { enabled in Task { await controller.setSetting(.dns, enabled: enabled) } }
                    ))
                    .labelsHidden()
                }
                Rectangle().fill(RayfishTheme.line).frame(height: 1)
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("mDNS discovery").foregroundColor(RayfishTheme.ink)
                        Text("Discover peers on your local network.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                        if let status = controller.status, status.mdnsEnabled && !status.mdnsActive {
                            Text("mDNS discovery is not running. Check Rayfish logs.")
                                .font(RayfishTheme.text(12)).foregroundColor(RayfishTheme.amber)
                        }
                    }
                    Spacer()
                    Toggle("mDNS discovery", isOn: Binding(
                        get: { controller.status?.mdnsEnabled ?? false },
                        set: { enabled in Task { await controller.setSetting(.mdns, enabled: enabled) } }
                    ))
                    .labelsHidden()
                }
                Rectangle().fill(RayfishTheme.line).frame(height: 1)
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("QUIC engine").foregroundColor(RayfishTheme.ink)
                        Text("Standalone sends packets directly. FQ-CoDel is experimental and gives small transfers a turn alongside bulk traffic.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    Picker("QUIC engine", selection: Binding(
                        get: { controller.status?.quicFqCodel ?? false },
                        set: { enabled in
                            Task {
                                await controller.setSetting(.quicFqCodel, enabled: enabled)
                                engineNeedsReconnect = controller.error == nil
                            }
                        }
                    )) {
                        Text("Standalone").tag(false)
                        Text("FQ-CoDel").tag(true)
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                    .frame(width: 150)
                }
                if engineNeedsReconnect {
                    HStack {
                        Text("Reconnect to apply this change.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.amber)
                        Spacer()
                        Button("Reconnect now") {
                            engineNeedsReconnect = false
                            Task { await controller.reconnect() }
                        }
                        .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .compact))
                    }
                }
                if controller.status == nil {
                    Text("Connect to view and change connection settings.")
                        .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.faint)
                }
            }
            .toggleStyle(.switch)
            .disabled(controller.status == nil || controller.isLoading)
            .padding(18).rayfishCard()

            sectionLabel("ACCESS & PRIVACY")
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Mesh firewall").font(RayfishTheme.heading(15)).foregroundColor(RayfishTheme.ink)
                    Text("Configure per-network rules, general cross-network rules, and default policies.")
                        .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                }
                Spacer()
                Button("Open Firewall") {
                    controller.openFirewall()
                }
                .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .compact))
            }
            .padding(18).rayfishCard()

            InboundSettingsView(controller: controller)
            SSHSettingsView(controller: controller)

            sectionLabel("TOOLS")
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Command line").font(RayfishTheme.heading(15)).foregroundColor(RayfishTheme.ink)
                        Text("Make ray and tab completion available in new \(ShellCommandInstaller.shellName()) terminals.")
                            .font(RayfishTheme.text(13)).foregroundColor(RayfishTheme.muted)
                    }
                    Spacer()
                    Button("Install shell command") {
                        shellCommandResult = Result { try ShellCommandInstaller.install() }
                    }
                }
                Text("ray status").font(RayfishTheme.mono(12)).foregroundColor(RayfishTheme.rose)
                switch shellCommandResult {
                case let .success(config)?:
                    Label("Installed in ~/\(config.lastPathComponent). Open a new terminal to use ray.", systemImage: "checkmark.circle.fill")
                        .font(RayfishTheme.text(13))
                        .foregroundColor(RayfishTheme.green)
                case let .failure(error)?:
                    Label(error.localizedDescription, systemImage: "exclamationmark.triangle.fill")
                        .font(RayfishTheme.text(13))
                        .foregroundColor(RayfishTheme.amber)
                case nil:
                    EmptyView()
                }
            }.padding(18).rayfishCard()

            if LegacyDaemon.isInstalled {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Existing installation").font(RayfishTheme.heading(15)).foregroundColor(RayfishTheme.ink)
                    Text("Your identity and networks are imported automatically from the old Rayfish service. The old service is stopped and its original data is kept.")
                        .font(RayfishTheme.text(13))
                        .foregroundColor(RayfishTheme.muted)
                }.padding(18).frame(maxWidth: .infinity, alignment: .leading).rayfishCard()
            }
        }
    }

    private func sectionLabel(_ title: String) -> some View {
        Text(title)
            .font(RayfishTheme.mono(10))
            .tracking(1.2)
            .foregroundColor(RayfishTheme.faint)
            .padding(.top, 4)
    }
}

private struct RenameHostSheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var controller: TunnelController
    let network: ProviderNetwork
    @State private var hostname: String
    init(controller: TunnelController, network: ProviderNetwork) {
        self.controller = controller
        self.network = network
        _hostname = State(initialValue: network.hostname)
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Rename this Mac").font(RayfishTheme.heading(18))
            Text("\(hostname).\(network.name).ray").font(RayfishTheme.mono()).foregroundColor(RayfishTheme.muted)
            TextField("Hostname", text: $hostname)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") {
                    Task {
                        await controller.setHostname(network: network.name, hostname: hostname)
                        if controller.error == nil { dismiss() }
                    }
                }.buttonStyle(RayfishButtonStyle(kind: .primary)).disabled(hostname.isEmpty || controller.isLoading)
            }
        }.rayfishSheet().frame(width: 420)
    }
}
