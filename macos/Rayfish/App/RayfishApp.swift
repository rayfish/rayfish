import AppKit
import SwiftUI

@main
struct RayfishApp: App {
    @NSApplicationDelegateAdaptor(RayfishAppDelegate.self) private var appDelegate

    init() { RayfishTheme.registerFonts() }

    var body: some Scene {
        Settings { EmptyView() }
        .commands {
            CommandGroup(replacing: .appSettings) {}
            CommandGroup(replacing: .newItem) {
                Button("Open Rayfish") { appDelegate.openMainWindow() }
                    .keyboardShortcut("o", modifiers: .command)
            }
        }
    }
}

@MainActor
final class RayfishAppDelegate: NSObject, NSApplicationDelegate {
    private let controller = TunnelController()
    private var mainWindow: RayfishWindow?
    private var statusMenu: RayfishMenu?
    private var isTerminating = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        controller.notifications.install()
        controller.notifications.onOpen = { [weak self] page in
            self?.controller.page = page
            self?.openMainWindow()
        }
        statusMenu = RayfishMenu(controller: controller) { [weak self] in
            self?.openMainWindow()
        }
        openMainWindow()
    }

    func openMainWindow() {
        if mainWindow == nil {
            mainWindow = RayfishWindow(content: NSHostingView(rootView: ContentView(controller: controller)))
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
            let stopped = await controller.prepareToQuit()
            isTerminating = false
            if !stopped { openMainWindow() }
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

    private var connected: Bool { controller.isConnected }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header
                if let status = controller.status {
                    HStack(spacing: 18) {
                        HStack(spacing: 6) {
                            Text(status.ipv6)
                            Button {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(status.ipv6, forType: .string)
                            } label: {
                                Image(systemName: "doc.on.doc")
                            }
                            .buttonStyle(.plain)
                            .help("Copy IP address")
                            .accessibilityLabel("Copy this Mac's IP address")
                        }
                        Text("\(status.networks.count) networks")
                        Text("\(status.networks.reduce(0) { $0 + $1.peers.count }) peers")
                    }
                    .font(RayfishTheme.mono())
                    .foregroundColor(RayfishTheme.muted)
                }
                if let activity = controller.activity {
                    HStack(spacing: 10) {
                        ProgressView().controlSize(.small)
                        Text(activity)
                    }
                    .foregroundColor(RayfishTheme.muted)
                }
                if let error = controller.error {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: "exclamationmark.triangle")
                        Text(error).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    }
                    .font(RayfishTheme.text(14))
                    .foregroundColor(RayfishTheme.amber)
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RayfishTheme.amber.opacity(0.04))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(RayfishTheme.amber.opacity(0.25)))
                }
                switch controller.page {
                case .networks:
                    NetworksView(controller: controller)
                case .devices:
                    DevicesView(controller: controller)
                case .files:
                    FilesView(controller: controller)
                case .settings:
                    SettingsView(controller: controller)
                }
                Spacer(minLength: 24)
            }
            .padding(28)
            .frame(maxWidth: 976)
            .frame(maxWidth: .infinity)
        }
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
        VStack(spacing: 20) {
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
            HStack(spacing: 22) {
                ForEach(RayfishPage.allCases, id: \.self) { item in
                    Button { controller.page = item } label: {
                        Text(item.rawValue)
                            .font(RayfishTheme.heading(14))
                            .foregroundColor(controller.page == item ? RayfishTheme.ink : RayfishTheme.faint)
                            .padding(.bottom, 10)
                            .overlay(alignment: .bottom) {
                                Rectangle().fill(controller.page == item ? RayfishTheme.accent : .clear).frame(height: 2)
                            }
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(controller.page == item ? .isSelected : [])
                }
                Spacer()
                Text("PRIVATE MESH").font(RayfishTheme.mono(10)).tracking(1.4)
                    .foregroundColor(RayfishTheme.faint).padding(.bottom, 10)
            }
            .overlay(alignment: .bottom) { Rectangle().fill(RayfishTheme.line).frame(height: 1) }
        }
    }
}

private struct NetworksView: View {
    @ObservedObject var controller: TunnelController
    @State private var networkAction: NetworkAction?
    @State private var inviteCode: String?
    @State private var leavingNetwork: ProviderNetwork?
    @State private var renamingNetwork: ProviderNetwork?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let status = controller.status, !status.pendingRequests.isEmpty {
                Text("Needs attention").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
                VStack(spacing: 0) {
                    ForEach(status.pendingRequests) { request in
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("\(request.hostname ?? request.id) wants to join \(request.network)")
                                Text("Waiting \(request.waitingSecs)s")
                                    .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.faint)
                            }
                            Spacer()
                            Button("Deny", role: .destructive) { Task { await controller.deny(request: request) } }
                            Button("Approve") { Task { await controller.accept(request: request) } }
                                .buttonStyle(RayfishButtonStyle(kind: .primary))
                        }
                        .padding(14)
                    }
                }.rayfishCard()
            }
            HStack(spacing: 8) {
                Text("Networks").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
                Spacer()
                Button("Join with a code") { networkAction = .join }
                Button("Create a network") { networkAction = .create }
                    .buttonStyle(RayfishButtonStyle(kind: .primary))
            }
            .disabled(controller.isLoading)
            if let status = controller.status, !status.networks.isEmpty {
                ForEach(status.networks) { network in
                    NetworkCard(
                        network: network,
                        invite: { Task { inviteCode = await controller.invite(network: network.name) } },
                        leave: { leavingNetwork = network },
                        rename: { renamingNetwork = network }
                    )
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
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(inviteCode, forType: .string)
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
        .sheet(item: $networkAction) { action in NetworkSheet(controller: controller, action: action) }
    }
}

private struct NetworkCard: View {
    let network: ProviderNetwork
    let invite: () -> Void
    let leave: () -> Void
    let rename: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 8) {
                        Text(network.name).font(RayfishTheme.heading(16)).foregroundColor(RayfishTheme.ink)
                        Text(network.role.uppercased())
                            .font(RayfishTheme.mono(9)).tracking(0.8)
                            .foregroundColor(network.role == "coordinator" ? RayfishTheme.rose : RayfishTheme.muted)
                            .padding(.horizontal, 8).padding(.vertical, 3)
                            .overlay(Capsule().stroke(RayfishTheme.border))
                    }
                    Text("\(network.hostname).\(network.name).ray")
                        .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.faint)
                        .textSelection(.enabled)
                }
                Spacer()
                if network.role == "coordinator" { Button("Invite", action: invite) }
                Button("Rename", action: rename)
                Button("Leave", role: .destructive, action: leave)
                    .buttonStyle(RayfishButtonStyle(kind: .danger))
            }
            .padding(14)
            ForEach(network.peers) { peer in
                Rectangle().fill(RayfishTheme.line).frame(height: 1)
                PeerRow(peer: peer, domains: [peer.domain(in: network.name)])
                    .padding(.horizontal, 14).padding(.vertical, 11)
            }
            if network.peers.isEmpty {
                Rectangle().fill(RayfishTheme.line).frame(height: 1)
                Text("Waiting for peers...").font(RayfishTheme.mono(12))
                    .foregroundColor(RayfishTheme.faint).padding(18)
            }
        }
        .rayfishCard()
    }
}

private struct PeerRow: View {
    let peer: ProviderPeer
    let domains: [String]
    private var color: Color {
        peer.state == "direct" ? RayfishTheme.green : peer.state == "relay" ? RayfishTheme.amber : RayfishTheme.faint
    }
    var body: some View {
        HStack(spacing: 12) {
            Circle().fill(color).frame(width: 7, height: 7)
            Text(peer.hostname).foregroundColor(RayfishTheme.ink).frame(minWidth: 110, alignment: .leading)
            if peer.isOwnDevice {
                Text("YOU").font(RayfishTheme.mono(9)).foregroundColor(RayfishTheme.faint)
                    .padding(.horizontal, 5).padding(.vertical, 2)
                    .overlay(RoundedRectangle(cornerRadius: 4).stroke(RayfishTheme.border))
            }
            Text(peer.ipv6).foregroundColor(RayfishTheme.muted).lineLimit(1)
            Spacer(minLength: 8)
            Text(peer.state).foregroundColor(color)
            if let latency = peer.latencyMs { Text("\(latency) ms").foregroundColor(RayfishTheme.faint) }
        }
        .font(RayfishTheme.mono(12))
        .contextMenu {
            ForEach(domains, id: \.self) { domain in
                Button("Copy \(domain)") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(domain, forType: .string)
                }
            }
        }
    }
}

private struct DevicesView: View {
    @ObservedObject var controller: TunnelController
    @State private var connectingPeer = false
    private var peers: [ProviderPeer] {
        let all = controller.status?.networks.flatMap { $0.peers } ?? []
        return Dictionary(all.map { ($0.ipv6, $0) }, uniquingKeysWith: { first, _ in first })
            .values.sorted { $0.hostname < $1.hostname }
    }
    private func domains(for peer: ProviderPeer) -> [String] {
        (controller.status?.networks ?? []).compactMap { network in
            network.peers.first { $0.ipv6 == peer.ipv6 }?.domain(in: network.name)
        }.sorted()
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Devices").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
                Spacer()
                Button("Connect to a peer") { connectingPeer = true }
                    .buttonStyle(RayfishButtonStyle(kind: .primary))
                    .disabled(!controller.isConnected || controller.isLoading)
            }
            if let contactId = controller.status?.contactId {
                HStack(spacing: 12) {
                    Text("Your contact ID").foregroundColor(RayfishTheme.muted)
                    Text(contactId).font(RayfishTheme.mono(11)).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Button("Copy") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(contactId, forType: .string)
                    }.help("Share this ID so another peer can request a connection.")
                }.padding(14).rayfishCard()
            }
            if let requests = controller.status?.connectionRequests, !requests.isEmpty {
                Text("Connection requests").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
                VStack(spacing: 0) {
                    ForEach(requests) { request in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(request.hostname ?? request.id)
                                Text("\(request.id), waiting \(request.waitingSecs)s")
                                    .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.muted)
                            }
                            Spacer()
                            Button("Deny", role: .destructive) { Task { await controller.rejectConnection(id: request.id) } }
                            Button("Approve") { Task { await controller.approveConnection(id: request.id) } }
                                .buttonStyle(RayfishButtonStyle(kind: .primary))
                        }.padding(14)
                    }
                }.rayfishCard().disabled(controller.isLoading)
            }
            HStack {
                Text("Machines you control").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
                Spacer()
                if controller.isRefreshingMachines { ProgressView().controlSize(.small) }
                Button("Refresh") { controller.refreshMachines() }
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
                    ForEach(controller.machines) { machine in
                        MachineRow(machine: machine).padding(14)
                        Rectangle().fill(RayfishTheme.line).frame(height: 1)
                    }
                }.rayfishCard()
            }
            Text("Network peers").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
            if peers.isEmpty {
                EmptyState(title: "No devices to show.", description: "Devices appear here once this Mac joins a network.")
            } else {
                VStack(spacing: 0) {
                    ForEach(peers) { peer in
                        PeerRow(peer: peer, domains: domains(for: peer)).padding(14)
                        Rectangle().fill(RayfishTheme.line).frame(height: 1)
                    }
                }.rayfishCard()
            }
        }
        .sheet(isPresented: $connectingPeer) { ConnectPeerSheet(controller: controller) }
    }
}

private struct MachineRow: View {
    let machine: ProviderMachine
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
            VStack(alignment: .leading, spacing: 5) {
                Text(machine.hostname).foregroundColor(RayfishTheme.ink)
                Text(machine.ipv6).font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.muted)
                Text(machine.networks.isEmpty ? (machine.state == "online" ? "No networks" : "Networks unavailable") : machine.networks.joined(separator: ", "))
                    .font(RayfishTheme.mono(11)).foregroundColor(RayfishTheme.faint)
            }
            Spacer()
            Text(machine.state).font(RayfishTheme.mono(12)).foregroundColor(color)
        }
        .contextMenu {
            Button("Copy IP address") { copy(machine.ipv6) }
            Button("Copy identity") { copy(machine.identity) }
        }
    }
    private func copy(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }
}

private struct ConnectPeerSheet: View {
    @ObservedObject var controller: TunnelController
    @Environment(\.dismiss) private var dismiss
    @State private var contactId = ""
    @State private var hostname = ""
    @State private var message: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Connect to a peer").font(RayfishTheme.heading(18))
            Text("Paste their contact ID. They must approve the request before a private network is created.")
                .foregroundColor(RayfishTheme.muted)
            TextField("Contact ID or nearby peer ID", text: $contactId)
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
                                id: contactId.trimmingCharacters(in: .whitespacesAndNewlines),
                                hostname: name.isEmpty ? nil : name)
                        }
                    }.buttonStyle(RayfishButtonStyle(kind: .primary))
                        .disabled(contactId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || controller.isLoading || !controller.isConnected)
                }
            }
        }.rayfishSheet().frame(width: 480)
            .interactiveDismissDisabled(controller.isLoading)
    }
}

private struct EmptyState: View {
    let title: String
    let description: String
    var body: some View {
        VStack(spacing: 10) {
            Text(title).font(RayfishTheme.text(16)).foregroundColor(RayfishTheme.muted)
            Text(description).font(RayfishTheme.text(14)).foregroundColor(RayfishTheme.faint)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
        .rayfishCard()
    }
}

private struct SettingsView: View {
    @ObservedObject var controller: TunnelController
    @State private var shellCommandMessage: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Settings").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
            SSHSettingsView(controller: controller)
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("VPN").font(RayfishTheme.heading(15))
                    Spacer()
                    Text(controller.connectionLabel)
                        .font(RayfishTheme.mono(12)).foregroundColor(RayfishTheme.muted)
                }
                Text("The Rayfish system extension manages your connection.").foregroundColor(RayfishTheme.muted)
            }.padding(18).rayfishCard()
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("Start at login")
                    Spacer()
                    Toggle("Start at login", isOn: Binding(
                        get: { controller.launchAtLoginEnabled },
                        set: { controller.setLaunchAtLogin($0) }
                    ))
                    .labelsHidden()
                }
                Text("Open Rayfish and connect after you sign in.").foregroundColor(RayfishTheme.muted)
            }
            .toggleStyle(.switch)
            .padding(18).rayfishCard()
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("Magic DNS")
                    Spacer()
                    Toggle("Magic DNS", isOn: Binding(
                        get: { controller.status?.dnsEnabled ?? false },
                        set: { enabled in Task { await controller.setSetting(.dns, enabled: enabled) } }
                    ))
                    .labelsHidden()
                }
                Text("Resolve device names ending in .ray.").foregroundColor(RayfishTheme.muted)
                Rectangle().fill(RayfishTheme.line).frame(height: 1)
                HStack {
                    Text("mDNS discovery")
                    Spacer()
                    Toggle("mDNS discovery", isOn: Binding(
                        get: { controller.status?.mdnsEnabled ?? false },
                        set: { enabled in Task { await controller.setSetting(.mdns, enabled: enabled) } }
                    ))
                    .labelsHidden()
                }
                Text("Discover peers on your local network. Changing this briefly reconnects the VPN.")
                    .foregroundColor(RayfishTheme.muted)
                if let status = controller.status, status.mdnsEnabled != status.mdnsActive {
                    Button("Reconnect to apply mDNS") { Task { await controller.reconnect() } }
                }
                if controller.status == nil {
                    Text("Connect to view and change DNS settings.").foregroundColor(RayfishTheme.faint)
                }
            }
            .toggleStyle(.switch)
            .disabled(controller.status == nil || controller.isLoading)
            .padding(18).rayfishCard()
            VStack(alignment: .leading, spacing: 14) {
                Text("Command line").font(RayfishTheme.heading(15))
                Text("ray status").font(RayfishTheme.mono(13)).foregroundColor(RayfishTheme.rose)
                HStack {
                    Text("Make ray available in new \(ShellCommandInstaller.shellName()) terminals.")
                        .foregroundColor(RayfishTheme.muted)
                    Spacer()
                    Button("Install shell command") {
                        do {
                            let config = try ShellCommandInstaller.install()
                            shellCommandMessage = "Installed in \(config.lastPathComponent). Open a new terminal to use ray."
                        } catch { shellCommandMessage = error.localizedDescription }
                    }
                }
                if let shellCommandMessage { Text(shellCommandMessage).foregroundColor(RayfishTheme.muted) }
            }.padding(18).rayfishCard()
            VStack(alignment: .leading, spacing: 10) {
                Text("Existing installation").font(RayfishTheme.heading(15))
                Text("Your identity and networks are imported automatically from the old Rayfish service. The old service is stopped and its original data is kept.")
                    .foregroundColor(RayfishTheme.muted)
            }.padding(18).frame(maxWidth: .infinity, alignment: .leading).rayfishCard()
        }
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

private enum NetworkAction: String, Identifiable {
    case create = "Create", join = "Join"
    var id: Self { self }
}

private struct NetworkSheet: View {
    @ObservedObject var controller: TunnelController
    let action: NetworkAction
    @Environment(\.dismiss) private var dismiss
    @State private var input = ""
    @State private var hostname = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("\(action.rawValue) a network").font(RayfishTheme.heading(18))
            Text(action == .create ? "Only people you invite can join." : "Paste the invite code you received.")
                .foregroundColor(RayfishTheme.muted)
            if action == .create {
                TextField("Network name (optional)", text: $input)
            } else {
                TextEditor(text: $input)
                    .font(RayfishTheme.mono(12)).scrollContentBackground(.hidden)
                    .padding(8).frame(height: 100).background(RayfishTheme.deep)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(RayfishTheme.border))
            }
            TextField("This Mac's name (optional)", text: $hostname)
            if let error = controller.error { Text(error).foregroundColor(RayfishTheme.amber).font(RayfishTheme.text(13)) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button(action.rawValue) {
                    Task {
                        if controller.status == nil { await controller.connect() }
                        guard controller.status != nil else { return }
                        let requestedHostname = hostname.isEmpty ? nil : hostname
                        switch action {
                        case .create: await controller.create(name: input.isEmpty ? nil : input, hostname: requestedHostname)
                        case .join: await controller.join(code: input, hostname: requestedHostname)
                        }
                        if controller.error == nil { dismiss() }
                    }
                }.buttonStyle(RayfishButtonStyle(kind: .primary))
                    .disabled(controller.isLoading || (action == .join && input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty))
            }
        }.rayfishSheet().frame(width: action == .create ? 440 : 460)
    }
}
