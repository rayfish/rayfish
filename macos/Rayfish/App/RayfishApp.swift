import AppKit
import SwiftUI

@main
struct RayfishApp: App {
    @NSApplicationDelegateAdaptor(RayfishAppDelegate.self) private var appDelegate
    @StateObject private var controller = TunnelController()

    init() { RayfishTheme.registerFonts() }

    var body: some Scene {
        Window("Rayfish", id: "main") {
            ContentView(controller: controller)
                .environmentObject(appDelegate)
                .onAppear { appDelegate.controller = controller }
        }
        .defaultSize(width: 1000, height: 680)

        MenuBarExtra("Rayfish", image: "MenuBarIcon") {
            RayfishMenu(controller: controller)
                .onAppear { appDelegate.controller = controller }
        }
        .menuBarExtraStyle(.menu)
    }
}

@MainActor
final class RayfishAppDelegate: NSObject, NSApplicationDelegate, ObservableObject {
    var openMainWindow: (() -> Void)?
    weak var controller: TunnelController?
    private var isTerminating = false

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !isTerminating else { return .terminateLater }
        guard let controller else { return .terminateNow }
        isTerminating = true
        Task {
            let stopped = await controller.prepareToQuit()
            isTerminating = false
            if !stopped { openMainWindow?() }
            sender.reply(toApplicationShouldTerminate: stopped)
        }
        return .terminateLater
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openMainWindow?()
        return true
    }
}

private struct RayfishMenu: View {
    @Environment(\.openWindow) private var openWindow
    @ObservedObject var controller: TunnelController

    var body: some View {
        Group {
            Text("Rayfish: \(controller.connectionLabel.capitalized)")
            Button(controller.isConnected ? "Disconnect" : "Connect") {
                Task {
                    if controller.isConnected { await controller.disconnect() }
                    else { await controller.connect() }
                }
            }.disabled(controller.isLoading)

            if let status = controller.status {
                Button("Copy This Mac's IP Address") { copyAddress(status.ipv6) }
                    .help(status.ipv6)
                Divider()
                Section("Networks") {
                    if status.networks.isEmpty { Text("No networks yet") }
                    ForEach(status.networks) { network in
                        Menu("\(network.name) (\(network.peers.count) devices)") {
                            Text("\(network.hostname).\(network.name).ray")
                            Divider()
                            ForEach(network.peers) { peer in
                                Button {
                                    copyAddress(peer.ipv6)
                                } label: {
                                    Label("\(peer.hostname) (\(peer.state))",
                                          systemImage: peer.state == "idle" ? "circle" : "circle.fill")
                                }.help("Copy \(peer.ipv6)")
                            }
                        }
                    }
                }
            }
            if let activity = controller.activity {
                Divider()
                Text(activity)
            }
            if let error = controller.error {
                Divider()
                Button("Connection Issue: Open Rayfish") { showWindow() }
                    .help(error)
            }
            Divider()
            Button("Open Rayfish") { showWindow() }
                .keyboardShortcut("0", modifiers: .command)
            Button("Disconnect and Quit") { NSApp.terminate(nil) }
                .keyboardShortcut("q", modifiers: .command)
        }
        .task { await controller.startup() }
    }

    private func showWindow() {
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }

    private func copyAddress(_ address: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(address, forType: .string)
    }
}

private enum Page: String, CaseIterable {
    case networks = "Networks", devices = "Devices", settings = "Settings"
}

private struct ContentView: View {
    @Environment(\.openWindow) private var openWindow
    @EnvironmentObject private var appDelegate: RayfishAppDelegate
    @ObservedObject var controller: TunnelController
    @State private var page: Page = .networks
    @State private var showCreate = false
    @State private var showJoin = false

    private var connected: Bool { controller.isConnected }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header
                if let status = controller.status {
                    HStack(spacing: 18) {
                        Text(status.ipv6).textSelection(.enabled)
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
                switch page {
                case .networks:
                    NetworksView(controller: controller, showCreate: $showCreate, showJoin: $showJoin)
                case .devices:
                    DevicesView(controller: controller)
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
        .onAppear {
            appDelegate.openMainWindow = {
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }
        }
        .sheet(isPresented: $showCreate) { CreateNetworkSheet(controller: controller) }
        .sheet(isPresented: $showJoin) { JoinNetworkSheet(controller: controller) }
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
                ForEach(Page.allCases, id: \.self) { item in
                    Button { page = item } label: {
                        Text(item.rawValue)
                            .font(RayfishTheme.heading(14))
                            .foregroundColor(page == item ? RayfishTheme.ink : RayfishTheme.faint)
                            .padding(.bottom, 10)
                            .overlay(alignment: .bottom) {
                                Rectangle().fill(page == item ? RayfishTheme.accent : .clear).frame(height: 2)
                            }
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(page == item ? .isSelected : [])
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
    @Binding var showCreate: Bool
    @Binding var showJoin: Bool
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
                Button("Join with a code") { showJoin = true }
                Button("Create a network") { showCreate = true }
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
                PeerRow(peer: peer).padding(.horizontal, 14).padding(.vertical, 11)
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
            Text(peer.ipv6).foregroundColor(RayfishTheme.muted).lineLimit(1).textSelection(.enabled)
            Spacer(minLength: 8)
            Text(peer.state).foregroundColor(color)
            if let latency = peer.latencyMs { Text("\(latency) ms").foregroundColor(RayfishTheme.faint) }
        }
        .font(RayfishTheme.mono(12))
    }
}

private struct DevicesView: View {
    @ObservedObject var controller: TunnelController
    private var peers: [ProviderPeer] {
        let all = controller.status?.networks.flatMap { $0.peers } ?? []
        return Dictionary(all.map { ($0.ipv6, $0) }, uniquingKeysWith: { first, _ in first })
            .values.sorted { $0.hostname < $1.hostname }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Devices").font(RayfishTheme.heading()).foregroundColor(RayfishTheme.ink)
            if peers.isEmpty {
                EmptyState(title: "No devices to show.", description: "Devices appear here once this Mac joins a network.")
            } else {
                VStack(spacing: 0) {
                    ForEach(peers) { peer in
                        PeerRow(peer: peer).padding(14)
                        Rectangle().fill(RayfishTheme.line).frame(height: 1)
                    }
                }.rayfishCard()
            }
        }
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

private struct CreateNetworkSheet: View {
    @ObservedObject var controller: TunnelController
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var hostname = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Create a network").font(RayfishTheme.heading(18))
            Text("Only people you invite can join.").foregroundColor(RayfishTheme.muted)
            TextField("Network name (optional)", text: $name)
            TextField("This Mac's name (optional)", text: $hostname)
            if let error = controller.error { Text(error).foregroundColor(RayfishTheme.amber).font(RayfishTheme.text(13)) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Create") {
                    Task {
                        if controller.status == nil { await controller.connect() }
                        guard controller.status != nil else { return }
                        await controller.create(name: name.isEmpty ? nil : name, hostname: hostname.isEmpty ? nil : hostname)
                        if controller.error == nil { dismiss() }
                    }
                }.buttonStyle(RayfishButtonStyle(kind: .primary)).disabled(controller.isLoading)
            }
        }.rayfishSheet().frame(width: 440)
    }
}

private struct JoinNetworkSheet: View {
    @ObservedObject var controller: TunnelController
    @Environment(\.dismiss) private var dismiss
    @State private var code = ""
    @State private var hostname = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Join a network").font(RayfishTheme.heading(18))
            Text("Paste the invite code you received.").foregroundColor(RayfishTheme.muted)
            TextEditor(text: $code)
                .font(RayfishTheme.mono(12)).scrollContentBackground(.hidden)
                .padding(8).frame(height: 100).background(RayfishTheme.deep)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(RayfishTheme.border))
            TextField("This Mac's name (optional)", text: $hostname)
            if let error = controller.error { Text(error).foregroundColor(RayfishTheme.amber).font(RayfishTheme.text(13)) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Join") {
                    Task {
                        if controller.status == nil { await controller.connect() }
                        guard controller.status != nil else { return }
                        await controller.join(code: code, hostname: hostname.isEmpty ? nil : hostname)
                        if controller.error == nil { dismiss() }
                    }
                }.buttonStyle(RayfishButtonStyle(kind: .primary))
                    .disabled(code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || controller.isLoading)
            }
        }.rayfishSheet().frame(width: 460)
    }
}
