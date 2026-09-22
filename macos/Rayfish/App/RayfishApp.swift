import AppKit
import SwiftUI

@main
struct RayfishApp: App {
    var body: some Scene {
        MenuBarExtra("Rayfish", systemImage: "fish") {
            Button("Open Rayfish") {
                NSApp.activate(ignoringOtherApps: true)
            }
            Divider()
            Button("Quit Rayfish") {
                NSApp.terminate(nil)
            }
        }
        WindowGroup("Rayfish") {
            ContentView()
        }
    }
}

private struct ContentView: View {
    @StateObject private var controller = TunnelController()
    @State private var selection: SidebarItem? = .networks
    @State private var showCreate = false
    @State private var showJoin = false

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Section {
                    Label("Networks", systemImage: "circle.hexagongrid.fill")
                        .tag(SidebarItem.networks)
                    Label("Devices", systemImage: "desktopcomputer")
                        .tag(SidebarItem.devices)
                }
                Section {
                    Label("Settings", systemImage: "gearshape")
                        .tag(SidebarItem.settings)
                }
            }
            .navigationTitle("Rayfish")
        } detail: {
            switch selection ?? .networks {
            case .networks:
                NetworksView(controller: controller, showCreate: $showCreate, showJoin: $showJoin)
            case .devices:
                DevicesView(controller: controller)
            case .settings:
                SettingsView(controller: controller)
            }
        }
        .frame(minWidth: 820, minHeight: 560)
        .sheet(isPresented: $showCreate) {
            CreateNetworkSheet(controller: controller)
        }
        .sheet(isPresented: $showJoin) {
            JoinNetworkSheet(controller: controller)
        }
        .task {
            await controller.refresh()
            await controller.poll()
        }
    }
}

private enum SidebarItem: Hashable {
    case networks
    case devices
    case settings
}

private struct NetworksView: View {
    @ObservedObject var controller: TunnelController
    @Binding var showCreate: Bool
    @Binding var showJoin: Bool
    @State private var inviteCode: String?
    @State private var leavingNetwork: ProviderNetwork?
    @State private var renamingNetwork: ProviderNetwork?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 6) {
                        Label(controller.status?.active == true ? "Rayfish is connected" : "Rayfish is ready", systemImage: "checkmark.circle.fill")
                            .font(.title2.weight(.semibold))
                            .foregroundStyle(.green)
                        Text("Create a private network or join one with an invite code.")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button(controller.status?.active == true ? "Disconnect" : "Connect") {
                        Task {
                            if controller.status?.active == true {
                                await controller.disconnect()
                            } else {
                                await controller.connect()
                            }
                        }
                    }
                    .disabled(controller.isLoading)
                    Button("Join with a code") { showJoin = true }
                    Button("Create network") { showCreate = true }
                        .buttonStyle(.borderedProminent)
                }

                if let error = controller.error {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }

                if let status = controller.status, !status.pendingRequests.isEmpty {
                    GroupBox("Needs attention") {
                        ForEach(status.pendingRequests) { request in
                            HStack {
                                VStack(alignment: .leading) {
                                    Text("\(request.hostname ?? request.id) wants to join \(request.network)")
                                    Text("Waiting \(request.waitingSecs)s")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("Deny", role: .destructive) {
                                    Task { await controller.deny(request: request) }
                                }
                                Button("Approve") {
                                    Task { await controller.accept(request: request) }
                                }
                                .buttonStyle(.borderedProminent)
                            }
                            .padding(.vertical, 4)
                        }
                    }
                }

                if let status = controller.status, !status.networks.isEmpty {
                    ForEach(status.networks) { network in
                        NetworkCard(
                            network: network,
                            invite: { Task { inviteCode = await controller.invite(network: network.name) } },
                            leave: { leavingNetwork = network },
                            rename: { renamingNetwork = network }
                        )
                    }
                } else {
                    GroupBox {
                        EmptyState(
                            title: "No networks yet",
                            systemImage: "circle.hexagongrid",
                            description: "A network is a private space for the devices and people you invite."
                        )
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 48)
                    }
                }

                VStack(alignment: .leading, spacing: 8) {
                    Text("What happens next")
                        .font(.headline)
                    Label("Your Mac gets a stable private address.", systemImage: "checkmark")
                    Label("Invitees join with a one-time code.", systemImage: "checkmark")
                    Label("Names like laptop.home.ray work automatically.", systemImage: "checkmark")
                }
                .foregroundStyle(.secondary)
            }
            .padding(28)
        }
        .navigationTitle("Networks")
        .alert("Invite code", isPresented: Binding(
            get: { inviteCode != nil },
            set: { if !$0 { inviteCode = nil } }
        )) {
            Button("Copy") {
                if let inviteCode {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(inviteCode, forType: .string)
                }
            }
            Button("Done", role: .cancel) {}
        } message: {
            Text(inviteCode ?? "")
        }
        .confirmationDialog(
            "Leave \(leavingNetwork?.name ?? "network")?",
            isPresented: Binding(get: { leavingNetwork != nil }, set: { if !$0 { leavingNetwork = nil } })
        ) {
            Button("Leave network", role: .destructive) {
                if let leavingNetwork {
                    Task { await controller.leave(network: leavingNetwork.name) }
                }
                leavingNetwork = nil
            }
        } message: {
            Text("This Mac will lose access to the network until it joins again.")
        }
        .sheet(item: $renamingNetwork) { network in
            RenameHostSheet(controller: controller, network: network)
        }
    }
}

private struct NetworkCard: View {
    let network: ProviderNetwork
    let invite: () -> Void
    let leave: () -> Void
    let rename: () -> Void

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading) {
                        Text(network.name).font(.headline)
                        Text("\(network.hostname).\(network.name).ray")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Text(network.role.capitalized)
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                    if network.role == "coordinator" {
                        Button("Invite", action: invite)
                            .buttonStyle(.bordered)
                    }
                    Button("Rename", action: rename)
                        .buttonStyle(.bordered)
                    Button("Leave", role: .destructive, action: leave)
                        .buttonStyle(.bordered)
                }
                ForEach(network.peers) { peer in
                    HStack(spacing: 10) {
                        Circle().fill(peer.state == "direct" ? .green : .secondary).frame(width: 8, height: 8)
                        Text(peer.hostname)
                        if peer.isOwnDevice { Text("YOUR DEVICE").font(.caption2).foregroundStyle(.secondary) }
                        Spacer()
                        Text(peer.latencyMs.map { "\($0) ms" } ?? peer.state)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(4)
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
            Text("Rename this Mac")
                .font(.title2.weight(.semibold))
            Text("The new name will be \(hostname.isEmpty ? "available" : "\(hostname).\(network.name).ray").")
                .foregroundStyle(.secondary)
            TextField("Hostname", text: $hostname)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") {
                    Task {
                        await controller.setHostname(network: network.name, hostname: hostname)
                        if controller.error == nil { dismiss() }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(hostname.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 420)
    }
}

private struct DevicesView: View {
    @ObservedObject var controller: TunnelController

    var body: some View {
        Group {
            let allPeers = controller.status?.networks.flatMap { $0.peers } ?? []
            let peers = Array(
                Dictionary(
                    allPeers.map { ($0.ipv6, $0) },
                    uniquingKeysWith: { first, _ in first }
                ).values
            )
            if peers.isEmpty {
                EmptyState(
                    title: "No devices to show",
                    systemImage: "desktopcomputer",
                    description: "Devices appear here once this Mac joins a network."
                )
            } else {
                List(peers) { peer in
                    HStack(spacing: 12) {
                        Image(systemName: peer.isOwnDevice ? "laptopcomputer" : "desktopcomputer")
                            .foregroundStyle(peer.state == "direct" ? .green : .secondary)
                        VStack(alignment: .leading) {
                            Text(peer.hostname)
                            Text(peer.ipv6)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(peer.latencyMs.map { "\($0) ms" } ?? peer.state)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .navigationTitle("Devices")
    }
}

private struct EmptyState: View {
    let title: String
    let systemImage: String
    let description: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: systemImage)
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text(title)
                .font(.headline)
            Text(description)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(32)
    }
}

private struct SettingsView: View {
    @ObservedObject var controller: TunnelController
    @State private var legacyStateDirectory = ""

    var body: some View {
        Form {
            Section("VPN") {
                LabeledContent("Status") {
                    Text(controller.status?.active == true ? "Connected" : "Not connected")
                        .foregroundStyle(.secondary)
                }
                Text("The Rayfish system extension manages the VPN connection.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Section("Advanced") {
                LabeledContent("Command line") {
                    Text("ray status")
                        .fontDesign(.monospaced)
                }
            }
            Section("Migrate existing Rayfish") {
                Text("Stop the legacy Rayfish service first, then enter its state directory. Migration copies the identity and saved networks without changing the old state.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                TextField("Legacy state directory", text: $legacyStateDirectory)
                    .textFieldStyle(.roundedBorder)
                Button("Migrate and connect") {
                    Task {
                        await controller.connect(
                            legacyStateDirectory: legacyStateDirectory.trimmingCharacters(
                                in: .whitespacesAndNewlines
                            )
                        )
                    }
                }
                .disabled(legacyStateDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
    }
}

private struct CreateNetworkSheet: View {
    @ObservedObject var controller: TunnelController
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var hostname = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Create a network")
                .font(.title2.weight(.semibold))
            Text("Only people you invite can join.")
                .foregroundStyle(.secondary)
            TextField("Network name, optional", text: $name)
            TextField("This Mac's name, optional", text: $hostname)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Create") {
                    Task {
                        await controller.create(
                            name: name.isEmpty ? nil : name,
                            hostname: hostname.isEmpty ? nil : hostname
                        )
                        if controller.error == nil { dismiss() }
                    }
                }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(24)
        .frame(width: 420)
    }
}

private struct JoinNetworkSheet: View {
    @ObservedObject var controller: TunnelController
    @Environment(\.dismiss) private var dismiss
    @State private var code = ""
    @State private var hostname = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Join a network")
                .font(.title2.weight(.semibold))
            Text("Paste the invite code you received.")
                .foregroundStyle(.secondary)
            TextEditor(text: $code)
                .fontDesign(.monospaced)
                .frame(height: 100)
            TextField("This Mac's name, optional", text: $hostname)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Join") {
                    Task {
                        await controller.join(code: code, hostname: hostname.isEmpty ? nil : hostname)
                        if controller.error == nil { dismiss() }
                    }
                }
                    .buttonStyle(.borderedProminent)
                    .disabled(code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 460)
    }
}
