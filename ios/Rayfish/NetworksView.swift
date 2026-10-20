import SwiftUI

struct NetworksView: View {
    @EnvironmentObject private var model: AppModel
    @State private var adding = false
    @State private var invite: SharedCode?

    var body: some View {
        let networks = model.snapshot.networks
        let running = model.tunnelState == .on
        ScrollView {
            VStack(spacing: 12) {
                BrandHeader(title: "Networks") {
                    Button("Add") { adding = true }.buttonStyle(PillStyle()).font(Rf.semibold(14))
                        .frame(height: 34)
                }
                if networks.isEmpty {
                    SectionCard {
                        Text(model.loaded ? "No networks yet. Add one to get started." : "Starting…")
                            .font(Rf.text()).foregroundStyle(Rf.muted)
                        if model.loaded {
                            PillButton("Join or create a network") { adding = true }.padding(.top, 10)
                        }
                    }
                }
                ForEach(networks) { network in
                    NavigationLink(value: network.name) {
                        NetworkRow(network: network, running: running)
                    }
                    .buttonStyle(.plain)
                    .contextMenu {
                        if let domain = network.domain { Text(domain) }
                        Button("Invite") { Task { invite = await model.invite(network.name) } }
                        Button("Copy address") { model.copy(network.domain ?? network.ipv6, toast: "Address copied") }
                    }
                }
                ForEach(model.snapshot.pendingNetworks, id: \.self) { name in
                    SectionCard {
                        HStack(spacing: 10) {
                            Dot(color: Rf.faint)
                            VStack(alignment: .leading, spacing: 2) {
                                RowTitle(name)
                                RowSubtitle("waiting for approval")
                            }
                        }
                    }
                }
            }
            .padding(20)
        }
        .rayfishPage()
        .statusBarBackdrop()
        .toolbar(.hidden, for: .navigationBar)
        .navigationDestination(for: String.self) { name in
            NetworkDetailView(name: name)
        }
        .sheet(isPresented: $adding) { AddNetworkSheet() }
        .sheet(item: $invite) { CodeSheet(code: $0) }
    }
}

struct NetworkRow: View {
    var network: NetworkDetail
    var running: Bool

    var body: some View {
        SectionCard {
            HStack(spacing: 10) {
                Dot(color: dot)
                VStack(alignment: .leading, spacing: 2) {
                    RowTitle(network.name)
                    RowSubtitle("\(network.hostname.isEmpty ? "unknown" : network.hostname) · \(line)")
                }
                Spacer()
                Image(systemName: "chevron.right").font(.system(size: 13)).foregroundStyle(Rf.faint)
            }
        }
        .contentShape(Rectangle())
    }

    /// Amber while a saved network is restoring, red when it failed or the
    /// tunnel is off, green once a peer is reachable, grey when nobody is.
    private var dot: Color {
        if network.state == .connecting { return Rf.amber }
        if network.state == .notConnected || !running { return Rf.rose500 }
        return network.peersOnline > 0 ? Rf.emerald : Rf.faint
    }

    private var line: String {
        switch network.state {
        case .connecting: "connecting…"
        case .notConnected: network.reason.map { "not connected · \($0)" } ?? "not connected"
        case .connected:
            running ? "\(network.peersOnline) peer\(network.peersOnline == 1 ? "" : "s") online" : "offline"
        }
    }
}

struct AddNetworkSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var code = ""
    @State private var name = ""
    @State private var scanning = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                SectionLabel("Join or pair")
                RayfishField("Invite or pairing code", text: $code)
                HStack(spacing: 8) {
                    PillButton("Continue") { submit(code) }
                    PillButton("Scan", outline: true) { scanning = true }
                }
                SectionLabel("Create a network").padding(.top, 14)
                RayfishField("Network name (optional)", text: $name)
                PillButton("Create network") {
                    let trimmed = name.trimmingCharacters(in: .whitespaces)
                    dismiss()
                    Task { await model.perform(.create(name: trimmed.isEmpty ? nil : trimmed)) }
                }
            }
            .padding(20)
        }
        .rayfishPage()
        .presentationDetents([.medium, .large])
        .sheet(isPresented: $scanning) {
            QRScannerSheet { scanned in
                scanning = false
                submit(scanned)
            }
        }
    }

    private func submit(_ input: String) {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            model.toast = "Enter a code first"
            return
        }
        dismiss()
        Task { await model.perform(.submitCode(trimmed)) }
    }
}
