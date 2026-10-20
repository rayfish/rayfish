import SwiftUI

struct HomeView: View {
    @EnvironmentObject private var model: AppModel
    var openNetworks: () -> Void
    @State private var sending = false

    private var snapshot: Snapshot { model.snapshot }

    var body: some View {
        let networks = snapshot.networks
        let online = networks.reduce(0) { $0 + $1.peersOnline }
        let connected = networks.filter { $0.state == .connected }.count
        let state = model.tunnelState
        let running = state == .on
        let starting = !model.loaded
        let transitioning = starting || state.isTransitioning
            || (running && networks.contains { $0.state == .connecting })
        let banner = banner(state: state, starting: starting, connected: connected)

        ScrollView {
            VStack(spacing: 12) {
                BrandHeader()
                StatusEyebrow(connected: running && connected > 0 && !transitioning,
                              text: banner, transitioning: transitioning)
                ToggleCard(title: "Tunnel", subtitle: banner, isOn: Binding(
                    get: { state == .on || state == .connecting },
                    set: { on in Task { await model.setTunnel(on) } }
                ))
                .disabled(state.isTransitioning)
                if model.refreshFailed {
                    SectionCard {
                        Text("Could not read Rayfish's status.").font(Rf.text()).foregroundStyle(Rf.muted)
                        LinkButton("Retry") { model.refresh() }
                    }
                }
                SectionCard {
                    SectionLabel("Networks")
                    KeyValueRow(key: "Networks", value: "\(networks.count) · \(online) peer\(online == 1 ? "" : "s") online")
                }
                if networks.isEmpty {
                    PillButton("Join or create a network", action: openNetworks)
                } else {
                    PillButton("Send files") { sending = true }
                        .disabled(!snapshot.controlPlane || !networks.contains { !$0.peers.isEmpty })
                }
                files
                requests
            }
            .padding(20)
        }
        .rayfishPage()
        .statusBarBackdrop()
        .toolbar(.hidden, for: .navigationBar)
        .sheet(isPresented: $sending) { SendFilesSheet(peers: nil) }
    }

    private func banner(state: TunnelState, starting: Bool, connected: Int) -> String {
        let networks = snapshot.networks
        switch state {
        case _ where starting: return "Starting"
        case .disconnecting: return "Disconnecting…"
        case .connecting: return "connecting…"
        case .off: return "offline"
        case .on:
            if networks.contains(where: { $0.state == .connecting }) { return "connecting…" }
            if connected > 0 { return "connected · \(connected) network\(connected == 1 ? "" : "s")" }
            if networks.isEmpty { return model.isSimulator ? "Node running · no networks yet" : "VPN running · no networks yet" }
            return "Network connection failed"
        }
    }

    @ViewBuilder
    private var files: some View {
        let offers = snapshot.offers
        let transfers = snapshot.transfers.sorted { $0.isActive && !$1.isActive }
        if !offers.isEmpty || !snapshot.queued.isEmpty || !transfers.isEmpty {
            SectionCard {
                SectionLabel("Files")
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(offers) { offer in
                        RequestRow(
                            title: offer.filename,
                            subtitle: "file · \(formatSize(offer.size)) · from \(offer.from)",
                            accept: "Save",
                            onAccept: { Task { await model.perform(.acceptFile(id: offer.id)) } },
                            onDecline: { Task { await model.perform(.rejectFile(id: offer.id)) } }
                        )
                    }
                    ForEach(snapshot.queued) { send in
                        VStack(alignment: .leading, spacing: 2) {
                            RowTitle(send.filename)
                            RowSubtitle("waiting for \(send.peer) · \(formatSize(send.size))")
                            LinkButton("Cancel") { Task { await model.perform(.cancelSend(id: send.id)) } }
                        }
                    }
                    ForEach(transfers) { transfer in
                        TransferRow(transfer: transfer) {
                            Task { await model.perform(.cancelTransfer(id: transfer.id)) }
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var requests: some View {
        if !snapshot.connects.isEmpty || !snapshot.joins.isEmpty {
            SectionCard {
                SectionLabel("Requests")
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(snapshot.connects) { request in
                        RequestRow(
                            title: request.hostname ?? request.shortId,
                            subtitle: "connect request · \(request.shortId) · \(request.waitingSecs)s",
                            accept: "Accept",
                            onAccept: { Task { await model.perform(.approveConnect(id: request.shortId)) } },
                            onDecline: { Task { await model.perform(.rejectConnect(id: request.shortId)) } }
                        )
                    }
                    ForEach(snapshot.joins) { request in
                        RequestRow(
                            title: request.hostname ?? request.shortId,
                            subtitle: "wants to join \(request.network) · \(request.shortId)",
                            accept: "Accept",
                            onAccept: { Task { await model.perform(.acceptJoin(network: request.network, id: request.shortId)) } },
                            onDecline: { Task { await model.perform(.denyJoin(network: request.network, id: request.shortId)) } }
                        )
                    }
                }
            }
        }
    }
}

struct RowTitle: View {
    var text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text).font(Rf.semibold(14)).foregroundStyle(Rf.heading).lineLimit(2)
    }
}

struct RowSubtitle: View {
    var text: String
    var color = Rf.muted
    init(_ text: String, color: Color = Rf.muted) {
        self.text = text
        self.color = color
    }
    var body: some View {
        Text(text).font(Rf.text(13)).foregroundStyle(color)
    }
}

struct RequestRow: View {
    var title: String
    var subtitle: String
    var accept: String
    var onAccept: () -> Void
    var onDecline: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            RowTitle(title)
            RowSubtitle(subtitle)
            HStack(spacing: 8) {
                LinkButton(accept, color: Rf.emerald, action: onAccept)
                LinkButton("Decline", action: onDecline)
            }
        }
    }
}

struct TransferRow: View {
    var transfer: Transfer
    var onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            RowTitle(transfer.filename)
            RowSubtitle("\(label) · \(transfer.peer) · \(formatSize(transfer.size))",
                        color: transfer.state == .failed ? Rf.rose400 : Rf.muted)
            if transfer.isActive {
                if transfer.state == .offered || transfer.size == 0 {
                    ProgressView().progressViewStyle(.linear).tint(Rf.rose500)
                } else {
                    ProgressView(value: min(1, Double(transfer.transferred) / Double(transfer.size)))
                        .tint(Rf.rose500)
                    RowSubtitle("\(formatSize(transfer.transferred)) of \(formatSize(transfer.size))")
                }
                if transfer.outgoing { LinkButton("Cancel", action: onCancel) }
            }
        }
    }

    private var label: String {
        switch transfer.state {
        case .failed: "failed"
        case .done: transfer.outgoing ? "sent" : "received"
        case .offered: "waiting"
        case .transferring: transfer.outgoing ? "sending" : "receiving"
        }
    }
}
