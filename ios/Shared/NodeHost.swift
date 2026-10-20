import Foundation

/// Runs app commands against a Rust node. The packet tunnel hosts the started
/// node; the app hosts an unstarted one that answers from the saved config while
/// the tunnel is off, and the simulator build starts its own because it has no
/// packet tunnel at all.
final class NodeHost: @unchecked Sendable {
    let node: Node
    private let lock = NSLock()
    private var acceptingIds: Set<UInt64> = []
    private var started = false
    /// Called with the file name when a download lands in the received folder.
    var onReceived: (@Sendable (String) -> Void)?

    init(directory: URL) {
        node = Node(configDir: directory.path)
    }

    var isStarted: Bool { lock.withLock { started } }

    /// Blocks while the node builds its endpoint, up to the core's own timeout.
    func start() throws {
        try node.start()
        lock.withLock { started = true }
    }

    func stop() {
        lock.withLock { started = false }
        node.stop()
    }

    func handle(_ command: Command) throws -> Reply {
        switch command {
        case .snapshot:
            return Reply(snapshot: snapshot())
        case .create(let name):
            let info = try node.create(name: name)
            return Reply(snapshot: snapshot(), message: "Created \(info.name)")
        case .submitCode(let code):
            let message = switch try node.submitCode(input: code) {
            case .joined(let info): info.pending ? "Asked to join \(info.name)" : "Joined \(info.name)"
            case .paired: "Device paired"
            }
            return Reply(snapshot: snapshot(), message: message)
        case .invite(let network):
            return Reply(code: try node.invite(network: network))
        case .leave(let network):
            try node.leave(network: network)
        case .setHostname(let network, let hostname):
            try node.setHostname(network: network, hostname: hostname)
        case .setDeviceName(let name):
            try node.setDefaultHostname(name: name)
            // Live networks take the name now; saved ones pick it up on rejoin.
            if isStarted {
                for network in node.status().networks where network.state == .connected {
                    try node.setHostname(network: network.name, hostname: name)
                }
            }
        case .firewall:
            return Reply(firewall: try node.firewallShow())
        case .allowInbound(let network, let protocolName, let port, let peer):
            try node.firewallAdd(direction: "in", action: "allow", protocol: protocolName,
                                 port: port, peer: peer, network: network)
            return Reply(firewall: try node.firewallShow())
        case .removeFirewallRule(let index):
            try node.firewallRemove(index: index)
            return Reply(firewall: try node.firewallShow())
        case .setDefaultInbound(let action):
            try node.firewallSetDefaultInbound(action: action)
            return Reply(firewall: try node.firewallShow())
        case .approveConnect(let id):
            try node.approveConnectRequest(shortId: id)
        case .rejectConnect(let id):
            try node.rejectConnectRequest(shortId: id)
        case .acceptJoin(let network, let id):
            try node.acceptJoinRequest(network: network, shortId: id)
        case .denyJoin(let network, let id):
            try node.denyJoinRequest(network: network, shortId: id)
        case .acceptFile(let id):
            try accept(id)
        case .rejectFile(let id):
            try node.rejectFileOffer(id: id)
        case .sendFiles(let paths, let peer):
            // Dial first so the offer lands on an awake device. A peer that does
            // not answer still gets the offer once it comes back.
            _ = node.wakePeer(peer: peer)
            for path in paths {
                try node.sendFile(path: path, peer: peer)
            }
        case .cancelSend(let id):
            try node.cancelSend(id: id)
        case .cancelTransfer(let id):
            try node.cancelTransfer(id: id)
        case .startPairing:
            return Reply(code: try node.startPairing())
        case .unpair:
            try node.unpair()
        case .setQuicEngine(let engine):
            try node.setQuicEngine(engine: engine)
        case .reloadTelemetry:
            Telemetry.apply()
        case .sendDiagnostics:
            guard Telemetry.sendDiagnostics(node: node) else { throw DiagnosticsError.unavailable }
            return Reply(message: "Diagnostics sent")
        }
        return Reply(snapshot: snapshot())
    }

    func snapshot() -> Snapshot {
        let status = node.status()
        var snapshot = Snapshot(
            controlPlane: isStarted,
            nodeId: status.nodeId,
            ipv6: status.ipv6,
            deviceName: node.defaultHostname(),
            paired: node.isPaired(),
            quicEngine: (try? node.quicEngine()) ?? .standalone,
            networks: status.networks,
            pendingNetworks: status.pendingNetworks
        )
        guard isStarted else { return snapshot }
        let accepting = lock.withLock { acceptingIds }
        snapshot.offers = ((try? node.listFileOffers()) ?? []).filter { !accepting.contains($0.id) }
        snapshot.queued = (try? node.listQueuedSends()) ?? []
        snapshot.transfers = (try? node.listTransfers()) ?? []
        snapshot.connects = (try? node.listConnectRequests()) ?? []
        snapshot.joins = status.networks
            .filter { $0.isCoordinator && $0.state == .connected }
            .flatMap { network in
                ((try? node.listJoinRequests(network: network.name)) ?? []).map {
                    JoinRequestModel(network: network.name, shortId: $0.shortId, hostname: $0.hostname)
                }
            }
        return snapshot
    }

    /// Start a download and return at once; the transfer list shows progress.
    /// Each offer downloads into its own folder, and only a finished file moves
    /// to the received folder, so the app never collects a partial file.
    func accept(_ id: UInt64) throws {
        let inserted = lock.withLock { acceptingIds.insert(id).inserted }
        guard inserted else { return }
        let folder = try AppGroup.incoming().appendingPathComponent(String(id), isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            defer { _ = lock.withLock { acceptingIds.remove(id) } }
            do {
                try node.acceptFileOffer(id: id, outputDir: folder.path)
                for name in try collect(folder) { onReceived?(name) }
            } catch {
                RayfishLog.tunnel.error("Receiving file \(id) failed: \(error.localizedDescription, privacy: .public)")
            }
            try? FileManager.default.removeItem(at: folder)
        }
    }

    /// Accept offers from this person's own paired devices when they asked for it.
    func autoAcceptOwnDevices() {
        guard isStarted, Preferences.autoAcceptOwnDevices,
              let offers = try? node.listFileOffers() else { return }
        for offer in offers where offer.ownDevice {
            try? accept(offer.id)
        }
    }

    private func collect(_ folder: URL) throws -> [String] {
        let manager = FileManager.default
        let received = try AppGroup.received()
        return try manager.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil).map { file in
            let target = FileNames.unique(file.lastPathComponent, in: received)
            try manager.moveItem(at: file, to: target)
            return file.lastPathComponent
        }
    }
}

enum FileNames {
    /// `name` in `folder`, numbered like Finder does when it is taken.
    static func unique(_ name: String, in folder: URL) -> URL {
        let manager = FileManager.default
        var candidate = folder.appendingPathComponent(name)
        let base = (name as NSString).deletingPathExtension
        let ext = (name as NSString).pathExtension
        var number = 2
        while manager.fileExists(atPath: candidate.path) {
            let numbered = ext.isEmpty ? "\(base) \(number)" : "\(base) \(number).\(ext)"
            candidate = folder.appendingPathComponent(numbered)
            number += 1
        }
        return candidate
    }
}

enum DiagnosticsError: LocalizedError {
    case unavailable

    var errorDescription: String? { "Diagnostics unavailable" }
}
