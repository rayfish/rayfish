import Darwin
import Foundation
import NetworkExtension
import OSLog

final class PacketTunnelProvider: NEPacketTunnelProvider, PacketFlow {
    private var node: Node?
    private var messageListener: TunnelMessageListener?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        RayfishLog.tunnel.info("Starting tunnel build \(Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown", privacy: .public)")
        do {
            let clientRequirement = try TunnelIPC.requirement(for: "com.rayfish.app")
            let directory = try stateDirectory()
            let node = Node(configDir: directory.path)
            if let legacy = try LegacyDaemon.discover() {
                RayfishLog.tunnel.info("Checking legacy daemon migration")
                try legacy.migrateIfNeeded(to: directory) { source in
                    try node.migrateLegacyState(source: source.path)
                }
            }
            try node.start()
            let settings = try networkSettings(address: node.ipv6Address())
            setTunnelNetworkSettings(settings) { [weak self] error in
                guard error == nil else {
                    RayfishLog.tunnel.error("Network settings failed: \(error!.localizedDescription, privacy: .public)")
                    completionHandler(error)
                    return
                }
                guard let self else {
                    completionHandler(ProviderError.providerReleased)
                    return
                }
                do {
                    try node.activate(flow: self)
                    self.node = node
                    self.messageListener = TunnelMessageListener(
                        listener: NSXPCListener(machServiceName: TunnelIPC.serviceName),
                        clientRequirement: clientRequirement
                    ) { [weak self] data, reply in
                        guard let self else { reply(nil); return }
                        self.handleAppMessage(data, completionHandler: reply)
                    }
                    self.readPackets()
                    RayfishLog.tunnel.info("Tunnel is ready; command listener started")
                    completionHandler(nil)
                } catch {
                    RayfishLog.tunnel.error("Tunnel activation failed: \(error.localizedDescription, privacy: .public)")
                    completionHandler(error)
                }
            }
        } catch {
            RayfishLog.tunnel.error("Tunnel startup failed: \(error.localizedDescription, privacy: .public)")
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        let started = DispatchTime.now().uptimeNanoseconds
        RayfishLog.tunnel.info("Stopping tunnel, reason \(reason.rawValue)")
        messageListener?.invalidate()
        messageListener = nil
        do {
            let stoppingNode = node
            node = nil
            stoppingNode?.stop()
        }
        let elapsedMs = (DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
        RayfishLog.tunnel.info("Tunnel stopped in \(elapsedMs) ms")
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        do {
            let request = try JSONDecoder().decode(ProviderRequest.self, from: messageData)
            RayfishLog.tunnel.debug("Handling \(request.action.rawValue, privacy: .public)")
            let response = try handle(request)
            completionHandler?(try JSONEncoder().encode(response))
        } catch {
            RayfishLog.tunnel.error("Command failed: \(error.localizedDescription, privacy: .private)")
            let response = ProviderResponse(success: false, error: error.localizedDescription, status: nil, inviteCode: nil)
            completionHandler?(try? JSONEncoder().encode(response))
        }
    }

    func writePacket(packet: Data) {
        let family = packet.first.map { $0 >> 4 } == 6 ? AF_INET6 : AF_INET
        packetFlow.writePackets([packet], withProtocols: [NSNumber(value: family)])
    }

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else {
                return
            }
            do {
                guard let node = node else {
                    return
                }
                try node.receivePackets(packets: packets)
                self.readPackets()
            } catch {
                RayfishLog.tunnel.error("Packet processing failed: \(error.localizedDescription, privacy: .public)")
                self.cancelTunnelWithError(error)
            }
        }
    }

    private func networkSettings(address: String) throws -> NEPacketTunnelNetworkSettings {
        // Rayfish has no single tunnel server; macOS still requires a numeric IP here.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv6 = NEIPv6Settings(addresses: [address], networkPrefixLengths: [128])
        ipv6.includedRoutes = [NEIPv6Route(destinationAddress: "200::", networkPrefixLength: 7)]
        settings.ipv6Settings = ipv6
        let dns = NEDNSSettings(servers: ["200::53"])
        dns.matchDomains = ["ray"]
        settings.dnsSettings = dns
        return settings
    }

    private func stateDirectory() throws -> URL {
        let manager = FileManager.default
        guard let root = manager.containerURL(forSecurityApplicationGroupIdentifier: "group.com.rayfish.app") else {
            throw ProviderError.missingAppGroup
        }
        let path = root.appendingPathComponent("rayfish", isDirectory: true)
        try manager.createDirectory(at: path, withIntermediateDirectories: true)
        return path
    }

    private func handle(_ request: ProviderRequest) throws -> ProviderResponse {
        guard let node else {
            throw ProviderError.notStarted
        }
        switch request.action {
        case .status:
            return ProviderResponse(success: true, error: nil, status: status(from: try node.status()), inviteCode: nil)
        case .create:
            try node.createNetwork(name: request.name, hostname: request.hostname)
        case .join:
            guard let code = request.code, !code.isEmpty else {
                throw ProviderError.missingInviteCode
            }
            try node.joinNetwork(code: code, hostname: request.hostname)
        case .invite:
            guard let name = request.name, !name.isEmpty else {
                throw ProviderError.missingNetworkName
            }
            let code = try node.createInvite(network: name)
            return ProviderResponse(success: true, error: nil, status: status(from: try node.status()), inviteCode: code)
        case .leave:
            guard let name = request.name, !name.isEmpty else {
                throw ProviderError.missingNetworkName
            }
            try node.leaveNetwork(network: name)
        case .setHostname:
            guard let name = request.name, !name.isEmpty, let hostname = request.hostname, !hostname.isEmpty else {
                throw ProviderError.missingNetworkName
            }
            try node.setHostname(network: name, hostname: hostname)
        case .acceptRequest:
            guard let name = request.name, let id = request.id else {
                throw ProviderError.missingNetworkName
            }
            try node.acceptRequest(network: name, id: id)
        case .denyRequest:
            guard let name = request.name, let id = request.id else {
                throw ProviderError.missingNetworkName
            }
            try node.denyRequest(network: name, id: id)
        }
        return ProviderResponse(success: true, error: nil, status: status(from: try node.status()), inviteCode: nil)
    }

    private func status(from status: NodeStatus) -> ProviderStatus {
        ProviderStatus(
            active: status.active,
            ipv6: status.ipv6,
            networks: status.networks.map { network in
                ProviderNetwork(
                    name: network.name,
                    hostname: network.hostname,
                    ipv6: network.ipv6,
                    role: network.role,
                    peers: network.peers.map { peer in
                        ProviderPeer(
                            hostname: peer.hostname,
                            ipv6: peer.ipv6,
                            state: peer.state,
                            latencyMs: peer.latencyMs,
                            isOwnDevice: peer.isOwnDevice
                        )
                    }
                )
            },
            pendingRequests: status.pendingRequests.map { request in
                ProviderJoinRequest(
                    network: request.network,
                    id: request.id,
                    hostname: request.hostname,
                    waitingSecs: request.waitingSecs
                )
            }
        )
    }
}

private enum ProviderError: LocalizedError {
    case providerReleased
    case notStarted
    case missingInviteCode
    case missingNetworkName
    case missingAppGroup

    var errorDescription: String? {
        switch self {
        case .providerReleased:
            "Rayfish packet tunnel provider was released during startup"
        case .notStarted:
            "Rayfish is not connected"
        case .missingInviteCode:
            "An invite code is required"
        case .missingNetworkName:
            "A network name is required"
        case .missingAppGroup:
            "Rayfish shared storage is unavailable"
        }
    }
}
