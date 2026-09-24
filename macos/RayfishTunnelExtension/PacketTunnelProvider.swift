import Darwin
import Foundation
import NetworkExtension
import OSLog

final class PacketTunnelProvider: NEPacketTunnelProvider, PacketFlow {
    private var node: Node?
    private var appliedDNS: Bool?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        RayfishLog.tunnel.info("Starting tunnel build \(Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown", privacy: .public)")
        var startingNode: Node?
        do {
            let directory = try stateDirectory()
            let node = Node(configDir: directory.path)
            startingNode = node
            if let legacy = try LegacyDaemon.discover() {
                RayfishLog.tunnel.info("Checking legacy daemon migration")
                try legacy.migrateIfNeeded(to: directory) { source in
                    try node.migrateLegacyState(source: source.path)
                }
            }
            try node.start()
            let status = try node.status()
            let settings = networkSettings(address: status.ipv6, dnsEnabled: status.dnsEnabled)
            setTunnelNetworkSettings(settings) { [weak self] error in
                if let error {
                    node.stop()
                    RayfishLog.tunnel.error("Network settings failed: \(error.localizedDescription, privacy: .public)")
                    completionHandler(error)
                    return
                }
                guard let self else {
                    node.stop()
                    completionHandler(ProviderError.providerReleased)
                    return
                }
                do {
                    try node.activate(flow: self)
                    self.node = node
                    self.appliedDNS = status.dnsEnabled
                    self.readPackets()
                    RayfishLog.tunnel.info("Tunnel is ready")
                    completionHandler(nil)
                } catch {
                    node.stop()
                    RayfishLog.tunnel.error("Tunnel activation failed: \(error.localizedDescription, privacy: .public)")
                    completionHandler(error)
                }
            }
        } catch {
            startingNode?.stop()
            RayfishLog.tunnel.error("Tunnel startup failed: \(error.localizedDescription, privacy: .public)")
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        let started = DispatchTime.now().uptimeNanoseconds
        RayfishLog.tunnel.info("Stopping tunnel, reason \(reason.rawValue)")
        do {
            let stoppingNode = node
            node = nil
            appliedDNS = nil
            stoppingNode?.stop()
        }
        let elapsedMs = (DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
        RayfishLog.tunnel.info("Tunnel stopped in \(elapsedMs) ms")
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        Task { @MainActor [weak self] in
            guard let self else { completionHandler?(nil); return }
            await self.handleMessage(messageData, completionHandler: completionHandler)
        }
    }

    @MainActor
    private func handleMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) async {
        do {
            let request = try JSONDecoder().decode(ProviderRequest.self, from: messageData)
            RayfishLog.tunnel.debug("Handling \(request.action.rawValue, privacy: .public)")
            guard let node else { throw ProviderError.notStarted }
            let previousDNS = appliedDNS
            let response = try await Task.detached {
                try self.handle(request, node: node)
            }.value
            guard self.node === node else { throw ProviderError.notStarted }
            if let status = response.status, appliedDNS != status.dnsEnabled {
                do {
                    try await setTunnelNetworkSettings(networkSettings(address: status.ipv6, dnsEnabled: status.dnsEnabled))
                    appliedDNS = status.dnsEnabled
                } catch {
                    if request.action == .setSetting, request.setting == .dns, let previousDNS {
                        try node.setSetting(key: .dns, enabled: previousDNS)
                    }
                    throw error
                }
            }
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
            guard let self, let node = self.node else { return }
            do {
                try node.receivePackets(packets: packets)
                self.readPackets()
            } catch {
                RayfishLog.tunnel.error("Packet processing failed: \(error.localizedDescription, privacy: .public)")
                self.cancelTunnelWithError(error)
            }
        }
    }

    private func networkSettings(address: String, dnsEnabled: Bool) -> NEPacketTunnelNetworkSettings {
        // Rayfish has no single tunnel server; macOS still requires a numeric IP here.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv6 = NEIPv6Settings(addresses: [address], networkPrefixLengths: [128])
        ipv6.includedRoutes = [NEIPv6Route(destinationAddress: "200::", networkPrefixLength: 7)]
        settings.ipv6Settings = ipv6
        if dnsEnabled {
            let dns = NEDNSSettings(servers: ["200::53"])
            dns.matchDomains = ["ray"]
            settings.dnsSettings = dns
        }
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

    private func handle(_ request: ProviderRequest, node: Node) throws -> ProviderResponse {
        var inviteCode: String?
        var message: String?
        switch request.action {
        case .status:
            break
        case .machines:
            let machines = try node.machines().map { machine in
                ProviderMachine(identity: machine.identity, hostname: machine.hostname,
                                ipv6: machine.ipv6, state: machine.state, networks: machine.networks)
            }
            return ProviderResponse(success: true, error: nil, status: nil, inviteCode: nil, machines: machines)
        case .setSetting:
            guard let setting = request.setting, let enabled = request.enabled else {
                throw ProviderError.missingSetting
            }
            try node.setSetting(key: setting == .dns ? .dns : .mdns, enabled: enabled)
        case .connectPeer:
            guard let id = request.id, !id.isEmpty else { throw ProviderError.missingPeer }
            message = try node.connectPeer(contactId: id, hostname: request.hostname)
        case .approveConnection, .rejectConnection:
            guard let id = request.id, !id.isEmpty else { throw ProviderError.missingPeer }
            if request.action == .approveConnection {
                try node.approveConnection(id: id)
            } else {
                try node.rejectConnection(id: id)
            }
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
            inviteCode = try node.createInvite(network: name)
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
        case .acceptRequest, .denyRequest:
            guard let name = request.name, let id = request.id else {
                throw ProviderError.missingNetworkName
            }
            if request.action == .acceptRequest {
                try node.acceptRequest(network: name, id: id)
            } else {
                try node.denyRequest(network: name, id: id)
            }
        }
        return ProviderResponse(success: true, error: nil, status: status(from: try node.status()), inviteCode: inviteCode, message: message)
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
            },
            contactId: status.contactId,
            connectionRequests: status.connectionRequests.map { request in
                ProviderConnectionRequest(id: request.id, hostname: request.hostname, waitingSecs: request.waitingSecs)
            },
            dnsEnabled: status.dnsEnabled,
            mdnsEnabled: status.mdnsEnabled,
            mdnsActive: status.mdnsActive
        )
    }
}

private enum ProviderError: LocalizedError {
    case providerReleased
    case notStarted
    case missingInviteCode
    case missingNetworkName
    case missingAppGroup
    case missingSetting
    case missingPeer

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
        case .missingSetting:
            "A setting and its value are required"
        case .missingPeer:
            "A peer contact ID or request ID is required"
        }
    }
}
