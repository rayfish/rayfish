import Darwin
import Foundation
import NetworkExtension
import RayApple

final class PacketTunnelProvider: NEPacketTunnelProvider, PacketFlow {
    private var node: Node?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        do {
            let node = Node(configDir: stateDirectory().path)
            try node.start()
            let settings = try networkSettings(address: node.ipv6Address())
            setTunnelNetworkSettings(settings) { [weak self] error in
                guard error == nil else {
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
                    self.readPackets()
                    completionHandler(nil)
                } catch {
                    completionHandler(error)
                }
            }
        } catch {
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        node?.stop()
        node = nil
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        do {
            let request = try JSONDecoder().decode(ProviderRequest.self, from: messageData)
            let response = try handle(request)
            completionHandler?(try JSONEncoder().encode(response))
        } catch {
            let response = ProviderResponse(success: false, error: error.localizedDescription, status: nil)
            completionHandler?(try? JSONEncoder().encode(response))
        }
    }

    func writePacket(_ packet: [UInt8]) {
        let data = Data(packet)
        let family = packet.first.map { $0 >> 4 } == 6 ? AF_INET6 : AF_INET
        packetFlow.writePackets([data], withProtocols: [NSNumber(value: family)])
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
                try node.receivePackets(packets: packets.map(Array.init))
                self.readPackets()
            } catch {
                self.cancelTunnelWithError(error)
            }
        }
    }

    private func networkSettings(address: String) throws -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "rayfish")
        let ipv6 = NEIPv6Settings(addresses: [address], networkPrefixLengths: [128])
        ipv6.includedRoutes = [NEIPv6Route(destinationAddress: "200::", networkPrefixLength: 7)]
        settings.ipv6Settings = ipv6
        let dns = NEDNSSettings(servers: ["200::53"])
        dns.matchDomains = ["ray"]
        settings.dnsSettings = dns
        return settings
    }

    private func stateDirectory() -> URL {
        let manager = FileManager.default
        let root = manager.containerURL(forSecurityApplicationGroupIdentifier: "group.xyz.rayfish")
            ?? manager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let path = root.appendingPathComponent("rayfish", isDirectory: true)
        try? manager.createDirectory(at: path, withIntermediateDirectories: true)
        return path
    }

    private func handle(_ request: ProviderRequest) throws -> ProviderResponse {
        guard let node else {
            throw ProviderError.notStarted
        }
        switch request.action {
        case .status:
            return ProviderResponse(success: true, error: nil, status: status(from: try node.status()))
        case .create:
            try node.createNetwork(name: request.name)
        case .join:
            guard let code = request.code, !code.isEmpty else {
                throw ProviderError.missingInviteCode
            }
            try node.joinNetwork(code: code)
        }
        return ProviderResponse(success: true, error: nil, status: status(from: try node.status()))
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
            }
        )
    }
}

private enum ProviderError: LocalizedError {
    case providerReleased
    case notStarted
    case missingInviteCode

    var errorDescription: String? {
        switch self {
        case .providerReleased:
            "Rayfish packet tunnel provider was released during startup"
        case .notStarted:
            "Rayfish is not connected"
        case .missingInviteCode:
            "An invite code is required"
        }
    }
}
