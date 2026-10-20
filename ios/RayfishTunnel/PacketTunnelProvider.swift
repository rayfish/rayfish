import Foundation
import Network
import NetworkExtension
import UserNotifications

/// Hosts the Rust node for as long as the VPN is on. iOS suspends the app, so
/// this is the only process that can keep peers, file offers and requests
/// moving in the background.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let queue = DispatchQueue(label: "xyz.rayfish.ios.tunnel.node")
    private var host: NodeHost?
    private var watch: FileWatch?
    private var pathMonitor: NWPathMonitor?
    private var lastPath: String?
    private var sleptAt: Date?
    private let notifier = OfferNotifier()

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        RayfishLog.tunnel.info("Starting tunnel build \(Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown", privacy: .public)")
        Telemetry.apply()
        queue.async { [self] in
            let host: NodeHost
            do {
                host = NodeHost(directory: try AppGroup.stateDirectory())
            } catch {
                RayfishLog.tunnel.error("Shared storage unavailable: \(error.localizedDescription, privacy: .public)")
                completionHandler(error)
                return
            }
            do {
                try host.start()
            } catch {
                RayfishLog.tunnel.error("Node start failed: \(error.localizedDescription, privacy: .public)")
                Telemetry.captureStartFailure(error, node: host.node)
                completionHandler(error)
                return
            }
            let address = host.node.status().ipv6
            setTunnelNetworkSettings(Self.settings(address: address)) { [self] error in
                queue.async { [self] in
                    if let error {
                        host.stop()
                        RayfishLog.tunnel.error("Network settings failed: \(error.localizedDescription, privacy: .public)")
                        completionHandler(error)
                        return
                    }
                    do {
                        // The utun exists only once the settings are applied.
                        try host.node.upPacketTunnel()
                    } catch {
                        host.stop()
                        RayfishLog.tunnel.error("Tunnel activation failed: \(error.localizedDescription, privacy: .public)")
                        completionHandler(error)
                        return
                    }
                    self.host = host
                    host.onReceived = { [notifier] name in notifier.received(name) }
                    watchFiles(host)
                    watchPath()
                    // A toggle changed while starting went to the app's own node.
                    Telemetry.apply()
                    RayfishLog.tunnel.info("Tunnel is ready")
                    completionHandler(nil)
                    VPNPreferences.reloadControl()
                }
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        RayfishLog.tunnel.info("Stopping tunnel, reason \(reason.rawValue)")
        queue.async { [self] in
            pathMonitor?.cancel()
            pathMonitor = nil
            watch?.cancel()
            watch = nil
            host?.stop()
            host = nil
            completionHandler()
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let host else {
            completionHandler?(try? JSONEncoder().encode(Reply(error: "Rayfish is not connected")))
            return
        }
        // Off the provider queue: joins and pairing dial peers for a while, and
        // status reads must keep answering meanwhile.
        DispatchQueue.global(qos: .userInitiated).async {
            let reply: Reply
            do {
                let command = try JSONDecoder().decode(Command.self, from: messageData)
                reply = try host.handle(command)
            } catch {
                reply = Reply(error: userMessage(error))
            }
            completionHandler?(try? JSONEncoder().encode(reply))
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        queue.async { [self] in sleptAt = Date() }
        completionHandler()
    }

    /// A sleeping phone wakes every few seconds for any incoming packet, so a
    /// rebind on each wake kept the radio busy all night. Only a long sleep can
    /// leave sockets stale; interface changes come from the path monitor.
    override func wake() {
        queue.async { [self] in
            guard let sleptAt, Date().timeIntervalSince(sleptAt) >= Self.staleSleep else { return }
            host?.node.networkChanged()
        }
    }

    private static let staleSleep: TimeInterval = 10 * 60

    private func watchFiles(_ host: NodeHost) {
        watch = try? host.node.watchFiles(listener: FileListener { [weak self, weak host] in
            guard let self, let host else { return }
            queue.async {
                host.autoAcceptOwnDevices()
                self.notifier.offers((try? host.node.listFileOffers()) ?? [])
            }
        })
    }

    /// iroh rebinds when told the network changed. Repeated callbacks for the
    /// same interfaces are dropped so a flapping path does not churn sockets.
    private func watchPath() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self, path.status == .satisfied else { return }
            let key = path.availableInterfaces.map(\.name).joined(separator: ",")
            queue.async {
                guard self.lastPath != key else { return }
                let first = self.lastPath == nil
                self.lastPath = key
                if !first { self.host?.node.networkChanged() }
            }
        }
        monitor.start(queue: queue)
        pathMonitor = monitor
    }

    private static func settings(address: String) -> NEPacketTunnelNetworkSettings {
        // There is no single tunnel server, but NetworkExtension wants an address.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // WireGuard found iOS mishandles IPv6 interface prefixes longer than /120.
        let ipv6 = NEIPv6Settings(addresses: [address], networkPrefixLengths: [120])
        ipv6.includedRoutes = [NEIPv6Route(destinationAddress: "200::", networkPrefixLength: 7)]
        settings.ipv6Settings = ipv6
        // Only .ray names go to the mesh resolver; everything else stays on the
        // system's own DNS.
        let dns = NEDNSSettings(servers: ["200::53"])
        dns.matchDomains = ["ray"]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns
        settings.mtu = 1500
        return settings
    }
}

private final class FileListener: FileChangeListener, @unchecked Sendable {
    private let change: () -> Void

    init(_ change: @escaping () -> Void) {
        self.change = change
    }

    func onChange() { change() }
}

/// Local notifications for offers and finished downloads, posted from the
/// tunnel because the app is usually suspended when they arrive.
final class OfferNotifier: @unchecked Sendable {
    private var announced: Set<UInt64> = []

    func offers(_ offers: [FileOffer]) {
        let current = Set(offers.map(\.id))
        announced.formIntersection(current)
        for offer in offers where !announced.contains(offer.id) {
            announced.insert(offer.id)
            if offer.ownDevice && Preferences.autoAcceptOwnDevices { continue }
            post(id: "offer-\(offer.id)", title: "File from \(offer.from)",
                 body: "\(offer.filename), \(formatSize(offer.size))")
        }
    }

    func received(_ name: String) {
        post(id: "received-\(UUID().uuidString)", title: "File received", body: "Open Rayfish to save \(name) to Files")
    }

    private func post(id: String, title: String, body: String) {
        let center = UNUserNotificationCenter.current()
        // Posting without permission has crashed extensions, so ask first.
        center.getNotificationSettings { settings in
            guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else { return }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            center.add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
        }
    }
}
