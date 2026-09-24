import AppKit
import Combine
import NetworkExtension

// A view model fixture keeps these UI tests away from the installed VPN.
@MainActor
final class TunnelController: ObservableObject {
    @Published var status: ProviderStatus?
    @Published var activity: String? = "Connecting..."
    @Published var error: String?
    @Published var isLoading = true
    @Published var connectionStatus: NEVPNStatus = .connecting
    var isConnected: Bool { connectionStatus == .connected }
    var connectionLabel: String { isConnected ? "connected" : "disconnected" }
    func connect() async { connectionStatus = .connected }
    func disconnect() async { connectionStatus = .disconnected }
}

@main
struct AppUITests {
    @MainActor
    static func main() {
        _ = NSApplication.shared
        let controller = TunnelController()
        let menu = NSMenu()
        let owner = RayfishMenu(controller: controller, menu: menu) {}
        defer { withExtendedLifetime(owner) {} }
        precondition(row("activity", in: menu)?.title == "Connecting...")
        let header = row("connection", in: menu)
        controller.status = ProviderStatus(active: true, ipv6: "287::1", networks: [
            ProviderNetwork(name: "field", hostname: "dario", ipv6: "287::1", role: "coordinator", peers: [
                ProviderPeer(hostname: "ty2-hypr01", ipv6: "278::1", state: "idle", latencyMs: nil, isOwnDevice: false)
            ])
        ], pendingRequests: [])
        controller.connectionStatus = .connected
        controller.activity = nil
        controller.isLoading = false
        drainTrackingUpdates()
        precondition(row("activity", in: menu) == nil)
        precondition(row("connection", in: menu) === header)
        let network = row("network:field", in: menu)!
        let submenu = network.submenu!
        let peer = row("peer:278::1", in: submenu)!
        precondition(peer.representedObject as? String == "ty2-hypr01.field.ray")
        print("PASS: connecting menu receives networks while tracking")

        controller.status!.networks[0].peers[0].hostname = "renamed"
        controller.status!.networks[0].peers[0].state = "direct"
        controller.status!.networks[0].peers.append(
            ProviderPeer(hostname: "second", ipv6: "278::2", state: "relay", latencyMs: nil, isOwnDevice: false)
        )
        controller.error = "Test connection issue"
        drainTrackingUpdates()
        precondition(row("network:field", in: menu) === network)
        precondition(network.submenu === submenu)
        precondition(row("peer:278::1", in: submenu) === peer)
        precondition(peer.title == "renamed (direct)")
        precondition(peer.representedObject as? String == "renamed.field.ray")
        precondition(network.title == "field (2 devices)")
        precondition(row("Connection Issue: Open Rayfish", in: menu)?.toolTip == "Test connection issue")
        print("PASS: peer updates preserve submenu and row identity")

        controller.status = nil
        controller.error = nil
        controller.connectionStatus = .disconnected
        drainTrackingUpdates()
        precondition(row("network:field", in: menu) == nil)
        precondition(row("Connection Issue: Open Rayfish", in: menu) == nil)
        precondition(row("Open Rayfish", in: menu) != nil)
        print("PASS: disconnect clears stale networks and errors")

        let content = NSView()
        let window = RayfishWindow(content: content)
        window.show()
        precondition(window.isVisible)
        window.performClose(nil)
        precondition(!window.isVisible)
        precondition(window.contentView === content)
        window.show()
        precondition(window.isVisible)
        precondition(window.contentView === content)
        window.orderOut(nil)
        print("PASS: close hides the dashboard and reopening preserves its content")
    }

    @MainActor
    private static func row(_ id: String, in menu: NSMenu) -> NSMenuItem? {
        menu.items.first { $0.identifier?.rawValue == id }
    }

    @MainActor
    private static func drainTrackingUpdates() {
        // The default run-loop mode is deliberately not serviced here.
        RunLoop.main.run(mode: .eventTracking, before: Date(timeIntervalSinceNow: 0.05))
    }
}
