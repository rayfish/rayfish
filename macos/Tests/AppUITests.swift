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
    func selectExitNode(network: String, peer: String?) async {}
}

@main
struct AppUITests {
    @MainActor
    static func main() throws {
        try shellCommandAliases()
        _ = NSApplication.shared
        let controller = TunnelController()
        let menu = NSMenu()
        var updateVersion: String?
        var restartCount = 0
        let owner = RayfishMenu(controller: controller, menu: menu,
                                updateReady: { updateVersion },
                                restartUpdate: { restartCount += 1 }) {}
        defer { withExtendedLifetime(owner) {} }
        precondition(row("activity", in: menu)?.title == "Connecting...")
        updateVersion = "0.5.6"
        owner.menuNeedsUpdate(menu)
        let update = row("restart-update", in: menu)!
        precondition(update.toolTip == "Install Rayfish 0.5.6")
        precondition(NSApp.sendAction(update.action!, to: update.target, from: update))
        precondition(restartCount == 1)
        updateVersion = nil
        owner.menuNeedsUpdate(menu)
        precondition(row("restart-update", in: menu) == nil)
        let header = row("connection", in: menu)
        controller.status = ProviderStatus(active: true, ipv6: "287::1", networks: [
            ProviderNetwork(name: "testnet", hostname: "local-device", ipv6: "287::1", role: "coordinator", peers: [
                ProviderPeer(hostname: "remote-device", ipv6: "278::1", state: "idle", latencyMs: nil, isOwnDevice: false)
            ])
        ], pendingRequests: [], exitNodes: [
            ProviderExitNodeNetwork(network: "testnet", using: nil, available: ["remote-device"],
                                    refused: [], problem: nil)
        ])
        controller.connectionStatus = .connected
        controller.activity = nil
        controller.isLoading = false
        drainTrackingUpdates()
        precondition(row("activity", in: menu) == nil)
        precondition(row("connection", in: menu) === header)
        let network = row("network:testnet", in: menu)!
        let submenu = network.submenu!
        let peer = row("peer:278::1", in: submenu)!
        precondition(peer.representedObject as? String == "remote-device.testnet.ray")
        let exits = row("exit-node", in: menu)!.submenu!
        precondition(row("exit-direct", in: exits)?.state == .on)
        precondition(row("exit:testnet:remote-device", in: exits)?.isEnabled == true)
        print("PASS: connecting menu receives networks while tracking")

        controller.status!.networks[0].peers[0].identity = "peer-id"
        controller.status!.exitNodes[0].using = "peer-id"
        drainTrackingUpdates()
        precondition(row("exit-node", in: menu)?.submenu === exits)
        precondition(row("exit-direct", in: exits)?.state == .off)
        precondition(row("exit:testnet:remote-device", in: exits)?.state == .on)

        controller.status!.networks[0].peers[0].hostname = "renamed"
        controller.status!.networks[0].peers[0].state = "direct"
        controller.status!.networks[0].peers.append(
            ProviderPeer(hostname: "second", ipv6: "278::2", state: "relay", latencyMs: nil, isOwnDevice: false)
        )
        controller.error = "Test connection issue"
        controller.status!.connectionWarning = "Connection quality is poor."
        drainTrackingUpdates()
        precondition(row("network:testnet", in: menu) === network)
        precondition(network.submenu === submenu)
        precondition(row("peer:278::1", in: submenu) === peer)
        precondition(peer.title == "renamed (direct)")
        precondition(peer.representedObject as? String == "renamed.testnet.ray")
        precondition(network.title == "testnet (2 devices)")
        precondition(row("connection-quality", in: menu)?.toolTip == "Connection quality is poor.")
        precondition(row("Connection Issue: Open Rayfish", in: menu)?.toolTip == "Test connection issue")
        print("PASS: peer updates preserve submenu and row identity")

        controller.status = nil
        controller.error = nil
        controller.connectionStatus = .disconnected
        drainTrackingUpdates()
        precondition(row("network:testnet", in: menu) == nil)
        precondition(row("connection-quality", in: menu) == nil)
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

    private static func shellCommandAliases() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("Rayfish Test's $App")
        let command = """
        #!/bin/sh
        if [ "$1" = completions ]; then
          if [ "$2" = zsh ]; then
            printf '%s\\n' 'function _ray_test() { :; }' 'compdef _ray_test ray'
          else
            printf '%s\\n' 'complete -W peer ray'
          fi
        else
          printf '%s' "$1"
        fi
        """
        try command.write(to: executable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)

        let original = "# Keep this setting\nexport RAYFISH_TEST=1\n\n# Rayfish command\nalias ray='old'\n"
        let configuration = directory.appendingPathComponent("shellrc")
        for shell in ["zsh", "bash"] {
            let updated = ShellCommandInstaller.replacingCommand(
                in: original, executable: executable.path, shell: shell)
            precondition(updated.hasPrefix("# Keep this setting\nexport RAYFISH_TEST=1\n"))
            precondition(!updated.contains("alias ray='old'"))
            precondition(updated.contains("completions \(shell)"))
            precondition(ShellCommandInstaller.replacingCommand(
                in: updated, executable: executable.path, shell: shell) == updated)
            let check = shell == "zsh" ? "print -r -- \"${_comps[ray]}\"\n" : "complete -p ray\n"
            try (updated + "ray 'argument with spaces'\n" + check)
                .write(to: configuration, atomically: true, encoding: .utf8)
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/\(shell)")
            process.arguments = (shell == "zsh" ? ["-f"] : ["--noprofile", "--norc", "-O", "expand_aliases"])
                + [configuration.path]
            let output = Pipe()
            process.standardOutput = output
            try process.run()
            process.waitUntilExit()
            precondition(process.terminationStatus == 0)
            let result = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            precondition(result.hasPrefix("argument with spaces"))
            precondition(result.contains(shell == "zsh" ? "_ray_test" : "complete -W"))
        }
        print("PASS: shell command installation registers completion in zsh and bash")
    }
}
