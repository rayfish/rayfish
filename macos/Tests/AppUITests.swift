import AppKit
import Combine
import NetworkExtension

// A view model fixture keeps these UI tests away from the installed VPN.
@MainActor
final class TunnelController: ObservableObject {
    @Published var page: RayfishPage = .networks
    @Published var firewallScope: FirewallScope = .general
    @Published var firewallReturnToNetworks = false
    @Published var status: ProviderStatus?
    @Published var firewall: ProviderFirewallState?
    @Published var activity: String? = "Connecting..."
    @Published var error: String?
    @Published var isLoading = true
    @Published var connectionStatus: NEVPNStatus = .connecting
    var isConnected: Bool { connectionStatus == .connected }
    var connectionLabel: String { isConnected ? "connected" : "disconnected" }
    func connect() async { connectionStatus = .connected }
    func disconnect() async { connectionStatus = .disconnected }
    func selectExitNode(network: String, peer: String?) async {}
    func loadFirewall() async {}
    func addFirewallRule(direction: String, action: String, protocolName: String,
                         port: String, peer: String?, network: String?) async -> Bool { true }
    func removeFirewallRule(at index: UInt32) async {}
    func setFirewallDefaultInbound(_ action: String) async {}
    func setFirewallDefaultOutbound(_ action: String) async {}
    func setFirewallEnabled(_ enabled: Bool) async {}
    func setFirewallReject(_ reject: Bool) async {}
    func acceptFirewallSuggestions(network: String) async {}
    func denyFirewallSuggestions(network: String) async {}
    func setNetworkFirewallAutoAccept(network: String, enabled: Bool) async {}
}

enum RayfishPage: String, CaseIterable {
    case networks = "Networks", devices = "Devices", firewall = "Firewall", files = "Files", settings = "Settings"
}

@main
struct AppUITests {
    @MainActor
    static func main() throws {
        firewallPartitioningAndLabels()
        try shellCommandAliases()
        try fishCommandInstallation()
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
        precondition(row("connection-quality", in: menu) == nil)
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
        let executable = directory.appendingPathComponent("Rayfish Test's $App\\bundle")
        let command = """
        #!/bin/sh
        if [ "$1" = completions ]; then
          if [ "$2" = zsh ]; then
            printf '%s\\n' 'function _ray_test() { :; }' 'compdef _ray_test ray'
          elif [ "$2" = fish ]; then
            printf '%s\\n' 'complete -c ray -f -a peer'
          else
            printf '%s\\n' 'complete -W peer ray'
          fi
        else
          printf '%s' "$1"
        fi
        """
        try command.write(to: executable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)

        let configuration = directory.appendingPathComponent("shellrc")
        for shell in ["zsh", "bash", "fish"] {
            let setting = shell == "fish" ? "set -gx RAYFISH_TEST 1" : "export RAYFISH_TEST=1"
            let original = "# Keep this setting\n\(setting)\n\n# Rayfish command\nalias ray='old'\n"
            let updated = ShellCommandInstaller.replacingCommand(
                in: original, executable: executable.path, shell: shell)
            precondition(updated.hasPrefix("# Keep this setting\n\(setting)\n"))
            precondition(!updated.contains("alias ray='old'"))
            precondition(updated.contains("completions \(shell)"))
            precondition(ShellCommandInstaller.replacingCommand(
                in: updated, executable: executable.path, shell: shell) == updated)
            let check: String
            let options: [String]
            switch shell {
            case "zsh":
                check = "print -r -- \"${_comps[ray]}\"\n"
                options = ["-f"]
            case "fish":
                check = "complete -C 'ray '\n"
                options = ["--no-config"]
            default:
                check = "complete -p ray\n"
                options = ["--noprofile", "--norc", "-O", "expand_aliases"]
            }
            try (updated + "ray 'argument with spaces'\n" + check)
                .write(to: configuration, atomically: true, encoding: .utf8)
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = [shell] + options + [configuration.path]
            let output = Pipe()
            process.standardOutput = output
            try process.run()
            process.waitUntilExit()
            precondition(process.terminationStatus == 0)
            let result = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            precondition(result.hasPrefix("argument with spaces"))
            let expected = shell == "zsh" ? "_ray_test" : shell == "fish" ? "peer" : "complete -W"
            precondition(result.contains(expected))
        }
        print("PASS: shell command installation registers completion in zsh, bash, and fish")
    }

    private static func fishCommandInstallation() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let executable = home.appendingPathComponent("ray")
        try "#!/bin/sh\n".write(to: executable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)

        var environment = ["SHELL": "/opt/test/bin/fish"]
        precondition(ShellCommandInstaller.shellName(environment: environment) == "fish")
        let defaultConfig = home.appendingPathComponent(".config/fish/config.fish")
        let installed = try ShellCommandInstaller.install(
            executable: executable, home: home, environment: environment)
        precondition(installed == defaultConfig)
        precondition(FileManager.default.fileExists(atPath: installed.path))

        environment["XDG_CONFIG_HOME"] = "relative-config"
        let relativeInstalled = try ShellCommandInstaller.install(
            executable: executable, home: home, environment: environment)
        precondition(relativeInstalled == defaultConfig)

        let config = home.appendingPathComponent("custom config")
        environment["XDG_CONFIG_HOME"] = config.path
        let customInstalled = try ShellCommandInstaller.install(
            executable: executable, home: home, environment: environment)
        precondition(customInstalled == config.appendingPathComponent("fish/config.fish"))
        let settings = "# Keep this setting\nset -gx RAYFISH_TEST 1\n"
        try settings.write(to: customInstalled, atomically: true, encoding: .utf8)
        _ = try ShellCommandInstaller.install(executable: executable, home: home, environment: environment)
        let contents = try String(contentsOf: customInstalled, encoding: .utf8)
        precondition(contents.hasPrefix(settings))
        _ = try ShellCommandInstaller.install(executable: executable, home: home, environment: environment)
        let reinstalled = try String(contentsOf: customInstalled, encoding: .utf8)
        precondition(reinstalled == contents)
        print("PASS: fish installation creates its config directory and preserves settings on reinstall")
    }

    private static func firewallPartitioningAndLabels() {
        let networks = [
            ProviderNetwork(name: "alpha", hostname: "laptop", ipv6: "200::1", role: "coordinator", peers: [
                ProviderPeer(hostname: "server-a", ipv6: "200::2", state: "direct", latencyMs: 12,
                             isOwnDevice: false, identity: "abcdef1234567890")
            ]),
            ProviderNetwork(name: "beta", hostname: "laptop", ipv6: "200::1", role: "member", peers: [])
        ]
        let firewall = ProviderFirewallState(
            defaultInbound: "deny",
            defaultOutbound: "allow",
            reject: true,
            disabled: false,
            rules: [
                ProviderFirewallRule(direction: "in", action: "allow", protocolName: "icmp",
                                     port: "*", peer: "any", network: "any"),
                ProviderFirewallRule(direction: "in", action: "allow", protocolName: "tcp",
                                     port: "443", peer: "abcdef", network: "alpha", suggestedBy: "alpha"),
                ProviderFirewallRule(direction: "out", action: "deny", protocolName: "udp",
                                     port: "53", peer: "any", network: "beta"),
                ProviderFirewallRule(direction: "in", action: "allow", protocolName: "tcp",
                                     port: "22", peer: "any", network: "departed")
            ],
            networks: [
                ProviderNetworkFirewall(network: "alpha", autoAccept: true, pendingRules: [
                    ProviderFirewallRule(direction: "in", action: "allow", protocolName: "tcp",
                                         port: "8080", peer: "any", network: "alpha", suggestedBy: "alpha")
                ])
            ]
        )
        let alphaRules = FirewallModel.rules(forNetwork: "alpha", in: firewall)
        precondition(alphaRules.map(\.index) == [1])
        let betaRules = FirewallModel.rules(forNetwork: "beta", in: firewall)
        precondition(betaRules.map(\.index) == [2])
        let generalRules = FirewallModel.generalRules(in: firewall, activeNetworks: ["alpha", "beta"])
        precondition(generalRules.map(\.index) == [0, 3])
        precondition(FirewallModel.autoAccept(forNetwork: "alpha", in: firewall))
        precondition(!FirewallModel.autoAccept(forNetwork: "beta", in: firewall))
        precondition(FirewallModel.pendingRules(forNetwork: "alpha", in: firewall).count == 1)
        precondition(FirewallModel.peerLabel(for: "abcdef", in: networks, scopedNetwork: "alpha") == "server-a (abcdef)")
        precondition(FirewallModel.peerLabel(for: "any", in: networks, scopedNetwork: nil) == "Any peer")
        precondition(FirewallModel.trafficSummary(for: firewall.rules[0]) == "ICMP (ping and diagnostics)")
        precondition(FirewallModel.trafficSummary(for: firewall.rules[1]) == "TCP · port 443")
        precondition(FirewallModel.originLabel(for: firewall.rules[1]) == "SUGGESTED")
        print("PASS: per-network and general firewall views preserve global rule indices and resolve peers")
    }
}
