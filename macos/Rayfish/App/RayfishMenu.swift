import AppKit
import SwiftUI

@MainActor
final class RayfishMenu: NSObject, NSMenuDelegate {
    private let controller: TunnelController
    private let openWindow: () -> Void
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)

    init(controller: TunnelController, openWindow: @escaping () -> Void) {
        self.controller = controller
        self.openWindow = openWindow
        super.init()
        let image = NSImage(named: "MenuBarIcon")?.copy() as? NSImage
        image?.size = NSSize(width: 18, height: 18)
        image?.isTemplate = true
        statusItem.button?.image = image
        statusItem.button?.setAccessibilityLabel("Rayfish")
        let menu = NSMenu()
        menu.autoenablesItems = false
        menu.delegate = self
        statusItem.menu = menu
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        // A custom menu view preserves the real switch; SwiftUI menu toggles become checkmarks.
        let header = NSMenuItem()
        let view = NSHostingView(rootView: RayfishConnectionSwitch(controller: controller) {
            menu.cancelTracking()
        })
        view.frame.size = view.fittingSize
        header.view = view
        menu.addItem(header)
        menu.addItem(.separator())

        if let status = controller.status {
            let copy = item("Copy This Mac's IP Address", action: #selector(copyAddress(_:)))
            copy.representedObject = status.ipv6
            copy.toolTip = status.ipv6
            menu.addItem(copy)
            menu.addItem(.separator())
            menu.addItem(item("Networks"))
            if status.networks.isEmpty { menu.addItem(item("No networks yet")) }
            for network in status.networks {
                let entry = item("\(network.name) (\(network.peers.count) devices)")
                entry.isEnabled = true
                let peers = NSMenu()
                peers.autoenablesItems = false
                peers.addItem(item("\(network.hostname).\(network.name).ray"))
                peers.addItem(.separator())
                for peer in network.peers {
                    let entry = item("\(peer.hostname) (\(peer.state))", action: #selector(copyAddress(_:)))
                    entry.representedObject = peer.domain(in: network.name)
                    entry.toolTip = "Copy \(peer.domain(in: network.name))"
                    entry.image = NSImage(systemSymbolName: peer.state == "idle" ? "circle" : "circle.fill",
                                          accessibilityDescription: peer.state)
                    peers.addItem(entry)
                }
                entry.submenu = peers
                menu.addItem(entry)
            }
        }
        if let activity = controller.activity {
            menu.addItem(.separator())
            menu.addItem(item(activity))
        }
        if let error = controller.error {
            menu.addItem(.separator())
            let entry = item("Connection Issue: Open Rayfish", action: #selector(showWindow))
            entry.toolTip = error
            menu.addItem(entry)
        }
        menu.addItem(.separator())
        menu.addItem(item("Open Rayfish", action: #selector(showWindow), key: "0"))
        let quit = item("Disconnect and Quit", action: #selector(NSApplication.terminate(_:)), key: "q")
        quit.target = NSApp
        menu.addItem(quit)
    }

    private func item(_ title: String, action: Selector? = nil, key: String = "") -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
        item.target = self
        item.isEnabled = action != nil
        return item
    }

    @objc private func showWindow() { openWindow() }

    @objc private func copyAddress(_ sender: NSMenuItem) {
        guard let address = sender.representedObject as? String else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(address, forType: .string)
    }
}

private struct RayfishConnectionSwitch: View {
    @ObservedObject var controller: TunnelController
    let dismiss: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("Rayfish").font(.system(size: 13, weight: .medium))
                Text(controller.connectionLabel.capitalized)
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("VPN connection", isOn: Binding(
                get: { controller.isConnected },
                set: { connected in
                    dismiss()
                    Task {
                        if connected { await controller.connect() }
                        else { await controller.disconnect() }
                    }
                }
            ))
            .toggleStyle(.switch)
            .environment(\.controlActiveState, .active)
            .labelsHidden()
            .disabled(controller.isLoading
                      || controller.connectionStatus == .connecting
                      || controller.connectionStatus == .reasserting
                      || controller.connectionStatus == .disconnecting)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .frame(width: 300)
    }
}
