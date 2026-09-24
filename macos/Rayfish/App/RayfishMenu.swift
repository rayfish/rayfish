import AppKit
import Combine
import SwiftUI

@MainActor
final class RayfishMenu: NSObject, NSMenuDelegate {
    private let controller: TunnelController
    private let openWindow: () -> Void
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let header = NSMenuItem()
    private var observation: AnyCancellable?
    private var updateScheduled = false

    init(controller: TunnelController, menu: NSMenu = NSMenu(), openWindow: @escaping () -> Void) {
        self.controller = controller
        self.openWindow = openWindow
        super.init()
        let image = NSImage(named: "MenuBarIcon")?.copy() as? NSImage
        image?.size = NSSize(width: 18, height: 18)
        image?.isTemplate = true
        statusItem.button?.image = image
        statusItem.button?.setAccessibilityLabel("Rayfish")
        menu.autoenablesItems = false
        menu.delegate = self
        statusItem.menu = menu
        // A custom menu view preserves the real switch; SwiftUI menu toggles become checkmarks.
        let view = NSHostingView(rootView: RayfishConnectionSwitch(controller: controller))
        view.frame.size = view.fittingSize
        header.view = view
        header.identifier = .init("connection")
        update(menu)
        observation = controller.objectWillChange.sink { [weak self] in
            guard let self, !self.updateScheduled else { return }
            self.updateScheduled = true
            // Published values change after this notification. Also run while
            // AppKit is tracking a menu, rather than waiting for it to close.
            RunLoop.main.perform(inModes: [.common, .eventTracking]) { [weak self] in
                MainActor.assumeIsolated {
                    guard let self else { return }
                    self.updateScheduled = false
                    if let menu = self.statusItem.menu { self.update(menu) }
                }
            }
        }
    }

    func menuNeedsUpdate(_ menu: NSMenu) { update(menu) }

    private func update(_ menu: NSMenu) {
        var items = [header, separator("header-end")]

        if let status = controller.status {
            let copy = item("Copy This Mac's IP Address", action: #selector(copyAddress(_:)))
            copy.representedObject = status.ipv6
            copy.toolTip = status.ipv6
            items.append(copy)
            items.append(separator("address-end"))
            items.append(item("Networks"))
            if status.networks.isEmpty { items.append(item("No networks yet")) }
            for network in status.networks {
                let entry = item("\(network.name) (\(network.peers.count) devices)", id: "network:\(network.name)")
                entry.isEnabled = true
                let peers = NSMenu()
                peers.autoenablesItems = false
                peers.addItem(item("\(network.hostname).\(network.name).ray", id: "hostname"))
                peers.addItem(separator("hostname-end"))
                for peer in network.peers {
                    let entry = item("\(peer.hostname) (\(peer.state))", action: #selector(copyAddress(_:)), id: "peer:\(peer.ipv6)")
                    entry.representedObject = peer.domain(in: network.name)
                    entry.toolTip = "Copy \(peer.domain(in: network.name))"
                    entry.image = NSImage(systemSymbolName: peer.state == "idle" ? "circle" : "circle.fill",
                                          accessibilityDescription: peer.state)
                    peers.addItem(entry)
                }
                entry.submenu = peers
                items.append(entry)
            }
        }
        if let activity = controller.activity {
            items.append(separator("activity-start"))
            items.append(item(activity, id: "activity"))
        }
        if let error = controller.error {
            items.append(separator("error-start"))
            let entry = item("Connection Issue: Open Rayfish", action: #selector(showWindow))
            entry.toolTip = error
            items.append(entry)
        }
        items.append(separator("footer-start"))
        items.append(item("Open Rayfish", action: #selector(showWindow), key: "o"))
        let quit = item("Disconnect and Quit", action: #selector(NSApplication.terminate(_:)), key: "q")
        quit.target = NSApp
        items.append(quit)
        reconcile(menu, with: items)
    }

    // Keep existing rows and submenus alive so an open submenu stays open.
    private func reconcile(_ menu: NSMenu, with desired: [NSMenuItem]) {
        let identifiers = Set(desired.map(\.identifier))
        for old in menu.items where !identifiers.contains(old.identifier) { menu.removeItem(old) }
        for (index, next) in desired.enumerated() {
            let current = menu.items.first { $0.identifier == next.identifier } ?? next
            if current !== next {
                current.title = next.title
                current.isEnabled = next.isEnabled
                current.toolTip = next.toolTip
                current.representedObject = next.representedObject
                current.image = next.image
                if let submenu = next.submenu {
                    if let existing = current.submenu { reconcile(existing, with: submenu.items) }
                    else { next.submenu = nil; current.submenu = submenu }
                } else { current.submenu = nil }
            }
            if menu.index(of: current) != index {
                current.menu?.removeItem(current)
                menu.insertItem(current, at: index)
            }
        }
    }

    private func separator(_ id: String) -> NSMenuItem {
        let item = NSMenuItem.separator()
        item.identifier = .init(id)
        return item
    }

    private func item(_ title: String, action: Selector? = nil, key: String = "", id: String? = nil) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
        item.identifier = .init(id ?? title)
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
