import AppKit

@MainActor
final class RayfishWindow: NSWindow, NSWindowDelegate {
    init(content: NSView) {
        super.init(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 680),
                   styleMask: [.titled, .closable, .miniaturizable, .resizable],
                   backing: .buffered, defer: false)
        title = "Rayfish"
        contentView = content
        contentMinSize = NSSize(width: 820, height: 560)
        isReleasedWhenClosed = false
        collectionBehavior.insert(.moveToActiveSpace)
        delegate = self
        center()
    }

    func show() {
        if isMiniaturized { deminiaturize(nil) }
        makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }
}
