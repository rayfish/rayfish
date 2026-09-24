import AppKit
import CoreText
import SwiftUI

/// Colors and typefaces shared with src/cli/gui.html and rayfish.xyz.
enum RayfishTheme {
    static let background = color(0x18181b)
    static let panel = color(0x1c1c20)
    static let deep = color(0x09090b)
    static let line = color(0x27272a)
    static let border = color(0x3f3f46)
    static let ink = color(0xf4f4f5)
    static let body = color(0xd4d4d8)
    static let muted = color(0xa1a1aa)
    static let faint = color(0x71717a)
    static let rose = color(0xfb7185)
    static let accent = color(0xf43f5e)
    static let green = color(0x34d399)
    static let amber = color(0xfbbf24)

    static func text(_ size: CGFloat = 15) -> Font { .custom("ChakraPetch-Regular", size: size) }
    static func heading(_ size: CGFloat = 17) -> Font { .custom("ChakraPetch-SemiBold", size: size) }
    static func mono(_ size: CGFloat = 12) -> Font { .custom("IBMPlexMono-Regular", size: size) }
    static let logo = Font.custom("PressStart2P-Regular", size: 15)

    static func registerFonts() {
        for name in ["ChakraPetch-Regular", "ChakraPetch-SemiBold", "IBMPlexMono-Regular", "PressStart2P-Regular"] {
            if let url = Bundle.main.url(forResource: name, withExtension: "ttf", subdirectory: "Fonts") {
                CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
            }
        }
    }

    private static func color(_ hex: UInt32) -> Color {
        Color(red: Double((hex >> 16) & 255) / 255,
              green: Double((hex >> 8) & 255) / 255,
              blue: Double(hex & 255) / 255)
    }
}

struct RayfishButtonStyle: ButtonStyle {
    enum Kind { case secondary, primary, danger, connected }
    var kind: Kind = .secondary
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(RayfishTheme.heading(13))
            .foregroundColor(foreground)
            .padding(.horizontal, 12)
            .frame(minHeight: 32)
            .background(kind == .primary ? RayfishTheme.accent : Color.clear)
            .background(configuration.isPressed ? Color.white.opacity(0.06) : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 7))
            .overlay(RoundedRectangle(cornerRadius: 7).stroke(border, lineWidth: 1))
            .opacity(isEnabled ? 1 : 0.4)
            .contentShape(RoundedRectangle(cornerRadius: 7))
    }

    private var foreground: Color {
        switch kind {
        case .primary: .white
        case .danger: RayfishTheme.rose
        case .connected: RayfishTheme.green
        case .secondary: RayfishTheme.body
        }
    }
    private var border: Color {
        switch kind {
        case .primary: RayfishTheme.accent
        case .danger: RayfishTheme.accent.opacity(0.35)
        case .connected: RayfishTheme.green.opacity(0.4)
        case .secondary: RayfishTheme.border
        }
    }
}

struct RayfishFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .textFieldStyle(.plain)
            .padding(.horizontal, 11)
            .padding(.vertical, 9)
            .background(RayfishTheme.deep)
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(RayfishTheme.border))
    }
}

extension View {
    func rayfishCard() -> some View {
        background(RayfishTheme.panel)
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(RayfishTheme.line))
    }

    func rayfishSheet() -> some View {
        padding(24)
            .font(RayfishTheme.text())
            .foregroundColor(RayfishTheme.body)
            .background(RayfishTheme.panel)
            .textFieldStyle(RayfishFieldStyle())
            .buttonStyle(RayfishButtonStyle())
            .tint(RayfishTheme.accent)
            .preferredColorScheme(.dark)
    }
}
