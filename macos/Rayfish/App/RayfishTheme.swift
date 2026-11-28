import AppKit
import CoreText
import SwiftUI

/// Colors and typefaces shared with src/cli/gui.html and rayfish.xyz.
enum RayfishTheme {
    static let background = color(0x18181b)
    static let panel = color(0x1c1c20)
    static let panelRaised = color(0x222227)
    static let deep = color(0x09090b)
    static let line = color(0x27272a)
    static let border = color(0x3f3f46)
    static let borderHover = color(0x52525b)
    static let ink = color(0xf4f4f5)
    static let body = color(0xd4d4d8)
    static let muted = color(0xa1a1aa)
    static let faint = color(0x71717a)
    static let rose = color(0xfb7185)
    static let accent = color(0xf43f5e)
    static let accentHover = color(0xe11d48)
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

    static func color(_ hex: UInt32) -> Color {
        Color(red: Double((hex >> 16) & 255) / 255,
              green: Double((hex >> 8) & 255) / 255,
              blue: Double(hex & 255) / 255)
    }
}

struct RayfishButtonStyle: ButtonStyle {
    enum Kind { case secondary, primary, danger, connected, subtle }
    enum Size { case regular, compact, inline }
    var kind: Kind = .secondary
    var size: Size = .regular

    func makeBody(configuration: Configuration) -> some View {
        StyledButtonBody(configuration: configuration, kind: kind, size: size)
    }

    private struct StyledButtonBody: View {
        let configuration: Configuration
        let kind: Kind
        let size: Size
        @Environment(\.isEnabled) private var isEnabled
        @State private var isHovered = false

        var body: some View {
            configuration.label
                .font(RayfishTheme.heading(fontSize))
                .foregroundColor(foreground)
                .padding(.horizontal, horizontalPadding)
                .frame(minHeight: minHeight)
                .background(backgroundFill)
                .clipShape(RoundedRectangle(cornerRadius: cornerRadius))
                .overlay(RoundedRectangle(cornerRadius: cornerRadius).stroke(border, lineWidth: 1))
                .opacity(isEnabled ? 1 : 0.42)
                .contentShape(RoundedRectangle(cornerRadius: cornerRadius))
                .onHover { isHovered = $0 }
        }

        private var fontSize: CGFloat {
            switch size {
            case .regular: 13
            case .compact: 12
            case .inline: 11.5
            }
        }

        private var horizontalPadding: CGFloat {
            switch size {
            case .regular: 13
            case .compact: 10
            case .inline: 8
            }
        }

        private var minHeight: CGFloat {
            switch size {
            case .regular: 32
            case .compact: 28
            case .inline: 22
            }
        }

        private var cornerRadius: CGFloat {
            size == .inline ? 6 : 7
        }

        private var foreground: Color {
            switch kind {
            case .primary: .white
            case .danger: RayfishTheme.rose
            case .connected: RayfishTheme.green
            case .subtle: isHovered ? RayfishTheme.ink : RayfishTheme.muted
            case .secondary: isHovered ? RayfishTheme.ink : RayfishTheme.body
            }
        }

        private var backgroundFill: Color {
            switch kind {
            case .primary:
                if configuration.isPressed { return RayfishTheme.accentHover.opacity(0.9) }
                return isHovered && isEnabled ? RayfishTheme.accentHover : RayfishTheme.accent
            case .danger:
                if configuration.isPressed { return RayfishTheme.accent.opacity(0.14) }
                return isHovered && isEnabled ? RayfishTheme.accent.opacity(0.08) : Color.clear
            case .connected:
                if configuration.isPressed { return RayfishTheme.green.opacity(0.14) }
                return isHovered && isEnabled ? RayfishTheme.green.opacity(0.07) : Color.clear
            case .subtle:
                if configuration.isPressed { return Color.white.opacity(0.08) }
                return isHovered && isEnabled ? Color.white.opacity(0.045) : Color.clear
            case .secondary:
                if configuration.isPressed { return Color.white.opacity(0.08) }
                return isHovered && isEnabled ? Color.white.opacity(0.04) : Color.clear
            }
        }

        private var border: Color {
            switch kind {
            case .primary:
                isHovered && isEnabled ? RayfishTheme.accentHover : RayfishTheme.accent
            case .danger:
                isHovered && isEnabled ? RayfishTheme.accent.opacity(0.65) : RayfishTheme.accent.opacity(0.35)
            case .connected:
                isHovered && isEnabled ? RayfishTheme.green.opacity(0.7) : RayfishTheme.green.opacity(0.4)
            case .subtle:
                isHovered && isEnabled ? RayfishTheme.border.opacity(0.7) : Color.clear
            case .secondary:
                isHovered && isEnabled ? RayfishTheme.borderHover : RayfishTheme.border
            }
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

struct RayfishSearchField: View {
    let prompt: String
    @Binding var text: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(RayfishTheme.faint)
            TextField(prompt, text: $text)
                .textFieldStyle(.plain)
                .font(RayfishTheme.text(13))
                .foregroundColor(RayfishTheme.ink)
            if !text.isEmpty {
                Button {
                    text = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 12))
                        .foregroundColor(RayfishTheme.muted)
                }
                .buttonStyle(.plain)
                .help("Clear filter")
            }
        }
        .padding(.horizontal, 11)
        .frame(height: 32)
        .background(RayfishTheme.deep)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(RayfishTheme.border))
    }
}

struct RayfishBadge: View {
    enum Tone { case neutral, accent, success, warning }
    let text: String
    var tone: Tone = .neutral

    var body: some View {
        Text(text)
            .font(RayfishTheme.mono(10))
            .tracking(0.6)
            .foregroundColor(foreground)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(background)
            .clipShape(Capsule())
            .overlay(Capsule().stroke(stroke, lineWidth: 1))
    }

    private var foreground: Color {
        switch tone {
        case .neutral: RayfishTheme.muted
        case .accent: RayfishTheme.rose
        case .success: RayfishTheme.green
        case .warning: RayfishTheme.amber
        }
    }

    private var background: Color {
        switch tone {
        case .neutral: Color.white.opacity(0.02)
        case .accent: RayfishTheme.accent.opacity(0.08)
        case .success: RayfishTheme.green.opacity(0.08)
        case .warning: RayfishTheme.amber.opacity(0.08)
        }
    }

    private var stroke: Color {
        switch tone {
        case .neutral: RayfishTheme.border
        case .accent: RayfishTheme.rose.opacity(0.35)
        case .success: RayfishTheme.green.opacity(0.35)
        case .warning: RayfishTheme.amber.opacity(0.35)
        }
    }
}

struct EmptyState: View {
    let title: String
    let description: String
    var body: some View {
        VStack(spacing: 8) {
            Text(title).font(RayfishTheme.heading(15)).foregroundColor(RayfishTheme.body)
            Text(description)
                .font(RayfishTheme.text(14))
                .foregroundColor(RayfishTheme.muted)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 460)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 36)
        .padding(.horizontal, 20)
        .rayfishCard()
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
