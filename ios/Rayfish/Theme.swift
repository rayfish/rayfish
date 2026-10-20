import SwiftUI
import UIKit

/// The rayfish.xyz palette and typefaces, shared with the Android and macOS apps.
enum Rf {
    static let bg = color(0x18181b)
    static let sheet = color(0x1c1c1f)
    static let card = color(0x27272a).opacity(0.5)
    static let cardBorder = color(0x3f3f46).opacity(0.7)
    static let heading = color(0xf4f4f5)
    static let body = color(0xd4d4d8)
    static let muted = color(0xa1a1aa)
    static let faint = color(0x71717a)
    static let rose400 = color(0xfb7185)
    static let rose500 = color(0xf43f5e)
    static let emerald = color(0x34d399)
    static let amber = color(0xfbbf24)
    static let primary = color(0xf4f4f5)
    static let onPrimary = color(0x18181b)

    /// Body text is the system face. Chakra Petch is kept for titles and Plex
    /// Mono for data (ids, addresses, codes), where they read well.
    static func text(_ size: CGFloat = 14) -> Font { system(size, .regular) }
    static func semibold(_ size: CGFloat = 14) -> Font { system(size, .semibold) }
    static func bold(_ size: CGFloat = 20) -> Font { .custom("ChakraPetch-Bold", size: size) }
    static func mono(_ size: CGFloat = 12) -> Font { .custom("IBMPlexMono-Regular", size: size) }
    static let logo = Font.custom("PressStart2P-Regular", size: 14)

    /// Scales with Dynamic Type, as the custom fonts do.
    private static func system(_ size: CGFloat, _ weight: UIFont.Weight) -> Font {
        Font(UIFontMetrics(forTextStyle: .body).scaledFont(for: .systemFont(ofSize: size, weight: weight)) as CTFont)
    }

    private static func color(_ hex: UInt32) -> Color {
        Color(red: Double((hex >> 16) & 255) / 255,
              green: Double((hex >> 8) & 255) / 255,
              blue: Double(hex & 255) / 255)
    }

    static func applyAppearance() {
        let tabs = UITabBarAppearance()
        tabs.configureWithOpaqueBackground()
        tabs.backgroundColor = UIColor(bg)
        UITabBar.appearance().standardAppearance = tabs
        UITabBar.appearance().scrollEdgeAppearance = tabs
        let bar = UINavigationBarAppearance()
        bar.configureWithOpaqueBackground()
        bar.backgroundColor = UIColor(bg)
        bar.shadowColor = .clear
        bar.titleTextAttributes = [.foregroundColor: UIColor(heading),
                                   .font: UIFont(name: "ChakraPetch-Bold", size: 17) ?? .boldSystemFont(ofSize: 17)]
        UINavigationBar.appearance().standardAppearance = bar
        UINavigationBar.appearance().scrollEdgeAppearance = bar
        let segments = UISegmentedControl.appearance()
        segments.selectedSegmentTintColor = UIColor(rose500)
        segments.setTitleTextAttributes([.foregroundColor: UIColor(body),
                                         .font: UIFont.systemFont(ofSize: 14, weight: .medium)], for: .normal)
        segments.setTitleTextAttributes([.foregroundColor: UIColor.white,
                                         .font: UIFont.systemFont(ofSize: 14, weight: .semibold)], for: .selected)
    }
}

struct BrandHeader<Actions: View>: View {
    var title: String?
    @ViewBuilder var actions: Actions

    var body: some View {
        HStack(spacing: 9) {
            if let title {
                Text(title).font(Rf.bold(20)).foregroundStyle(Rf.heading)
            } else {
                Image("Logo").resizable().frame(width: 26, height: 26)
                    .clipShape(RoundedRectangle(cornerRadius: 7))
                    .accessibilityHidden(true)
                Text("Rayfish").font(Rf.logo).foregroundStyle(Rf.heading)
            }
            Spacer()
            actions
        }
        .padding(.bottom, 12)
    }
}

extension BrandHeader where Actions == EmptyView {
    init(title: String? = nil) {
        self.init(title: title) { EmptyView() }
    }
}

struct StatusEyebrow: View {
    var connected: Bool
    var text: String
    var transitioning = false

    var body: some View {
        let color = transitioning ? Rf.amber : (connected ? Rf.emerald : Rf.muted)
        HStack(spacing: 7) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(text.uppercased()).font(Rf.semibold(12)).tracking(1).foregroundStyle(color)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.bottom, 14)
    }
}

struct SectionCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Rf.card)
            .clipShape(RoundedRectangle(cornerRadius: 15))
            .overlay(RoundedRectangle(cornerRadius: 15).stroke(Rf.cardBorder))
    }
}

struct SectionLabel: View {
    var text: String

    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text.uppercased()).font(Rf.semibold(12)).tracking(1).foregroundStyle(Rf.faint)
            .padding(.bottom, 8)
    }
}

struct KeyValueRow: View {
    var key: String
    var value: String
    var copy: (() -> Void)?

    var body: some View {
        let row = HStack(spacing: 12) {
            Text(key).font(Rf.text()).foregroundStyle(Rf.muted)
            Spacer(minLength: 0)
            Text(value).font(Rf.mono(14)).foregroundStyle(Rf.body)
                .lineLimit(2).multilineTextAlignment(.trailing)
            if copy != nil {
                Image(systemName: "doc.on.doc").font(.system(size: 12)).foregroundStyle(Rf.faint)
                    .accessibilityLabel("Copy")
            }
        }
        .padding(.top, 6)
        .frame(minHeight: copy == nil ? nil : 44)
        if let copy {
            Button(action: copy) { row }.buttonStyle(.plain)
        } else {
            row
        }
    }
}

struct PillButton: View {
    var title: String
    var outline = false
    var action: () -> Void

    init(_ title: String, outline: Bool = false, action: @escaping () -> Void) {
        self.title = title
        self.outline = outline
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            Text(title).font(Rf.semibold(14)).frame(maxWidth: .infinity, minHeight: 40)
        }
        .buttonStyle(PillStyle(outline: outline))
    }
}

struct PillStyle: ButtonStyle {
    var outline = false
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 16)
            .foregroundStyle(outline ? Rf.body : Rf.onPrimary)
            .background(outline ? Color.clear : Rf.primary)
            .clipShape(Capsule())
            .overlay(Capsule().stroke(outline ? Rf.cardBorder : Color.clear))
            .opacity(isEnabled ? (configuration.isPressed ? 0.75 : 1) : 0.4)
    }
}

struct LinkButton: View {
    var title: String
    var color = Rf.rose400
    var action: () -> Void

    init(_ title: String, color: Color = Rf.rose400, action: @escaping () -> Void) {
        self.title = title
        self.color = color
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            // No horizontal padding, so the text lines up with the text around it.
            Text(title).font(Rf.semibold(14)).foregroundStyle(color)
                .padding(.vertical, 6)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

struct RayfishField: View {
    var label: String
    @Binding var text: String
    var secure = false

    init(_ label: String, text: Binding<String>, secure: Bool = false) {
        self.label = label
        _text = text
        self.secure = secure
    }

    var body: some View {
        Group {
            if secure {
                SecureField(label, text: $text)
            } else {
                TextField(label, text: $text)
            }
        }
        .font(Rf.mono(14))
        .foregroundStyle(Rf.body)
        .textInputAutocapitalization(.never)
        .autocorrectionDisabled()
        .padding(.horizontal, 12).padding(.vertical, 11)
        .overlay(RoundedRectangle(cornerRadius: 11).stroke(Rf.cardBorder))
    }
}

struct ToggleCard: View {
    var title: String
    var subtitle: String
    @Binding var isOn: Bool

    var body: some View {
        SectionCard {
            Toggle(isOn: $isOn) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(Rf.semibold(16)).foregroundStyle(Rf.heading)
                    Text(subtitle).font(Rf.text(13)).foregroundStyle(Rf.muted)
                }
            }
            .tint(Rf.rose500)
        }
    }
}

struct Dot: View {
    var color: Color
    var size: CGFloat = 8

    var body: some View { Circle().fill(color).frame(width: size, height: size) }
}

extension View {
    /// The dark page every screen sits on.
    func rayfishPage() -> some View {
        frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .background(Rf.bg.ignoresSafeArea())
            .preferredColorScheme(.dark)
            .tint(Rf.rose400)
    }

    /// Covers the status bar on pages without a navigation bar, so scrolled
    /// content does not run under the clock.
    func statusBarBackdrop() -> some View {
        safeAreaInset(edge: .top, spacing: 0) {
            Color.clear.frame(height: 0).background(Rf.bg.ignoresSafeArea(edges: .top))
        }
    }
}


func copyToClipboard(_ text: String) {
    UIPasteboard.general.string = text
}

extension PeerConnState {
    var color: Color {
        switch self {
        case .active: Rf.emerald
        case .idle: Rf.amber
        case .offline: Rf.faint
        }
    }
}
