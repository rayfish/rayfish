import SwiftUI

struct PeerRow: View {
    let peer: ProviderPeer
    let domains: [String]
    let copyText: (String, String) -> Void
    var onAddFirewallRule: (() -> Void)? = nil
    @State private var isHovered: Bool

    init(
        peer: ProviderPeer,
        domains: [String],
        copyText: @escaping (String, String) -> Void,
        onAddFirewallRule: (() -> Void)? = nil,
        isHovered: Bool = false
    ) {
        self.peer = peer
        self.domains = domains
        self.copyText = copyText
        self.onAddFirewallRule = onAddFirewallRule
        _isHovered = State(initialValue: isHovered)
    }

    private var color: Color {
        peer.state == "direct" ? RayfishTheme.green : peer.state == "relay" ? RayfishTheme.amber : RayfishTheme.faint
    }

    var body: some View {
        HStack(spacing: 12) {
            Circle().fill(color).frame(width: 7, height: 7)
            Text(peer.hostname)
                .foregroundColor(isHovered && !domains.isEmpty ? RayfishTheme.rose : RayfishTheme.ink)
                .lineLimit(1)
                .frame(minWidth: 120, alignment: .leading)
            if peer.isOwnDevice {
                Text("YOU").font(RayfishTheme.mono(9)).foregroundColor(RayfishTheme.faint)
                    .lineLimit(1)
                    .fixedSize()
                    .padding(.horizontal, 5).padding(.vertical, 2)
                    .overlay(RoundedRectangle(cornerRadius: 4).stroke(RayfishTheme.border))
            }
            Text(peer.ipv6).foregroundColor(RayfishTheme.muted).lineLimit(1)
            Spacer(minLength: 8)
            if let domain = domains.first {
                Text("click to copy")
                    .font(RayfishTheme.mono(10))
                    .foregroundColor(RayfishTheme.faint)
                    .lineLimit(1)
                    .fixedSize()
                    .opacity(isHovered ? 1 : 0)
                    .allowsHitTesting(isHovered)
                    .accessibilityHidden(!isHovered)
                    .help("Copy \(domain)")
            }
            if let onAddFirewallRule {
                Button("+ Rule", action: onAddFirewallRule)
                    .buttonStyle(RayfishButtonStyle(kind: .secondary, size: .inline))
                    .fixedSize()
                    .opacity(isHovered ? 1 : 0)
                    .allowsHitTesting(isHovered)
                    .accessibilityHidden(!isHovered)
                    .help("Add a firewall rule for \(peer.hostname.isEmpty ? peer.ipv6 : peer.hostname)")
            }
            Text(peer.state)
                .foregroundColor(color)
                .lineLimit(1)
                .fixedSize()
            if let latency = peer.latencyMs {
                Text("\(latency) ms")
                    .foregroundColor(RayfishTheme.faint)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
                    .frame(minWidth: 52, alignment: .trailing)
            }
        }
        .font(RayfishTheme.mono(12))
        .frame(minHeight: 22)
        .padding(.horizontal, 16)
        .padding(.vertical, 7)
        .background(isHovered ? Color.white.opacity(0.025) : Color.clear)
        .contentShape(Rectangle())
        .onHover { isHovered = $0 }
        .onTapGesture {
            if let domain = domains.first {
                copyText(domain, "Copied \(domain)")
            } else {
                copyText(peer.ipv6, "Copied \(peer.ipv6)")
            }
        }
        .contextMenu {
            ForEach(domains, id: \.self) { domain in
                Button("Copy \(domain)") {
                    copyText(domain, "Copied \(domain)")
                }
            }
            Button("Copy IPv6 (\(peer.ipv6))") {
                copyText(peer.ipv6, "Copied IPv6 address")
            }
            if let identity = peer.identity {
                Button("Copy identity") {
                    copyText(identity, "Copied peer identity")
                }
            }
            if let onAddFirewallRule {
                Divider()
                Button("Add firewall rule for \(peer.hostname.isEmpty ? peer.ipv6 : peer.hostname)...") {
                    onAddFirewallRule()
                }
            }
        }
    }
}
