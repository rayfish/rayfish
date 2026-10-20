import AppIntents
import SwiftUI
import WidgetKit

@main
struct RayfishControls: WidgetBundle {
    var body: some Widget {
        TunnelControl()
    }
}

/// Turns the VPN on and off from Control Center, the Lock Screen or the
/// Action button.
struct TunnelControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: VPNPreferences.controlKind, provider: Provider()) { isOn in
            ControlWidgetToggle("Rayfish", isOn: isOn, action: SetTunnelIntent()) { isOn in
                Label(isOn ? "On" : "Off", image: "Rayfish")
            }
        }
        .displayName("Rayfish")
        .description("Turn the Rayfish VPN on or off.")
    }

    struct Provider: ControlValueProvider {
        var previewValue: Bool { false }

        func currentValue() async throws -> Bool {
            switch try await VPNPreferences.load()?.connection.status {
            case .connected, .connecting, .reasserting: true
            default: false
            }
        }
    }
}
