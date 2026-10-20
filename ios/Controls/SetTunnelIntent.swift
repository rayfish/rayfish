import AppIntents

/// The Control Center toggle's action. It is built into the app as well as the
/// controls extension, so iOS can run it in either.
struct SetTunnelIntent: SetValueIntent {
    static let title: LocalizedStringResource = "Turn Rayfish On or Off"

    @Parameter(title: "On")
    var value: Bool

    func perform() async throws -> some IntentResult {
        if value {
            _ = try await VPNPreferences.start(install: false)
        } else {
            _ = try await VPNPreferences.stop()
        }
        return .result()
    }
}
