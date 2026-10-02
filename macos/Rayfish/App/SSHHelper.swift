import Foundation
import ServiceManagement

enum SSHHelper {
    private static var service: SMAppService {
        SMAppService.daemon(plistName: "com.rayfish.app.ssh.plist")
    }

    static var approvalMessage: String? {
        guard service.status != .enabled else { return nil }
        return "To use mesh SSH or IPv4 services, allow Rayfish in System Settings > General > Login Items & Extensions."
    }

    static func register(openSettings: Bool = false) throws {
        let helper = service
        if helper.status == .notRegistered || helper.status == .notFound {
            try helper.register()
        }
        if openSettings, helper.status == .requiresApproval {
            SMAppService.openSystemSettingsLoginItems()
        }
    }
}
