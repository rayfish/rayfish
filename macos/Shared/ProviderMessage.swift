import Foundation

struct ProviderRequest: Codable {
    enum Action: String, Codable {
        case status
        case create
        case join
        case invite
        case leave
    }

    var action: Action
    var name: String? = nil
    var code: String? = nil
    var hostname: String? = nil
}

struct ProviderResponse: Codable {
    var success: Bool
    var error: String?
    var status: ProviderStatus?
    var inviteCode: String?
}

struct ProviderStatus: Codable, Equatable {
    var active: Bool
    var ipv6: String
    var networks: [ProviderNetwork]
}

struct ProviderNetwork: Codable, Equatable, Identifiable {
    var name: String
    var hostname: String
    var ipv6: String
    var role: String
    var peers: [ProviderPeer]

    var id: String { name }
}

struct ProviderPeer: Codable, Equatable, Identifiable {
    var hostname: String
    var ipv6: String
    var state: String
    var latencyMs: UInt32?
    var isOwnDevice: Bool

    var id: String { ipv6 }
}
