import Foundation

struct ProviderRequest: Codable {
    enum Action: String, Codable {
        case status
        case create
        case join
        case invite
        case leave
        case setHostname
        case acceptRequest
        case denyRequest
    }

    var action: Action
    var name: String? = nil
    var code: String? = nil
    var hostname: String? = nil
    var id: String? = nil
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
    var pendingRequests: [ProviderJoinRequest]
}

struct ProviderJoinRequest: Codable, Equatable, Identifiable {
    var network: String
    var id: String
    var hostname: String?
    var waitingSecs: UInt64
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
