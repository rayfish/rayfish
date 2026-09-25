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
        case machines
        case setSetting
        case connectPeer
        case approveConnection
        case rejectConnection
        case acceptFile
        case rejectFile
        case setSSHRule
    }

    var action: Action
    var name: String? = nil
    var code: String? = nil
    var hostname: String? = nil
    var id: String? = nil
    var setting: ProviderSetting? = nil
    var enabled: Bool? = nil
    var fileId: UInt64? = nil
    var directory: String? = nil
    var uid: UInt32? = nil
    var gid: UInt32? = nil
    var users: [String]? = nil
}

enum ProviderSetting: String, Codable {
    case dns, mdns, ssh
}

struct ProviderResponse: Codable {
    var success: Bool
    var error: String?
    var status: ProviderStatus?
    var inviteCode: String?
    var machines: [ProviderMachine]? = nil
    var message: String? = nil
}

struct ProviderStatus: Codable, Equatable {
    var active: Bool
    var ipv6: String
    var networks: [ProviderNetwork]
    var pendingRequests: [ProviderJoinRequest]
    var contactId: String? = nil
    var connectionRequests: [ProviderConnectionRequest] = []
    var dnsEnabled: Bool = true
    var mdnsEnabled: Bool = true
    var mdnsActive: Bool = true
    var files: [ProviderFile]? = nil
    var sshEnabled: Bool? = nil
    var sshRules: [ProviderSSHRule]? = nil
}

struct ProviderSSHRule: Codable, Equatable, Identifiable {
    var network: String
    var peer: String
    var users: [String]

    var id: String { "\(network):\(peer)" }
    var accounts: String {
        if users.isEmpty { return "Any account except root" }
        if users.contains("*") { return "Any account, including root" }
        return users.joined(separator: ", ")
    }
}

struct ProviderFile: Codable, Equatable, Identifiable {
    enum State: String, Codable { case pending, received }
    var transferId: UInt64
    var peer: String
    var filename: String
    var size: UInt64
    var state: State

    var id: String { "\(state.rawValue):\(transferId)" }
}

enum TunnelOwner {
    static let key = "ownerUID"

    static func uid(in configuration: [String: Any]?) -> UInt32? {
        guard let number = configuration?[key] as? NSNumber,
              let uid = UInt32(number.stringValue), uid > 0 else { return nil }
        return uid
    }
}

struct ProviderMachine: Codable, Equatable, Identifiable {
    var identity: String
    var hostname: String
    var ipv6: String
    var state: String
    var networks: [String]

    var id: String { identity }
}

struct ProviderConnectionRequest: Codable, Equatable, Identifiable {
    var id: String
    var hostname: String?
    var waitingSecs: UInt64
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
    var identity: String? = nil

    var id: String { ipv6 }

    func domain(in network: String) -> String { "\(hostname).\(network).ray" }
}
