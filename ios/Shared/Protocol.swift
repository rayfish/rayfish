import Foundation

/// A request from the app to the node. The tunnel receives these as provider
/// messages; the simulator build runs them against an in-process node.
enum Command: Codable, Equatable {
    case snapshot
    case create(name: String?)
    case submitCode(String)
    case invite(network: String)
    case leave(network: String)
    case setHostname(network: String, hostname: String)
    case setDeviceName(String)
    case firewall
    case allowInbound(network: String, protocolName: String, port: String?, peer: String?)
    case removeFirewallRule(index: UInt32)
    case setDefaultInbound(String)
    case approveConnect(id: String)
    case rejectConnect(id: String)
    case acceptJoin(network: String, id: String)
    case denyJoin(network: String, id: String)
    case acceptFile(id: UInt64)
    case rejectFile(id: UInt64)
    case sendFiles(paths: [String], peer: String)
    case cancelSend(id: UInt64)
    case cancelTransfer(id: UInt64)
    case startPairing
    case unpair
    case setQuicEngine(QuicEngineChoice)
    case networkChanged

    /// How long the app waits for a reply. Joining, pairing and approving dial
    /// peers, and sending wakes the receiver first.
    var timeout: TimeInterval {
        switch self {
        case .submitCode, .approveConnect, .acceptJoin, .startPairing, .unpair, .sendFiles: 90
        default: 15
        }
    }
}

enum QuicEngineChoice: String, Codable, CaseIterable, Identifiable {
    case standalone, fqCodel

    var id: String { rawValue }
}

struct Reply: Codable {
    var error: String? = nil
    var snapshot: Snapshot? = nil
    var code: String? = nil
    var message: String? = nil
    var firewall: FirewallModel? = nil
}

/// Everything the screens show, read in one round trip.
struct Snapshot: Codable, Equatable {
    /// The node is up: peers can reach it and files can move.
    var controlPlane = false
    /// The packet tunnel carries traffic.
    var running = false
    var nodeId = ""
    var ipv6 = ""
    var deviceName = ""
    var paired = false
    var quicEngine = QuicEngineChoice.standalone
    var networks: [NetworkModel] = []
    var pendingNetworks: [String] = []
    var offers: [OfferModel] = []
    var queued: [QueuedModel] = []
    var transfers: [TransferModel] = []
    var connects: [RequestModel] = []
    var joins: [JoinRequestModel] = []
    var accepting: [UInt64] = []
}

struct NetworkModel: Codable, Equatable, Identifiable {
    enum State: String, Codable { case connected, connecting, notConnected }

    var name: String
    var ipv6: String
    var hostname: String
    var isCoordinator: Bool
    var state: State
    var reason: String?
    var peers: [PeerModel]

    var id: String { name }
    var domain: String? { hostname.isEmpty ? nil : "\(hostname).\(name).ray" }
    var peersOnline: Int { peers.filter(\.isActive).count }
}

struct PeerModel: Codable, Equatable, Identifiable {
    enum State: String, Codable { case active, idle, offline }

    var nodeId: String
    var hostname: String
    var ipv6: String
    var state: State

    var id: String { nodeId }
    var isActive: Bool { state == .active }
    var displayName: String { hostname.isEmpty ? String(nodeId.prefix(8)) : hostname }
}

struct OfferModel: Codable, Equatable, Identifiable {
    var id: UInt64
    var from: String
    var filename: String
    var size: UInt64
    var ownDevice: Bool
}

struct QueuedModel: Codable, Equatable, Identifiable {
    var id: UInt64
    var peer: String
    var filename: String
    var size: UInt64
}

struct TransferModel: Codable, Equatable, Identifiable {
    enum State: String, Codable { case offered, transferring, done, failed }

    var id: UInt64
    var outgoing: Bool
    var peer: String
    var filename: String
    var size: UInt64
    var transferred: UInt64
    var state: State

    var isActive: Bool { state == .offered || state == .transferring }
}

struct RequestModel: Codable, Equatable, Identifiable {
    var shortId: String
    var hostname: String?
    var waitingSecs: UInt64

    var id: String { shortId }
}

struct JoinRequestModel: Codable, Equatable, Identifiable {
    var network: String
    var shortId: String
    var hostname: String?

    var id: String { "\(network):\(shortId)" }
}

struct FirewallModel: Codable, Equatable {
    var defaultInbound: String
    var defaultOutbound: String
    var rules: [FirewallRuleModel]
}

struct FirewallRuleModel: Codable, Equatable {
    /// Position in the node's full rule list, which removal takes.
    var index: UInt32
    var direction: String
    var action: String
    var protocolName: String
    var port: String
    var peer: String
    var network: String
}
