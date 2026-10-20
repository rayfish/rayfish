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
    case setQuicEngine(QuicEngine)
    /// The crash reporting toggle changed in the app group; the tunnel follows.
    case reloadTelemetry
    case sendDiagnostics

    /// How long the app waits for a reply. Joining, pairing and approving dial
    /// peers, and sending wakes the receiver first.
    var timeout: TimeInterval {
        switch self {
        case .submitCode, .approveConnect, .acceptJoin, .startPairing, .unpair, .sendFiles: 90
        default: 15
        }
    }
}

struct Reply: Codable {
    var error: String? = nil
    var snapshot: Snapshot? = nil
    var code: String? = nil
    var message: String? = nil
    var firewall: FirewallStateInfo? = nil
}

/// Everything the screens show, read in one round trip. The core's own
/// records, which the bindings make Codable for the trip from the tunnel.
struct Snapshot: Codable, Equatable {
    /// The node is up: peers can reach it and files can move.
    var controlPlane = false
    var nodeId = ""
    var ipv6 = ""
    var deviceName = ""
    var paired = false
    var quicEngine = QuicEngine.standalone
    var networks: [NetworkDetail] = []
    var pendingNetworks: [String] = []
    var offers: [FileOffer] = []
    var queued: [QueuedSend] = []
    var transfers: [Transfer] = []
    var connects: [PendingRequest] = []
    var joins: [JoinRequestModel] = []
}

extension NetworkDetail: Identifiable {
    public var id: String { name }
    var domain: String? { hostname.isEmpty ? nil : "\(hostname).\(name).ray" }
    var peersOnline: Int { peers.filter(\.isActive).count }
}

extension PeerInfo: Identifiable {
    public var id: String { nodeId }
    var isActive: Bool { state == .active }
    func domain(in network: NetworkDetail) -> String? {
        hostname.isEmpty ? nil : "\(hostname).\(network.name).ray"
    }
    var displayName: String { hostname.isEmpty ? String(nodeId.prefix(8)) : hostname }
}

extension FileOffer: Identifiable {}
extension QueuedSend: Identifiable {}

extension Transfer: Identifiable {
    var isActive: Bool { state == .offered || state == .transferring }
}

extension PendingRequest: Identifiable {
    public var id: String { shortId }
}

/// A join request carries no network of its own; the list it came from does.
struct JoinRequestModel: Codable, Equatable, Identifiable {
    var network: String
    var shortId: String
    var hostname: String?

    var id: String { "\(network):\(shortId)" }
}
