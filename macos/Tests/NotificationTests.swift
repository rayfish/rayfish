import Foundation

@main
struct NotificationTests {
    static func main() throws {
        precondition(TunnelOwner.uid(in: nil) == nil)
        for invalid in [NSNumber(value: 0), NSNumber(value: -1), NSNumber(value: 1.5), NSNumber(value: UInt64.max)] {
            precondition(TunnelOwner.uid(in: [TunnelOwner.key: invalid]) == nil)
        }
        precondition(TunnelOwner.uid(in: [TunnelOwner.key: NSNumber(value: 501)]) == 501)
        print("PASS: tunnel ownership rejects absent, root, fractional and overflowing UIDs")

        var tracker = RayfishNoticeTracker()
        var status = ProviderStatus(active: true, ipv6: "200::1", networks: [], pendingRequests: [
            ProviderJoinRequest(network: "box", id: "abc", hostname: "studio", waitingSecs: 1)
        ], connectionRequests: [ProviderConnectionRequest(id: "def", hostname: "friend", waitingSecs: 1)], files: [
            ProviderFile(transferId: 1, peer: "friend", filename: "photo.jpg", size: 42, state: .pending),
            ProviderFile(transferId: 9, peer: "friend", filename: "old.jpg", size: 42, state: .received)
        ])
        let first = tracker.update(status)
        precondition(first.added.count == 3)
        precondition(Set(first.added.map(\.page)) == [.networks, .devices, .files])
        precondition(tracker.update(status).added.isEmpty)
        status.pendingRequests[0].waitingSecs += 3
        status.connectionRequests[0].waitingSecs += 3
        precondition(tracker.update(status).added.isEmpty)
        print("PASS: first snapshot notifies pending events, skips old completed files and ignores repeated polls")

        status.pendingRequests.append(ProviderJoinRequest(network: "other", id: "abc", hostname: "studio", waitingSecs: 1))
        precondition(tracker.update(status).added.count == 1)
        status.files?.append(ProviderFile(transferId: 10, peer: "friend", filename: "auto.jpg", size: 42, state: .received))
        let received = tracker.update(status)
        precondition(received.added.count == 1 && received.added[0].title == "File received")
        status.pendingRequests = []
        status.connectionRequests = []
        status.files = []
        precondition(tracker.update(status).removed.count == 6)
        precondition(tracker.update(status).added.isEmpty)
        _ = tracker.update(nil)
        status.files = [ProviderFile(transferId: 1, peer: "friend", filename: "photo.jpg", size: 42, state: .pending)]
        precondition(tracker.update(status).added.count == 1)
        print("PASS: network scopes, automatic receives, resolved requests and reconnects are tracked")

        let encoded = try JSONEncoder().encode(status)
        let decoded = try JSONDecoder().decode(ProviderStatus.self, from: encoded)
        precondition(decoded == status)
        precondition(ProviderSSHRule(network: "box", peer: "*", users: []).accounts == "Any account except root")
        precondition(ProviderSSHRule(network: "box", peer: "*", users: ["*"]).accounts == "Any account, including root")
        print("PASS: file status round-trips and SSH account scopes remain distinct")
    }
}
