import Foundation
import NetworkExtension

@MainActor
private final class ReplyBarrier {
    private var waiting: [(Data, (Data?) -> Void)] = []

    func send(_ data: Data, reply: @escaping (Data?) -> Void) {
        waiting.append((data, reply))
        // Neither request completes until both have arrived.
        if waiting.count == 2 {
            for (data, reply) in waiting.reversed() { reply(data) }
            waiting.removeAll()
        }
    }
}

@main
struct TunnelIPCTests {
    @MainActor
    static func main() async throws {
        setbuf(stdout, nil)
        try await testManagerCache()
        let setting = ProviderRequest(action: .setSetting, setting: .dns, enabled: false)
        let decodedSetting = try JSONDecoder().decode(ProviderRequest.self, from: JSONEncoder().encode(setting))
        precondition(decodedSetting.setting == .dns && decodedSetting.enabled == false)
        let machine = ProviderMachine(identity: "machine-id", hostname: "server", ipv6: "200::1", state: "offline", networks: [])
        let inventory = ProviderResponse(success: true, error: nil, status: nil, inviteCode: nil, machines: [machine])
        let decodedInventory = try JSONDecoder().decode(ProviderResponse.self, from: JSONEncoder().encode(inventory))
        precondition(decodedInventory.status == nil && decodedInventory.machines == [machine])
        let status = ProviderStatus(active: true, ipv6: "200::2", networks: [], pendingRequests: [],
                                    contactId: "contact-id", connectionRequests: [
                                        ProviderConnectionRequest(id: "request-id", hostname: "laptop", waitingSecs: 7)
                                    ], dnsEnabled: false, mdnsEnabled: false, mdnsActive: true)
        let decodedStatus = try JSONDecoder().decode(ProviderStatus.self, from: JSONEncoder().encode(status))
        precondition(decodedStatus == status)
        precondition(status.needsTCPHelper)
        var noServices = status
        noServices.v4BridgeEnabled = false
        noServices.sshEnabled = false
        precondition(!noServices.needsTCPHelper)
        noServices.sshEnabled = true
        precondition(noServices.needsTCPHelper)
        noServices.sshEnabled = false
        noServices.v4BridgeEnabled = true
        precondition(noServices.needsTCPHelper)
        print("PASS: settings, peer requests, and independent machine inventory round-trip")

        let barrier = ReplyBarrier()
        async let first = TunnelIPC.send(Data("first".utf8), using: barrier.send)
        async let second = TunnelIPC.send(Data("second".utf8), using: barrier.send)
        let responses = try await [first, second]
        precondition(responses == [Data("first".utf8), Data("second".utf8)])
        print("PASS: concurrent provider requests receive their own replies")

        let expected = NSError(domain: "ProviderTest", code: 7)
        do {
            _ = try await TunnelIPC.send(Data()) { _, _ in throw expected }
            fatalError("A send error was ignored")
        } catch {
            precondition(error as NSError == expected)
            print("PASS: synchronous send errors propagate")
        }

        do {
            _ = try await TunnelIPC.send(Data()) { _, reply in reply(nil) }
            fatalError("An absent response was accepted")
        } catch TunnelIPCError.noResponse {
            print("PASS: absent provider response is reported")
        }

        var lateReply: ((Data?) -> Void)?
        do {
            _ = try await TunnelIPC.send(Data(), timeout: 0.01) { _, reply in lateReply = reply }
            fatalError("A stalled request did not time out")
        } catch TunnelIPCError.timedOut {
            lateReply?(Data())
            lateReply?(nil)
            print("PASS: timeout ignores late and duplicate replies")
        }

        let immediate = try await TunnelIPC.send(Data("immediate".utf8)) { data, reply in
            reply(data)
            reply(nil)
            throw expected
        }
        precondition(immediate == Data("immediate".utf8))
        print("PASS: completed response cannot be replaced by an error")
    }

    @MainActor
    private static func testManagerCache() async throws {
        func manager(provider: String = TunnelManagerCache.providerIdentifier) -> NETunnelProviderManager {
            let manager = NETunnelProviderManager()
            let configuration = NETunnelProviderProtocol()
            configuration.providerBundleIdentifier = provider
            manager.protocolConfiguration = configuration
            return manager
        }

        let center = NotificationCenter()
        let original = manager()
        let replacement = manager()
        var available = [manager(provider: "com.example.other"), original]
        var loads = 0
        let cache = TunnelManagerCache(notificationCenter: center) {
            loads += 1
            await Task.yield()
            return available
        }
        async let first = cache.load()
        async let second = cache.load()
        let concurrent = try await [first, second]
        precondition(concurrent.allSatisfy { $0 === original } && loads == 1)
        for _ in 0..<1_000 {
            let loaded = try await cache.load()
            precondition(loaded === original)
        }
        precondition(loads == 1)
        print("PASS: concurrent requests and repeated polls share one VPN manager")

        available = [replacement]
        // Connection state notifications must not replace the manager/session.
        center.post(name: .NEVPNStatusDidChange, object: original.connection)
        let unchanged = try await cache.load()
        precondition(unchanged === original && loads == 1)
        center.post(name: .NEVPNConfigurationChange, object: nil)
        let changed = try await cache.load()
        precondition(changed === replacement && loads == 2)
        available = []
        center.post(name: .NEVPNConfigurationChange, object: nil)
        let removed = try await cache.load()
        let stillRemoved = try await cache.load()
        precondition(removed == nil && stillRemoved == nil && loads == 3)
        available = [original]
        center.post(name: .NEVPNConfigurationChange, object: nil)
        let added = try await cache.load()
        precondition(added === original && loads == 4)
        print("PASS: configuration changes refresh replaced, removed and newly added VPNs")

        var pending: CheckedContinuation<[NETunnelProviderManager], Error>?
        let delayed = TunnelManagerCache(notificationCenter: center) {
            try await withCheckedThrowingContinuation { pending = $0 }
        }
        let stale = Task { try await delayed.load() }
        while pending == nil { await Task.yield() }
        delayed.store(replacement)
        pending?.resume(returning: [original])
        let stored = try await stale.value
        precondition(stored === replacement)
        print("PASS: saving a VPN configuration supersedes an older in-flight load")

        var resume: CheckedContinuation<Void, Never>?
        var reloads = 0
        let changing = TunnelManagerCache(notificationCenter: center) {
            reloads += 1
            if reloads == 1 {
                await withCheckedContinuation { resume = $0 }
                return [original]
            }
            return [replacement]
        }
        let outdated = Task { try await changing.load() }
        while resume == nil { await Task.yield() }
        center.post(name: .NEVPNConfigurationChange, object: nil)
        let fresh = try await changing.load()
        resume?.resume()
        let afterChange = try await outdated.value
        precondition(fresh === replacement && afterChange === replacement && reloads == 2)
        print("PASS: a configuration change during loading cannot restore a stale manager")

        var attempts = 0
        let failure = NSError(domain: "ManagerCacheTest", code: 1)
        let retrying = TunnelManagerCache(notificationCenter: center) {
            attempts += 1
            if attempts == 1 { throw failure }
            return [original]
        }
        do {
            _ = try await retrying.load()
            fatalError("A preference loading error was ignored")
        } catch { precondition(error as NSError == failure) }
        let retried = try await retrying.load()
        precondition(retried === original && attempts == 2)
        print("PASS: failed preference loads can be retried")
    }
}
