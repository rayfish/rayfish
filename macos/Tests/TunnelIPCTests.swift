import Foundation

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
}
