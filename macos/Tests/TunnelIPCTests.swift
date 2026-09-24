import Foundation

@main
struct TunnelIPCTests {
    @MainActor
    static func main() async throws {
        setbuf(stdout, nil)
        let requirement = try TunnelIPC.requirement(for: "com.rayfish.app")
        let listener = NSXPCListener.anonymous()
        var waiting: [(Data, (Data?) -> Void)] = []
        let server = TunnelMessageListener(listener: listener, clientRequirement: requirement) { data, reply in
            waiting.append((data, reply))
            // Neither request completes until both clients have connected.
            if waiting.count == 2 {
                for (data, reply) in waiting { reply(data) }
                waiting.removeAll()
            }
        }
        defer { server.invalidate() }
        async let ui = TunnelIPC.send(Data("ui".utf8), connection: NSXPCConnection(listenerEndpoint: listener.endpoint))
        async let cli = TunnelIPC.send(Data("cli".utf8), connection: NSXPCConnection(listenerEndpoint: listener.endpoint))
        let responses = try await [ui, cli]
        precondition(responses == [Data("ui".utf8), Data("cli".utf8)])
        print("PASS: simultaneous UI and CLI requests")

        let deniedListener = NSXPCListener.anonymous()
        let deniedServer = TunnelMessageListener(
            listener: deniedListener,
            clientRequirement: try TunnelIPC.requirement(for: "com.rayfish.untrusted")
        ) { _, _ in fatalError("An unauthorized client reached the handler") }
        defer { deniedServer.invalidate() }
        do {
            _ = try await TunnelIPC.send(Data(), connection: NSXPCConnection(listenerEndpoint: deniedListener.endpoint))
            fatalError("An unauthorized client was accepted")
        } catch TunnelIPCError.unavailable {
            print("PASS: unauthorized client rejected")
        } catch {
            precondition((error as NSError).domain == NSCocoaErrorDomain
                && ((error as NSError).code == NSXPCConnectionInvalid
                || (error as NSError).code == NSXPCConnectionInterrupted
                || (error as NSError).code == NSXPCConnectionCodeSigningRequirementFailure))
            print("PASS: unauthorized client rejected")
        }

        let slowListener = NSXPCListener.anonymous()
        let slowServer = TunnelMessageListener(listener: slowListener, clientRequirement: requirement) { data, reply in
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { reply(data) }
        }
        defer { slowServer.invalidate() }
        do {
            _ = try await TunnelIPC.send(Data(), connection: NSXPCConnection(listenerEndpoint: slowListener.endpoint), timeout: 0.05)
            fatalError("A stalled request did not time out")
        } catch TunnelIPCError.timedOut {
            try await Task.sleep(nanoseconds: 400_000_000)
            print("PASS: timeout and late reply complete only once")
        }
    }
}
