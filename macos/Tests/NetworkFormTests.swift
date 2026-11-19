import SwiftUI

// Compile the real form and sheet without a VPN, signing, or Rust bindings.
@MainActor
final class TunnelController: ObservableObject {
    @Published var status: ProviderStatus?
    @Published var error: String?
    @Published var isLoading = false
    @Published var activity: String?
    var connectSucceeds = true
    var requestSucceeds = true
    var connectCalls = 0
    var requests: [ProviderRequest] = []
    var onConnect: (() async -> Void)?
    var onRequest: (() async -> Void)?

    func connect() async {
        connectCalls += 1
        await onConnect?()
        if connectSucceeds {
            status = ProviderStatus(active: true, ipv6: "287::1", networks: [], pendingRequests: [])
        } else {
            error = "Could not connect."
        }
    }

    func create(name: String?, hostname: String?) async -> Bool {
        await perform(ProviderRequest(action: .create, name: name, hostname: hostname))
    }

    func join(code: String, hostname: String?) async -> Bool {
        await perform(ProviderRequest(action: .join, code: code, hostname: hostname))
    }

    private func perform(_ request: ProviderRequest) async -> Bool {
        requests.append(request)
        await onRequest?()
        error = requestSucceeds ? nil : "The network name is already in use."
        return requestSucceeds
    }
}

@main
struct NetworkFormTests {
    @MainActor
    static func main() async {
        for name in ["", "a", "0", "tommy-network", "macbook-pro-m4-pro-16", "a--b", String(repeating: "a", count: 63)] {
            precondition(NetworkForm.nameError(name) == nil, "Should accept: \(name)")
        }
        for name in ["Tommy's Network", "MacBook Pro M4 Pro 16\"", "UPPER", " ", " home", "home ",
                     "has.dot", "under_score", "-start", "end-", "-", "é", "а", "💻", "a\n", "a\0b",
                     String(repeating: "a", count: 64)] {
            precondition(NetworkForm.nameError(name) != nil, "Should reject: \(name)")
        }
        print("PASS: name validation matches the core's ASCII, length, and hyphen rules")

        let controller = TunnelController()
        let create = NetworkForm(action: .create)
        precondition(create.canSubmit)
        create.input = "Tommy's Network"
        create.hostname = "MacBook Pro M4 Pro 16\""
        precondition(create.networkNameError != nil && create.hostnameError != nil)
        let invalid = await create.submit(using: controller)
        precondition(!invalid && controller.connectCalls == 0 && controller.requests.isEmpty)
        create.input = "tommy-network"
        precondition(!create.canSubmit && create.networkNameError == nil && create.hostnameError != nil)
        create.hostname = "macbook-pro-m4-pro-16"
        precondition(create.canSubmit)
        let created = await create.submit(using: controller)
        precondition(created && controller.connectCalls == 1 && controller.requests.count == 1)
        precondition(controller.requests[0].name == "tommy-network")
        precondition(controller.requests[0].hostname == "macbook-pro-m4-pro-16")
        print("PASS: both fields validate before connecting or sending a create request")

        let automatic = NetworkForm(action: .create)
        let generated = await automatic.submit(using: controller)
        precondition(generated && controller.connectCalls == 1)
        precondition(controller.requests.last?.name == nil && controller.requests.last?.hostname == nil)
        print("PASS: blank optional fields retain automatic naming")

        controller.requestSucceeds = false
        let failed = await create.submit(using: controller)
        precondition(!failed && create.error == "The network name is already in use.")
        // Simulate the next successful status poll clearing the controller error.
        controller.error = nil
        precondition(create.error == "The network name is already in use.")
        precondition(create.canSubmit && !create.isSubmitting)
        controller.requestSucceeds = true
        let retried = await create.submit(using: controller)
        precondition(retried && create.error == nil)
        controller.requestSucceeds = false
        _ = await create.submit(using: controller)
        create.input = "another-network"
        precondition(create.error == nil)
        print("PASS: submission errors survive status polls and clear on retry or editing")

        let disconnected = TunnelController()
        disconnected.connectSucceeds = false
        let connectionForm = NetworkForm(action: .create)
        let connected = await connectionForm.submit(using: disconnected)
        precondition(!connected && connectionForm.error == "Could not connect.")
        precondition(disconnected.requests.isEmpty && !connectionForm.isSubmitting)
        disconnected.error = nil
        precondition(connectionForm.error == "Could not connect.")
        disconnected.connectSucceeds = true
        let reconnected = await connectionForm.submit(using: disconnected)
        precondition(reconnected && connectionForm.error == nil)
        print("PASS: connection failures stay visible and allow retrying")

        let join = NetworkForm(action: .join)
        precondition(!join.canSubmit)
        join.input = " \n "
        precondition(!join.canSubmit)
        join.input = "INVITE-Code/With+Symbols="
        precondition(join.canSubmit && join.networkNameError == nil)
        join.hostname = "Invalid Host"
        precondition(!join.canSubmit && join.hostnameError != nil)
        let badJoin = await join.submit(using: disconnected)
        precondition(!badJoin && disconnected.requests.count == 1)
        join.hostname = "my-mac"
        disconnected.requestSucceeds = false
        let failedJoin = await join.submit(using: disconnected)
        precondition(!failedJoin && join.error != nil)
        disconnected.error = nil
        precondition(join.error != nil)
        join.hostname = "another-mac"
        precondition(join.error == nil)
        disconnected.requestSucceeds = true
        let joined = await join.submit(using: disconnected)
        precondition(joined && disconnected.requests.last?.action == .join)
        precondition(disconnected.requests.last?.code == "INVITE-Code/With+Symbols=")
        precondition(disconnected.requests.last?.hostname == "another-mac")
        print("PASS: join validates the hostname without applying name rules to invite codes")

        let busy = NetworkForm(action: .create)
        disconnected.isLoading = true
        let blocked = await busy.submit(using: disconnected)
        precondition(!blocked)
        disconnected.isLoading = false
        let previousRequests = disconnected.requests.count
        disconnected.onRequest = {
            precondition(busy.isSubmitting && !busy.canSubmit)
            precondition(!busy.canCancel)
            busy.cancel() // A request already sent cannot be cancelled locally.
            let duplicate = await busy.submit(using: disconnected)
            precondition(!duplicate)
        }
        let submitted = await busy.submit(using: disconnected)
        precondition(submitted && !busy.isSubmitting && busy.canSubmit)
        precondition(disconnected.requests.count == previousRequests + 1)
        print("PASS: busy forms block duplicate submissions")

        for action in [NetworkAction.create, .join] {
            let pending = TunnelController()
            let cancelled = NetworkForm(action: action)
            cancelled.input = action == .create ? "my-network" : "INVITE-Code="
            var releaseConnection: CheckedContinuation<Void, Never>?
            var submission: Task<Bool, Never>?
            await withCheckedContinuation { (started: CheckedContinuation<Void, Never>) in
                pending.onConnect = {
                    pending.activity = "Enable Rayfish Tunnel in System Settings to continue."
                    await withCheckedContinuation { continuation in
                        releaseConnection = continuation
                        started.resume()
                    }
                }
                submission = Task { await cancelled.submit(using: pending) }
            }
            precondition(cancelled.isSubmitting && cancelled.isConnecting && cancelled.canCancel)
            precondition(!cancelled.canSubmit && pending.requests.isEmpty)
            cancelled.cancel()
            releaseConnection!.resume()
            let completed = await submission!.value
            precondition(!completed && pending.requests.isEmpty)
            precondition(cancelled.error == nil && !cancelled.isSubmitting && !cancelled.isConnecting)
            precondition(!cancelled.canSubmit)
        }
        let dismissed = NetworkForm(action: .create)
        dismissed.cancel()
        let afterDismissal = await dismissed.submit(using: controller)
        precondition(!afterDismissal)
        print("PASS: cancelling during extension approval prevents later create/join requests")
    }
}
