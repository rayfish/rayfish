import Foundation

/// Send one provider message and wait for its reply, failing after `timeout`.
/// The macOS and iOS apps both use it, each with its own errors for a reply
/// that never comes.
enum ProviderReply {
    @MainActor
    static func send(
        _ data: Data,
        timeout: TimeInterval,
        timedOut: Error,
        noResponse: Error,
        using sendMessage: @MainActor (Data, @escaping (Data?) -> Void) throws -> Void
    ) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            let pending = PendingReply(continuation)
            let timer = DispatchWorkItem { pending.finish(.failure(timedOut)) }
            pending.setTimer(timer)
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timer)
            do {
                try sendMessage(data) { reply in
                    pending.finish(reply.map { .success($0) } ?? .failure(noResponse))
                }
            } catch {
                pending.finish(.failure(error))
            }
        }
    }
}

/// Resumes once, with the reply or the timeout, and cancels the timeout so a
/// fast reply does not leave it pending for the full wait.
private final class PendingReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    private var timer: DispatchWorkItem?

    init(_ continuation: CheckedContinuation<Data, Error>) {
        self.continuation = continuation
    }

    func setTimer(_ timer: DispatchWorkItem) {
        lock.withLock {
            if continuation == nil { timer.cancel() } else { self.timer = timer }
        }
    }

    func finish(_ result: Result<Data, Error>) {
        let (continuation, timer) = lock.withLock {
            defer {
                self.continuation = nil
                self.timer = nil
            }
            return (self.continuation, self.timer)
        }
        timer?.cancel()
        continuation?.resume(with: result)
    }
}
