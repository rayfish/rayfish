import Foundation
import OSLog
import UserNotifications

enum RayfishPage: String, CaseIterable {
    case networks = "Networks", devices = "Devices", files = "Files", settings = "Settings"
}

struct RayfishNotice: Equatable {
    var id: String
    var title: String
    var body: String
    var page: RayfishPage
}

struct RayfishNoticeChanges {
    var added: [RayfishNotice]
    var removed: [String]
}

struct RayfishNoticeTracker {
    private var active: Set<String> = []
    private var hasSnapshot = false

    mutating func update(_ status: ProviderStatus?) -> RayfishNoticeChanges {
        guard let status else {
            let removed = Array(active)
            active = []
            hasSnapshot = false
            return RayfishNoticeChanges(added: [], removed: removed)
        }
        let prefix = "rayfish:\(status.ipv6):"
        var notices = status.connectionRequests.map { request in
            RayfishNotice(id: prefix + "connect:\(request.id)", title: "Connection request",
                          body: "\(request.hostname ?? request.id) wants to connect with you.", page: .devices)
        }
        notices += status.pendingRequests.map { request in
            RayfishNotice(id: prefix + "join:\(request.network):\(request.id)", title: "Network join request",
                          body: "\(request.hostname ?? request.id) wants to join \(request.network).", page: .networks)
        }
        let files = status.files ?? []
        notices += files.map { file in
            RayfishNotice(id: prefix + "file:\(file.id):\(file.peer):\(file.filename):\(file.size)",
                          title: file.state == .pending ? "Incoming file" : "File received",
                          body: "\(file.peer) sent \(file.filename).", page: .files)
        }
        let current = Set(notices.map(\.id))
        // Completed transfers from before the app opened are history. Pending
        // requests still need attention, including on the first snapshot.
        let historicalFiles = hasSnapshot ? Set<String>() : Set(files.filter { $0.state == .received }.map {
            prefix + "file:\($0.id):\($0.peer):\($0.filename):\($0.size)"
        })
        let added = notices.filter { !active.contains($0.id) && !historicalFiles.contains($0.id) }
        let removed = Array(active.subtracting(current))
        active = current
        hasSnapshot = true
        return RayfishNoticeChanges(added: added, removed: removed)
    }
}

@MainActor
final class RayfishNotifications: NSObject, UNUserNotificationCenterDelegate {
    var onOpen: ((RayfishPage) -> Void)?
    private var tracker = RayfishNoticeTracker()
    private var deliveryTask: Task<Void, Never>?
    private var authorizationReady = false
    private var latestStatus: ProviderStatus?

    func install() {
        UNUserNotificationCenter.current().delegate = self
    }

    func requestAuthorization() async {
        do {
            _ = try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
        } catch {
            RayfishLog.app.error("Notification permission failed: \(error.localizedDescription, privacy: .public)")
        }
        authorizationReady = true
        update(latestStatus)
    }

    func update(_ status: ProviderStatus?) {
        latestStatus = status
        guard authorizationReady else { return }
        let changes = tracker.update(status)
        guard !changes.added.isEmpty || !changes.removed.isEmpty else { return }
        let previous = deliveryTask
        deliveryTask = Task {
            // Preserve snapshot order if a response arrives while delivery awaits.
            await previous?.value
            let center = UNUserNotificationCenter.current()
            center.removePendingNotificationRequests(withIdentifiers: changes.removed)
            center.removeDeliveredNotifications(withIdentifiers: changes.removed)
            for notice in changes.added {
                let content = UNMutableNotificationContent()
                content.title = notice.title
                content.body = notice.body
                content.sound = .default
                content.userInfo = ["page": notice.page.rawValue]
                do {
                    try await center.add(UNNotificationRequest(identifier: notice.id, content: content, trigger: nil))
                } catch {
                    RayfishLog.app.error("Notification delivery failed: \(error.localizedDescription, privacy: .public)")
                }
            }
        }
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .list, .sound])
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let page = (response.notification.request.content.userInfo["page"] as? String)
            .flatMap(RayfishPage.init(rawValue:)) ?? .networks
        Task { @MainActor in
            if response.actionIdentifier == UNNotificationDefaultActionIdentifier { self.onOpen?(page) }
            completionHandler()
        }
    }
}
