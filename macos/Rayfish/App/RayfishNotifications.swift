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
    var destination: String? = nil
}

struct RayfishNoticeChanges {
    var added: [RayfishNotice]
    var updated: [RayfishNotice]
    var alertingUpdates: Set<String>
    var removed: [String]
}

struct RayfishNoticeTracker {
    private var active: [String: RayfishNotice] = [:]
    private var hasSnapshot = false

    mutating func update(_ status: ProviderStatus?) -> RayfishNoticeChanges {
        guard let status else {
            let removed = active.values.filter { $0.title != "File received" }.map(\.id)
            active = [:]
            hasSnapshot = false
            return RayfishNoticeChanges(added: [], updated: [], alertingUpdates: [], removed: removed)
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
            let kind = file.state == .pending ? "offer" : "receive"
            let progress = file.size == 0 ? 0 : min(100, Int(Double(file.transferred) / Double(file.size) * 100))
            let title: String
            let body: String
            switch file.state {
            case .pending:
                title = "Incoming file"
                body = "\(file.peer) wants to send \(file.filename)."
            case .transferring:
                title = "Receiving file"
                body = "\(file.filename) from \(file.peer): \(progress)%"
            case .received:
                title = "File received"
                body = "\(file.peer) sent \(file.filename)."
            }
            return RayfishNotice(id: prefix + "file:\(kind):\(file.transferId):\(file.peer):\(file.filename):\(file.size)",
                          title: title, body: body, page: .files,
                          destination: file.state == .received ? file.destination : nil)
        }
        let current = Set(notices.map(\.id))
        // Completed transfers from before the app opened are history. Pending
        // requests still need attention, including on the first snapshot.
        let historicalFiles = hasSnapshot ? Set<String>() : Set(files.filter { $0.state == .received }.map {
            prefix + "file:receive:\($0.transferId):\($0.peer):\($0.filename):\($0.size)"
        })
        let added = notices.filter { active[$0.id] == nil && !historicalFiles.contains($0.id) }
        let updated = notices.filter { active[$0.id] != nil && active[$0.id] != $0 }
        let alertingUpdates = Set(updated.filter { $0.title == "File received" && active[$0.id]?.title != $0.title }.map(\.id))
        let removed = active.values.filter { !current.contains($0.id) && $0.title != "File received" }.map(\.id)
        active = Dictionary(uniqueKeysWithValues: notices.map { ($0.id, $0) })
        hasSnapshot = true
        return RayfishNoticeChanges(added: added, updated: updated, alertingUpdates: alertingUpdates, removed: removed)
    }
}

@MainActor
final class RayfishNotifications: NSObject, UNUserNotificationCenterDelegate {
    var onOpen: ((RayfishPage) -> Void)?
    var onRevealFile: ((URL) -> Void)?
    var onRestartUpdate: (() -> Void)?
    private var tracker = RayfishNoticeTracker()
    private var deliveryTask: Task<Void, Never>?
    private var authorizationReady = false
    private var latestStatus: ProviderStatus?

    func install() {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let restart = UNNotificationAction(identifier: "rayfish.restart-update", title: "Restart and Update")
        center.setNotificationCategories([
            UNNotificationCategory(identifier: "rayfish.update", actions: [restart], intentIdentifiers: [], options: [])
        ])
    }

    func showUpdateReady(version: String) {
        let content = UNMutableNotificationContent()
        content.title = "Rayfish \(version) is ready"
        content.body = "Restart to install the update. The VPN will briefly disconnect."
        content.sound = .default
        content.categoryIdentifier = "rayfish.update"
        Task {
            do {
                try await UNUserNotificationCenter.current().add(
                    UNNotificationRequest(identifier: "rayfish:update", content: content, trigger: nil))
            } catch {
                RayfishLog.app.error("Update notification failed: \(error.localizedDescription, privacy: .public)")
            }
        }
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
        guard !changes.added.isEmpty || !changes.updated.isEmpty || !changes.removed.isEmpty else { return }
        let previous = deliveryTask
        deliveryTask = Task {
            // Preserve snapshot order if a response arrives while delivery awaits.
            await previous?.value
            let center = UNUserNotificationCenter.current()
            center.removePendingNotificationRequests(withIdentifiers: changes.removed)
            center.removeDeliveredNotifications(withIdentifiers: changes.removed)
            let alerting = Set(changes.added.map(\.id)).union(changes.alertingUpdates)
            for notice in changes.added + changes.updated {
                let content = UNMutableNotificationContent()
                content.title = notice.title
                content.body = notice.body
                if alerting.contains(notice.id) {
                    content.sound = .default
                } else {
                    content.interruptionLevel = .passive
                }
                content.userInfo = ["page": notice.page.rawValue]
                if let destination = notice.destination {
                    content.userInfo["destination"] = destination
                }
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
        let isUpdate = response.notification.request.content.categoryIdentifier == "rayfish.update"
        let page = (response.notification.request.content.userInfo["page"] as? String)
            .flatMap(RayfishPage.init(rawValue:)) ?? .networks
        let destination = response.notification.request.content.userInfo["destination"] as? String
        Task { @MainActor in
            if isUpdate {
                if response.actionIdentifier == UNNotificationDefaultActionIdentifier
                    || response.actionIdentifier == "rayfish.restart-update" {
                    self.onRestartUpdate?()
                }
            } else if response.actionIdentifier == UNNotificationDefaultActionIdentifier {
                if let destination, FileManager.default.fileExists(atPath: destination) {
                    self.onRevealFile?(URL(fileURLWithPath: destination))
                } else {
                    self.onOpen?(page)
                }
            }
            completionHandler()
        }
    }
}
