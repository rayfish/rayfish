import Foundation
import Security

/// An identity backup kept in iCloud Keychain, which syncs it end to end
/// encrypted to the user's other Apple devices. The identity is sealed with a
/// random password stored next to it, so the item alone restores it.
struct KeychainBackup: Codable, Identifiable {
    var code: String
    var password: String
    var publicKey: String
    var deviceName: String
    var saved: Date

    var id: String { publicKey }
}

enum IdentityKeychain {
    private static let service = "xyz.rayfish.ios.identity"

    /// Backups saved from any of the user's devices, newest first.
    static func list() -> [KeychainBackup] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnData as String: true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [Data] else { return [] }
        return items.compactMap { try? JSONDecoder().decode(KeychainBackup.self, from: $0) }
            .sorted { $0.saved > $1.saved }
    }

    /// Seal this device's identity and save it, replacing an older backup of it.
    static func save(node: Node, deviceName: String) throws {
        let password = try randomPassword()
        let backup = try node.backupIdentity(password: password)
        let item = KeychainBackup(code: backup.code, password: password, publicKey: backup.publicKey,
                                  deviceName: deviceName, saved: Date())
        let data = try JSONEncoder().encode(item)
        let match: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: backup.publicKey,
            kSecAttrSynchronizable as String: true,
        ]
        var status = SecItemUpdate(match as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var add = match
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
            add[kSecAttrLabel as String] = "Rayfish identity (\(deviceName))"
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw KeychainError(status) }
    }

    static func remove(_ publicKey: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: publicKey,
            kSecAttrSynchronizable as String: true,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError(status) }
    }

    private static func randomPassword() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw KeychainError(status) }
        return Data(bytes).base64EncodedString()
    }
}

struct KeychainError: LocalizedError {
    var status: OSStatus
    init(_ status: OSStatus) { self.status = status }

    var errorDescription: String? {
        let detail = SecCopyErrorMessageString(status, nil) as String? ?? "error \(status)"
        return "Keychain: \(detail)"
    }
}
