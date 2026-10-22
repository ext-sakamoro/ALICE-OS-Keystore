import Foundation
import Security

/// Data keys stored directly in the Keychain, without a Secure Enclave
///
/// For the iOS Simulator and devices without a Secure Enclave: the keys are protected by
/// the Keychain's data protection only (`AfterFirstUnlockThisDeviceOnly`), not by a
/// hardware-bound key. Prefer `SecureEnclaveVault` when `SecureEnclave.isAvailable`.
public final class KeychainVault: DataKeyStore {
    let service: String

    public init(name: String) {
        service = "alice-os-keystore.keychain.\(name)"
    }

    public func current() throws -> (generation: UInt32, key: Data) {
        guard let g = try generations().max() else {
            throw KeystoreError.unavailable(reason: "no data key yet (call createGeneration first)")
        }
        return (g, try key(generation: g))
    }

    public func key(generation: UInt32) throws -> Data {
        var out: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "dek.\(generation)",
            kSecReturnData as String: true,
        ] as CFDictionary, &out)
        if status == errSecItemNotFound { throw KeystoreError.unknownKey(generation: generation) }
        guard status == errSecSuccess, let key = out as? Data, key.count == 32 else {
            throw KeystoreError.unavailable(reason: osStatusReason("read key", status))
        }
        return key
    }

    @discardableResult
    public func createGeneration() throws -> UInt32 {
        let next = (try generations().max() ?? 0) + 1
        var key = Data(count: 32)
        let random = key.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard random == errSecSuccess else { throw KeystoreError.unavailable(reason: osStatusReason("random", random)) }
        defer { key.resetBytes(in: 0..<key.count) }
        let status = SecItemAdd([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "dek.\(next)",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: key,
        ] as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeystoreError.unavailable(reason: osStatusReason("store key", status)) }
        return next
    }

    public func destroy() throws {
        let status = SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeystoreError.unavailable(reason: osStatusReason("destroy", status))
        }
    }

    func generations() throws -> [UInt32] {
        var out: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ] as CFDictionary, &out)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = out as? [[String: Any]] else {
            throw KeystoreError.unavailable(reason: osStatusReason("list generations", status))
        }
        return items.compactMap { ($0[kSecAttrAccount as String] as? String)?.dropFirst(4) }.compactMap { UInt32($0) }
    }
}
