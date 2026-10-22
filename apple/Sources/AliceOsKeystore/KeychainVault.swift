import Foundation
import Security

/// Data keys stored directly in the Keychain, without a Secure Enclave
///
/// For the iOS Simulator and devices without a Secure Enclave: the keys are protected by
/// the Keychain's data protection only (`AfterFirstUnlockThisDeviceOnly`), not by a
/// hardware-bound key. Prefer `SecureEnclaveVault` when `SecureEnclave.isAvailable`.
public final class KeychainVault: DataKeyStore {
    let service: String

    let backend: KeychainBackend

    public convenience init(name: String) {
        self.init(name: name, backend: SystemKeychain())
    }

    init(name: String, backend: KeychainBackend) {
        self.backend = backend
        service = "alice-os-keystore.keychain.\(name)"
    }

    public func current() throws -> (generation: UInt32, key: Data) {
        guard let g = try generations().max() else {
            throw KeystoreError.unavailable(reason: "no data key yet (call createGeneration first)")
        }
        return (g, try key(generation: g))
    }

    public func key(generation: UInt32) throws -> Data {
        let (status, out) = backend.copyMatching([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "dek.\(generation)",
            kSecReturnData as String: true,
        ])
        if status == errSecItemNotFound { throw KeystoreError.unknownKey(generation: generation) }
        guard status == errSecSuccess, let key = out as? Data else {
            throw KeystoreError.unavailable(reason: osStatusReason("read key", status))
        }
        guard key.count == 32 else {
            throw KeystoreError.irrecoverable(reason: "stored key is \(key.count) bytes, expected 32")
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
        let status = backend.add([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "dek.\(next)",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: key,
        ])
        guard status == errSecSuccess else { throw KeystoreError.unavailable(reason: osStatusReason("store key", status)) }
        return next
    }

    public func destroy() throws {
        let status = backend.delete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service])
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeystoreError.unavailable(reason: osStatusReason("destroy", status))
        }
    }

    func generations() throws -> [UInt32] {
        let (status, out) = backend.copyMatching([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ])
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = out as? [[String: Any]] else {
            throw KeystoreError.unavailable(reason: osStatusReason("list generations", status))
        }
        return items.compactMap { ($0[kSecAttrAccount as String] as? String)?.dropFirst(4) }.compactMap { UInt32($0) }
    }
}
