import Foundation
import Security

/// Data keys wrapped by a Secure Enclave key
///
/// One Secure Enclave P-256 key per vault (`kSecAttrTokenIDSecureEnclave`, private-key use
/// only) wraps each 32-byte data key with ECIES
/// (`eciesEncryptionCofactorVariableIVX963SHA256AESGCM`); the wrapped blob is a Keychain
/// generic password (this device only, account `dek.<generation>`). The data key exists
/// in clear only in memory while it is used. Both items use
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, so keys open while the device is
/// locked after the first unlock (background work), and never leave the device (no
/// backup, no iCloud Keychain).
public final class SecureEnclaveVault: DataKeyStore {
    static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    let tag: Data
    let service: String

    /// `name` separates vaults of one app (it becomes the key tag and the Keychain service)
    public init(name: String) {
        tag = Data("alice-os-keystore.se.\(name)".utf8)
        service = "alice-os-keystore.dek.\(name)"
    }

    /// The highest stored generation and its key
    public func current() throws -> (generation: UInt32, key: Data) {
        guard let g = try generations().max() else {
            throw KeystoreError.unavailable(reason: "no data key yet (call createGeneration first)")
        }
        return (g, try key(generation: g))
    }

    /// Unwrap the key of `generation`
    public func key(generation: UInt32) throws -> Data {
        let blob = try readBlob(generation)
        let privateKey = try enclaveKey(create: false)
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateDecryptedData(privateKey, Self.algorithm, blob as CFData, &error) as Data? else {
            let code = osStatus(of: error)
            if let code, isTransient(code) {
                throw KeystoreError.unavailable(reason: osStatusReason("unwrap", code))
            }
            // the blob does not open under this enclave key: retrying gives the same result
            throw KeystoreError.irrecoverable(reason: "unwrap failed (OSStatus \(code.map(String.init) ?? "unknown"))")
        }
        guard key.count == 32 else {
            throw KeystoreError.irrecoverable(reason: "unwrapped \(key.count) bytes, expected 32")
        }
        return key
    }

    /// Make a fresh random key the next generation (1 for an empty vault) and return the generation
    @discardableResult
    public func createGeneration() throws -> UInt32 {
        let next = (try generations().max() ?? 0) + 1
        var key = Data(count: 32)
        let status = key.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard status == errSecSuccess else {
            throw KeystoreError.unavailable(reason: osStatusReason("random", status))
        }
        defer { key.resetBytes(in: 0..<key.count) }
        guard let publicKey = SecKeyCopyPublicKey(try enclaveKey(create: true)) else {
            throw KeystoreError.unavailable(reason: "no public key")
        }
        var error: Unmanaged<CFError>?
        guard let blob = SecKeyCreateEncryptedData(publicKey, Self.algorithm, key as CFData, &error) as Data? else {
            throw KeystoreError.unavailable(reason: "wrap failed: \(String(describing: error?.takeRetainedValue()))")
        }
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "dek.\(next)",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: blob,
        ]
        let added = SecItemAdd(add as CFDictionary, nil)
        guard added == errSecSuccess else {
            throw KeystoreError.unavailable(reason: osStatusReason("store wrapped key", added))
        }
        return next
    }

    /// Delete the wrapped key of `generation` (after everything sealed under it was resealed)
    public func retire(generation: UInt32) throws {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "dek.\(generation)",
        ]
        let status = SecItemDelete(q as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeystoreError.unavailable(reason: osStatusReason("retire", status))
        }
    }

    /// Delete every item of this vault (the Secure Enclave key and all wrapped keys)
    ///
    /// Keychain items outlive the app on iOS: call this before uninstalling test builds.
    public func destroy() throws {
        for (q, what) in [
            ([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service], "wrapped keys"),
            ([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag], "enclave key"),
        ] as [([String: Any], String)] {
            let status = SecItemDelete(q as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw KeystoreError.unavailable(reason: osStatusReason("destroy \(what)", status))
            }
        }
    }

    func generations() throws -> [UInt32] {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = out as? [[String: Any]] else {
            throw KeystoreError.unavailable(reason: osStatusReason("list generations", status))
        }
        return items.compactMap { ($0[kSecAttrAccount as String] as? String)?.dropFirst(4) }.compactMap { UInt32($0) }
    }

    func readBlob(_ generation: UInt32) throws -> Data {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "dek.\(generation)",
            kSecReturnData as String: true,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { throw KeystoreError.unknownKey(generation: generation) }
        guard status == errSecSuccess, let blob = out as? Data else {
            throw KeystoreError.unavailable(reason: osStatusReason("read wrapped key", status))
        }
        return blob
    }

    func enclaveKey(create: Bool) throws -> SecKey {
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecSuccess, let key = out { return key as! SecKey }
        if status == errSecItemNotFound, !create {
            // a wrapped key exists (it was read before) but the enclave key is gone (restored
            // backup, device reset): no retry brings it back
            throw KeystoreError.irrecoverable(reason: "enclave key missing")
        }
        guard status == errSecItemNotFound else {
            throw KeystoreError.unavailable(reason: osStatusReason("enclave key", status))
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error) else {
            throw KeystoreError.unavailable(reason: "access control: \(String(describing: error?.takeRetainedValue()))")
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw KeystoreError.unavailable(reason: "create enclave key: \(String(describing: error?.takeRetainedValue()))")
        }
        return key
    }
}
