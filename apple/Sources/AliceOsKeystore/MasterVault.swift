import Foundation
import LocalAuthentication
import Security

/// A secret that opens only after the current biometric set authenticates
///
/// For a high-value key that is needed rarely (issuing or revoking device certificates):
/// a Secure Enclave key with `.biometryCurrentSet` wraps the secret, the wrapped blob is
/// a Keychain item (`WhenUnlockedThisDeviceOnly`). Opening asks for Face ID / Touch ID
/// with `LAContext.evaluatePolicy` first and then uses that context for the key
/// (`kSecUseAuthenticationContext`): calling the decryption directly, without a context,
/// did not return on a device in testing. Changing the enrolled biometrics is meant to
/// make the key unusable (Apple's documented behaviour of `.biometryCurrentSet`); this
/// has not been tested.
///
/// The secret lives in numbered slots (enclave key tag and blob account carry the slot
/// number). `store` writes a new slot completely before it removes older ones, so a
/// failure while storing leaves the previous secret readable; `open` reads the highest
/// slot that has a blob.
public final class MasterVault {
    static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    let name: String
    let service: String

    public init(name: String) {
        self.name = name
        service = "alice-os-keystore.master.\(name)"
    }

    var tagPrefix: String { "alice-os-keystore.master.\(name)." }

    func tag(_ slot: UInt32) -> Data {
        Data("\(tagPrefix)\(slot)".utf8)
    }

    /// The slot number in an enclave key tag of this vault, nil for any other tag
    static func slot(fromTag tag: Data, prefix: String) -> UInt32? {
        guard let text = String(data: tag, encoding: .utf8), text.hasPrefix(prefix) else { return nil }
        return UInt32(text.dropFirst(prefix.count))
    }

    static func account(_ slot: UInt32) -> String {
        "master.\(slot)"
    }

    /// The slot number in a blob account name (`master.<n>`), nil for anything else
    static func slot(fromAccount account: String) -> UInt32? {
        guard account.hasPrefix("master.") else { return nil }
        return UInt32(account.dropFirst("master.".count))
    }

    /// The slot `open` reads: the highest slot that has a blob
    static func slotToOpen(_ slotsWithBlob: [UInt32]) -> UInt32? {
        slotsWithBlob.max()
    }

    /// The slot `store` writes next: one above every slot seen, whether it has a blob or
    /// only an enclave key left behind by a failed store (reusing that number would create
    /// a second key with the same tag)
    static func nextSlot(blobSlots: [UInt32], keySlots: [UInt32]) -> UInt32 {
        ((blobSlots + keySlots).max() ?? 0) + 1
    }

    /// Wrap `secret` under a new biometry-bound enclave key in a new slot, then remove older slots
    public func store(secret: Data) throws {
        let previous = try slotsWithBlob()
        let slot = Self.nextSlot(blobSlots: previous, keySlots: try slotsWithKey())
        do {
            try writeSlot(slot, secret: secret)
        } catch {
            // remove the half-written new slot; the previous secret is untouched either way,
            // but a cleanup failure is reported, not dropped
            do {
                try deleteSlot(slot)
            } catch let cleanup {
                throw KeystoreError.unavailable(reason: "store failed: \(error); removing the partial slot \(slot) failed: \(cleanup)")
            }
            throw error
        }
        for old in previous where old != slot {
            try deleteSlot(old)
        }
    }

    func writeSlot(_ slot: UInt32, secret: Data) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error) else {
            throw KeystoreError.unavailable(reason: "access control: \(String(describing: error?.takeRetainedValue()))")
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag(slot),
                kSecAttrAccessControl as String: access,
            ],
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error), let pub = SecKeyCopyPublicKey(key) else {
            throw KeystoreError.unavailable(reason: "create enclave key: \(String(describing: error?.takeRetainedValue()))")
        }
        guard let blob = SecKeyCreateEncryptedData(pub, Self.algorithm, secret as CFData, &error) as Data? else {
            throw KeystoreError.unavailable(reason: "wrap failed: \(String(describing: error?.takeRetainedValue()))")
        }
        let status = SecItemAdd([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: Self.account(slot),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: blob,
        ] as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeystoreError.unavailable(reason: osStatusReason("store wrapped secret", status))
        }
    }

    /// Ask for biometric authentication and return the secret
    public func open(reason: String) async throws -> Data {
        guard let slot = Self.slotToOpen(try slotsWithBlob()) else {
            throw KeystoreError.unknownKey(generation: 0)
        }
        let context = LAContext()
        var laError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laError) else {
            throw KeystoreError.unavailable(reason: "biometrics unavailable: \(String(describing: laError))")
        }
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch {
            throw KeystoreError.unavailable(reason: "authentication refused: \(error)")
        }
        var out: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag(slot),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
        ] as CFDictionary, &out)
        if status == errSecItemNotFound {
            // the blob is there but its enclave key is gone (biometric set changed, device reset)
            throw KeystoreError.irrecoverable(reason: "enclave key of the master secret missing")
        }
        guard status == errSecSuccess, let found = out else {
            throw KeystoreError.unavailable(reason: osStatusReason("enclave key", status))
        }
        let key = found as! SecKey
        var blobOut: CFTypeRef?
        let read = SecItemCopyMatching([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: Self.account(slot),
            kSecReturnData as String: true,
        ] as CFDictionary, &blobOut)
        guard read == errSecSuccess, let blob = blobOut as? Data else {
            throw KeystoreError.unavailable(reason: osStatusReason("read wrapped secret", read))
        }
        var error: Unmanaged<CFError>?
        guard let secret = SecKeyCreateDecryptedData(key, Self.algorithm, blob as CFData, &error) as Data? else {
            let code = osStatus(of: error)
            if let code, isTransient(code) {
                throw KeystoreError.unavailable(reason: osStatusReason("unwrap", code))
            }
            throw KeystoreError.irrecoverable(reason: "unwrap failed (OSStatus \(code.map(String.init) ?? "unknown"))")
        }
        return secret
    }

    /// Delete every slot (enclave keys and wrapped secrets, including orphan keys)
    public func destroy() throws {
        for slot in Set(try slotsWithBlob() + slotsWithKey()) {
            try deleteSlot(slot)
        }
    }

    func deleteSlot(_ slot: UInt32) throws {
        for q in [
            [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: Self.account(slot)],
            [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag(slot)],
        ] as [[String: Any]] {
            let status = SecItemDelete(q as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw KeystoreError.unavailable(reason: osStatusReason("delete slot \(slot)", status))
            }
        }
    }

    /// Slots that have an enclave key (including keys whose blob is missing)
    func slotsWithKey() throws -> [UInt32] {
        var out: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ] as CFDictionary, &out)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = out as? [[String: Any]] else {
            throw KeystoreError.unavailable(reason: osStatusReason("list enclave keys", status))
        }
        return items.compactMap { ($0[kSecAttrApplicationTag as String] as? Data).flatMap { Self.slot(fromTag: $0, prefix: tagPrefix) } }
    }

    func slotsWithBlob() throws -> [UInt32] {
        var out: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ] as CFDictionary, &out)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = out as? [[String: Any]] else {
            throw KeystoreError.unavailable(reason: osStatusReason("list slots", status))
        }
        return items.compactMap { ($0[kSecAttrAccount as String] as? String).flatMap(Self.slot(fromAccount:)) }
    }
}
