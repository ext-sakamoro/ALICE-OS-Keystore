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
public final class MasterVault {
    static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    let tag: Data
    let service: String

    public init(name: String) {
        tag = Data("alice-os-keystore.master.\(name)".utf8)
        service = "alice-os-keystore.master.\(name)"
    }

    /// Wrap `secret` under a new biometry-bound enclave key (replaces a previous one)
    public func store(secret: Data) throws {
        try destroy()
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
                kSecAttrApplicationTag as String: tag,
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
            kSecAttrAccount as String: "master",
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: blob,
        ] as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeystoreError.unavailable(reason: osStatusReason("store wrapped secret", status))
        }
    }

    /// Ask for biometric authentication and return the secret
    public func open(reason: String) async throws -> Data {
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
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
        ] as CFDictionary, &out)
        guard status == errSecSuccess, let found = out else {
            throw KeystoreError.unavailable(reason: osStatusReason("enclave key", status))
        }
        let key = found as! SecKey
        var blobOut: CFTypeRef?
        let read = SecItemCopyMatching([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "master",
            kSecReturnData as String: true,
        ] as CFDictionary, &blobOut)
        guard read == errSecSuccess, let blob = blobOut as? Data else {
            throw KeystoreError.unavailable(reason: osStatusReason("read wrapped secret", read))
        }
        var error: Unmanaged<CFError>?
        guard let secret = SecKeyCreateDecryptedData(key, Self.algorithm, blob as CFData, &error) as Data? else {
            throw KeystoreError.unavailable(reason: "unwrap failed: \(String(describing: error?.takeRetainedValue()))")
        }
        return secret
    }

    /// Delete the enclave key and the wrapped secret
    public func destroy() throws {
        for q in [
            [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service],
            [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag],
        ] as [[String: Any]] {
            let status = SecItemDelete(q as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw KeystoreError.unavailable(reason: osStatusReason("destroy", status))
            }
        }
    }
}
