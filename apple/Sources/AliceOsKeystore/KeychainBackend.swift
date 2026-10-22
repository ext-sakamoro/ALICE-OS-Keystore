import Foundation
import Security

/// The Keychain operations the vaults use, behind one seam
///
/// Production uses `SystemKeychain` (the Security framework); tests drive the vaults
/// through an in-memory implementation with injected faults, so the store / destroy /
/// cleanup paths are tested without a device.
protocol KeychainBackend {
    func copyMatching(_ query: [String: Any]) -> (OSStatus, CFTypeRef?)
    func add(_ attributes: [String: Any]) -> OSStatus
    func delete(_ query: [String: Any]) -> OSStatus
    func createRandomKey(_ attributes: [String: Any]) throws -> SecKey
}

/// The Security framework's Keychain
///
/// Every query and attribute dictionary carries `kSecUseDataProtectionKeychain`: on macOS
/// the default is the file-based keychain, while Secure Enclave keys live in the
/// data-protection keychain, so lookups without the flag would miss them (on iOS and
/// visionOS the data-protection keychain is the only one and the flag changes nothing).
struct SystemKeychain: KeychainBackend {
    static func prepared(_ dictionary: [String: Any]) -> [String: Any] {
        var d = dictionary
        d[kSecUseDataProtectionKeychain as String] = true
        return d
    }

    func copyMatching(_ query: [String: Any]) -> (OSStatus, CFTypeRef?) {
        var out: CFTypeRef?
        let status = SecItemCopyMatching(Self.prepared(query) as CFDictionary, &out)
        return (status, out)
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        SecItemAdd(Self.prepared(attributes) as CFDictionary, nil)
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        SecItemDelete(Self.prepared(query) as CFDictionary)
    }

    func createRandomKey(_ attributes: [String: Any]) throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(Self.prepared(attributes) as CFDictionary, &error) else {
            throw KeystoreError.unavailable(reason: "create enclave key: \(String(describing: error?.takeRetainedValue()))")
        }
        return key
    }
}
