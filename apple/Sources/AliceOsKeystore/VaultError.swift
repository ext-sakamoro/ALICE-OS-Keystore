import Foundation

/// Why a key store did not hand out a key (mirrors `VaultError` / `ForeignVaultError` in Rust)
public enum KeystoreError: Error, Equatable {
    /// No key of this generation
    case unknownKey(generation: UInt32)
    /// Cannot hand out keys now (device locked, authentication refused, Secure Enclave missing); a later call may succeed
    case unavailable(reason: String)
    /// The key cannot be recovered (the enclave key that wraps it is gone, the wrapped blob does not open); retrying will not help
    case irrecoverable(reason: String)
}

/// A data key store: hands out 32-byte keys by generation
public protocol DataKeyStore {
    /// The generation and key to seal new data with
    func current() throws -> (generation: UInt32, key: Data)
    /// The key of `generation`
    func key(generation: UInt32) throws -> Data
}

/// Keychain / Secure Enclave statuses that mean "not now" rather than "never"
func isTransient(_ status: OSStatus) -> Bool {
    status == errSecInteractionNotAllowed || status == errSecUserCanceled || status == errSecAuthFailed
}

/// The OSStatus inside a CFError from SecKeyCreateDecryptedData (its domain is NSOSStatusErrorDomain)
func osStatus(of error: Unmanaged<CFError>?) -> OSStatus? {
    guard let e = error?.takeRetainedValue() else { return nil }
    let ns = e as Error as NSError
    return ns.domain == NSOSStatusErrorDomain ? OSStatus(ns.code) : nil
}

func osStatusReason(_ what: String, _ status: OSStatus) -> String {
    let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
    return "\(what): OSStatus \(status) (\(message))"
}
