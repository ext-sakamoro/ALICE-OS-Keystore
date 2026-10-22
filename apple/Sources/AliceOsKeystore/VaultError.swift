import Foundation

/// Why a key store did not hand out a key (mirrors `VaultError` / `ForeignVaultError` in Rust)
public enum KeystoreError: Error, Equatable {
    /// No key of this generation
    case unknownKey(generation: UInt32)
    /// Cannot hand out keys now (device locked, authentication refused, Secure Enclave missing)
    case unavailable(reason: String)
}

/// A data key store: hands out 32-byte keys by generation
public protocol DataKeyStore {
    /// The generation and key to seal new data with
    func current() throws -> (generation: UInt32, key: Data)
    /// The key of `generation`
    func key(generation: UInt32) throws -> Data
}

func osStatusReason(_ what: String, _ status: OSStatus) -> String {
    let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
    return "\(what): OSStatus \(status) (\(message))"
}
