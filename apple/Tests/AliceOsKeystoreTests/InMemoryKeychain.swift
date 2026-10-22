import Foundation
import Security
@testable import AliceOsKeystore

/// An in-memory keychain for tests: items are dictionaries, keys are software P-256 keys
/// (ECIES works on them the same way), and faults can be injected per call.
final class InMemoryKeychain: KeychainBackend {
    var items: [[String: Any]] = []
    /// Return a status to fail an add / delete whose attributes or query match
    var failAdd: (([String: Any]) -> OSStatus?)?
    var failDelete: (([String: Any]) -> OSStatus?)?
    /// Every query / attribute dictionary passed in, in order
    var calls: [[String: Any]] = []

    static let matchKeys = [kSecClass, kSecAttrService, kSecAttrAccount, kSecAttrApplicationTag].map { $0 as String }

    func matches(_ item: [String: Any], _ query: [String: Any]) -> Bool {
        for k in Self.matchKeys {
            guard let want = query[k] else { continue }
            let have = item[k]
            if let w = want as? Data, let h = have as? Data { if w != h { return false } }
            else if let w = want as? String, let h = have as? String { if w != h { return false } }
            else if (want as? NSObject) != (have as? NSObject) { return false }
        }
        return true
    }

    func copyMatching(_ query: [String: Any]) -> (OSStatus, CFTypeRef?) {
        calls.append(query)
        let found = items.filter { matches($0, query) }
        if found.isEmpty { return (errSecItemNotFound, nil) }
        let all = (query[kSecMatchLimit as String] as? String) == (kSecMatchLimitAll as String)
        func shape(_ item: [String: Any]) -> Any {
            if query[kSecReturnRef as String] as? Bool == true { return item[kSecValueRef as String]! }
            if query[kSecReturnData as String] as? Bool == true { return item[kSecValueData as String]! }
            return item.filter { $0.key != (kSecValueData as String) && $0.key != (kSecValueRef as String) }
        }
        if all { return (errSecSuccess, found.map(shape) as CFArray) }
        return (errSecSuccess, shape(found[0]) as CFTypeRef)
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        calls.append(attributes)
        if let status = failAdd?(attributes) { return status }
        if items.contains(where: { matches($0, attributes) }) { return errSecDuplicateItem }
        items.append(attributes)
        return errSecSuccess
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        calls.append(query)
        if let status = failDelete?(query) { return status }
        let before = items.count
        items.removeAll { matches($0, query) }
        return items.count == before ? errSecItemNotFound : errSecSuccess
    }

    func createRandomKey(_ attributes: [String: Any]) throws -> SecKey {
        calls.append(attributes)
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey([
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ] as CFDictionary, &error) else {
            throw KeystoreError.unavailable(reason: "software key: \(String(describing: error?.takeRetainedValue()))")
        }
        let privateAttrs = attributes[kSecPrivateKeyAttrs as String] as? [String: Any] ?? [:]
        let tag = privateAttrs[kSecAttrApplicationTag as String] as? Data ?? Data()
        let item: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecValueRef as String: key,
        ]
        // a stand-in, stricter than the real Keychain (which accepts two keys with the same tag):
        // it makes a reused slot number visible in tests
        if items.contains(where: { matches($0, item) }) {
            throw KeystoreError.unavailable(reason: "duplicate key tag \(String(data: tag, encoding: .utf8) ?? "?")")
        }
        items.append(item)
        return key
    }

    /// Blob accounts and key tags currently stored, for assertions
    var accounts: [String] { items.compactMap { $0[kSecAttrAccount as String] as? String }.sorted() }
    var keyTags: [String] {
        items.compactMap { ($0[kSecAttrApplicationTag as String] as? Data).flatMap { String(data: $0, encoding: .utf8) } }.sorted()
    }
}
