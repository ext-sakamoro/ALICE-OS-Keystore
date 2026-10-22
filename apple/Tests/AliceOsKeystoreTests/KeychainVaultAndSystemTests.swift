import XCTest
import Security
@testable import AliceOsKeystore

/// KeychainVault through the in-memory backend, and what SystemKeychain hands to the Security functions
final class KeychainVaultAndSystemTests: XCTestCase {
    func testKeychainVaultGenerationsRoundTripAndDestroy() throws {
        let kc = InMemoryKeychain()
        let v = KeychainVault(name: "k", backend: kc)
        XCTAssertThrowsError(try v.current())
        XCTAssertEqual(try v.createGeneration(), 1)
        XCTAssertEqual(try v.createGeneration(), 2)
        let (g, k) = try v.current()
        XCTAssertEqual(g, 2)
        XCTAssertEqual(k.count, 32)
        XCTAssertEqual(try v.key(generation: 2), k)
        XCTAssertNotEqual(try v.key(generation: 1), k)
        XCTAssertThrowsError(try v.key(generation: 9)) { XCTAssertEqual($0 as? KeystoreError, .unknownKey(generation: 9)) }
        try v.destroy()
        XCTAssertEqual(kc.accounts, [])
        XCTAssertThrowsError(try v.current())
    }

    func testKeychainVaultReportsAFailedStoreAndAWrongLength() throws {
        let kc = InMemoryKeychain()
        let v = KeychainVault(name: "k", backend: kc)
        kc.failAdd = { _ in errSecIO }
        XCTAssertThrowsError(try v.createGeneration()) {
            guard case .unavailable = $0 as? KeystoreError else { return XCTFail("\($0)") }
        }
        XCTAssertEqual(kc.accounts, [])
        kc.failAdd = nil
        kc.items.append([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "alice-os-keystore.keychain.k",
            kSecAttrAccount as String: "dek.1",
            kSecValueData as String: Data(count: 16),
        ])
        XCTAssertThrowsError(try v.key(generation: 1)) {
            guard case .irrecoverable = $0 as? KeystoreError else { return XCTFail("\($0)") }
        }
    }

    func testKeychainVaultDestroyFailureIsReported() throws {
        let kc = InMemoryKeychain()
        let v = KeychainVault(name: "k", backend: kc)
        try v.createGeneration()
        kc.failDelete = { _ in errSecIO }
        XCTAssertThrowsError(try v.destroy())
        XCTAssertEqual(kc.accounts, ["dek.1"])
    }

    /// Every dictionary SystemKeychain passes to the Security functions, for all four operations,
    /// carries kSecUseDataProtectionKeychain (macOS would otherwise use the file-based keychain)
    func testEveryCallReachingTheSecurityLayerUsesTheDataProtectionKeychain() {
        var seen: [(String, [String: Any])] = []
        func record(_ op: String, _ d: CFDictionary) { seen.append((op, d as NSDictionary as! [String: Any])) }
        let system = SystemKeychain(security: SecurityFunctions(
            copyMatching: { d, _ in record("copyMatching", d); return errSecItemNotFound },
            add: { d, _ in record("add", d); return errSecSuccess },
            delete: { d in record("delete", d); return errSecSuccess },
            createRandomKey: { d, _ in record("createRandomKey", d); return nil }
        ))
        _ = system.copyMatching([kSecClass as String: kSecClassKey])
        _ = system.add([kSecClass as String: kSecClassGenericPassword])
        _ = system.delete([kSecClass as String: kSecClassGenericPassword])
        _ = try? system.createRandomKey([kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom])
        XCTAssertEqual(seen.map(\.0), ["copyMatching", "add", "delete", "createRandomKey"])
        for (op, d) in seen {
            XCTAssertEqual(d[kSecUseDataProtectionKeychain as String] as? Bool, true, op)
        }
    }
}

/// The default SecurityFunctions are the real Security calls: on an unmodified SystemKeychain,
/// looking up or deleting an item that was never stored does not report success (it reports
/// errSecItemNotFound, or errSecMissingEntitlement on an unsigned macOS test host). A no-op
/// stand-in would report success. `add` is checked with a dictionary that has no item class,
/// which the real call rejects (errSecParam, or the missing-entitlement status) whatever the
/// environment, so the test never stores an item.
final class SystemKeychainDefaultsTests: XCTestCase {
    func testLookupAndDeleteOfAMissingItemDoNotSucceed() {
        let system = SystemKeychain()
        let service = "alice-os-keystore.test.\(UUID().uuidString)"
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        let (lookup, _) = system.copyMatching(query)
        XCTAssertNotEqual(lookup, errSecSuccess)
        XCTAssertNotEqual(system.delete(query), errSecSuccess)
    }

    func testAddWithoutAnItemClassIsRejected() {
        let status = SystemKeychain().add([kSecAttrService as String: "alice-os-keystore.test.\(UUID().uuidString)"])
        XCTAssertNotEqual(status, errSecSuccess)
    }
}
