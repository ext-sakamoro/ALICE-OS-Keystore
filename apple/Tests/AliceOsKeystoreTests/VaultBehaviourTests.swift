import XCTest
import Security
@testable import AliceOsKeystore

/// store / destroy / key lookup driven through an in-memory keychain with injected faults
final class VaultBehaviourTests: XCTestCase {
    let secret1 = Data(repeating: 1, count: 32)
    let secret2 = Data(repeating: 2, count: 32)

    func testStoreReplacesTheOldSlot() throws {
        let kc = InMemoryKeychain()
        let v = MasterVault(name: "m", backend: kc)
        try v.store(secret: secret1)
        try v.store(secret: secret2)
        XCTAssertEqual(kc.accounts, ["master.2"])
        XCTAssertEqual(kc.keyTags, ["alice-os-keystore.master.m.2"])
    }

    func testAFailedStoreKeepsThePreviousSecret() throws {
        let kc = InMemoryKeychain()
        let v = MasterVault(name: "m", backend: kc)
        try v.store(secret: secret1)
        kc.failAdd = { ($0[kSecAttrAccount as String] as? String) == "master.2" ? errSecIO : nil }
        XCTAssertThrowsError(try v.store(secret: secret2))
        // the half-written slot 2 (its enclave key) was removed, slot 1 is intact
        XCTAssertEqual(kc.accounts, ["master.1"])
        XCTAssertEqual(kc.keyTags, ["alice-os-keystore.master.m.1"])
    }

    func testAFailedCleanupIsReportedWithTheOriginalError() throws {
        let kc = InMemoryKeychain()
        let v = MasterVault(name: "m", backend: kc)
        try v.store(secret: secret1)
        kc.failAdd = { ($0[kSecAttrAccount as String] as? String) == "master.2" ? errSecIO : nil }
        kc.failDelete = { ($0[kSecAttrApplicationTag as String] as? Data) == Data("alice-os-keystore.master.m.2".utf8) ? errSecIO : nil }
        XCTAssertThrowsError(try v.store(secret: secret2)) { error in
            let text = "\(error)"
            XCTAssertTrue(text.contains("store failed"), text)
            XCTAssertTrue(text.contains("removing the partial slot 2 failed"), text)
        }
        // the orphan key of slot 2 is still there
        XCTAssertEqual(kc.keyTags, ["alice-os-keystore.master.m.1", "alice-os-keystore.master.m.2"])
    }

    func testTheNextStoreSkipsAnOrphanKey() throws {
        let kc = InMemoryKeychain()
        let v = MasterVault(name: "m", backend: kc)
        try v.store(secret: secret1)
        kc.failAdd = { ($0[kSecAttrAccount as String] as? String) == "master.2" ? errSecIO : nil }
        kc.failDelete = { _ in errSecIO }
        XCTAssertThrowsError(try v.store(secret: secret2))
        kc.failAdd = nil
        kc.failDelete = nil
        // reusing 2 would create a second key with the tag of the orphan
        try v.store(secret: secret2)
        XCTAssertEqual(kc.accounts, ["master.3"])
    }

    func testDestroyRemovesOrphanKeys() throws {
        let kc = InMemoryKeychain()
        let v = MasterVault(name: "m", backend: kc)
        try v.store(secret: secret1)
        kc.failAdd = { ($0[kSecAttrAccount as String] as? String) == "master.2" ? errSecIO : nil }
        kc.failDelete = { _ in errSecIO }
        XCTAssertThrowsError(try v.store(secret: secret2))
        kc.failDelete = nil
        try v.destroy()
        XCTAssertEqual(kc.accounts, [])
        XCTAssertEqual(kc.keyTags, [])
    }

    func testDataKeysRoundTripAndAMissingEnclaveKeyIsIrrecoverable() throws {
        let kc = InMemoryKeychain()
        let v = SecureEnclaveVault(name: "d", backend: kc)
        XCTAssertEqual(try v.createGeneration(), 1)
        XCTAssertEqual(try v.createGeneration(), 2)
        let (g, k) = try v.current()
        XCTAssertEqual(g, 2)
        XCTAssertEqual(try v.key(generation: 2), k)
        XCTAssertThrowsError(try v.key(generation: 3)) { XCTAssertEqual($0 as? KeystoreError, .unknownKey(generation: 3)) }
        kc.items.removeAll { ($0[kSecClass as String] as? String) == (kSecClassKey as String) }
        XCTAssertThrowsError(try v.key(generation: 1)) {
            guard case .irrecoverable = $0 as? KeystoreError else { return XCTFail("\($0)") }
        }
    }

    func testEveryQueryUsesTheDataProtectionKeychain() {
        let prepared = SystemKeychain.prepared([kSecClass as String: kSecClassKey])
        XCTAssertEqual(prepared[kSecUseDataProtectionKeychain as String] as? Bool, true)
        XCTAssertEqual(prepared[kSecClass as String] as? String, kSecClassKey as String)
    }
}
