import XCTest
@testable import AliceOsKeystore

/// The slot rules that keep the previous master secret readable when storing a new one fails
final class MasterVaultSlotTests: XCTestCase {
    func testOpenReadsTheHighestSlotWithABlob() {
        XCTAssertNil(MasterVault.slotToOpen([]))
        XCTAssertEqual(MasterVault.slotToOpen([1]), 1)
        XCTAssertEqual(MasterVault.slotToOpen([3, 1, 2]), 3)
    }

    func testStoreWritesAboveEverySlotSeen() {
        XCTAssertEqual(MasterVault.nextSlot(blobSlots: [], keySlots: []), 1)
        XCTAssertEqual(MasterVault.nextSlot(blobSlots: [1], keySlots: [1]), 2)
        XCTAssertEqual(MasterVault.nextSlot(blobSlots: [4, 2], keySlots: []), 5)
    }

    func testAnOrphanKeyAboveTheBlobsIsSkipped() {
        // slot 2's store failed after its enclave key was created and the cleanup failed:
        // the next store must not reuse 2 (a second key with the same tag)
        XCTAssertEqual(MasterVault.nextSlot(blobSlots: [1], keySlots: [1, 2]), 3)
    }

    func testTagsParseOnlyForThisVault() {
        let v = MasterVault(name: "a")
        XCTAssertEqual(MasterVault.slot(fromTag: v.tag(5), prefix: v.tagPrefix), 5)
        XCTAssertNil(MasterVault.slot(fromTag: MasterVault(name: "b").tag(5), prefix: v.tagPrefix))
        XCTAssertNil(MasterVault.slot(fromTag: Data("alice-os-keystore.se.a".utf8), prefix: v.tagPrefix))
    }

    func testAFailedStoreLeavesThePreviousSlotTheOneToOpen() {
        // slot 1 holds the secret; storing writes slot 2; if writing slot 2 fails, its
        // partial items are deleted and slot 1 is still the highest slot with a blob
        let before: [UInt32] = [1]
        let attempted = MasterVault.nextSlot(blobSlots: before, keySlots: before)
        XCTAssertEqual(attempted, 2)
        let afterFailure = before // the half-written slot was removed
        XCTAssertEqual(MasterVault.slotToOpen(afterFailure), 1)
    }

    func testAccountNamesRoundTrip() {
        XCTAssertEqual(MasterVault.slot(fromAccount: MasterVault.account(7)), 7)
        XCTAssertNil(MasterVault.slot(fromAccount: "master"))
        XCTAssertNil(MasterVault.slot(fromAccount: "dek.3"))
        XCTAssertNil(MasterVault.slot(fromAccount: "master.x"))
    }

    func testTransientStatusesAreNotIrrecoverable() {
        XCTAssertTrue(isTransient(errSecInteractionNotAllowed))
        XCTAssertTrue(isTransient(errSecUserCanceled))
        XCTAssertFalse(isTransient(errSecItemNotFound))
        XCTAssertFalse(isTransient(errSecDecode))
    }
}
