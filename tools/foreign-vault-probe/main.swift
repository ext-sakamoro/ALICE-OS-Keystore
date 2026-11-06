import Foundation

// An error the binding does not know: a key store built on another library throws these
struct OtherLibraryError: Error {}

final class Vault: ForeignKeyVault, Sendable {
    let failure: (any Error & Sendable)?
    init(failure: (any Error & Sendable)?) { self.failure = failure }
    func current() throws -> GenerationKey {
        if let failure { throw failure }
        return GenerationKey(generation: 1, key: Data(repeating: 1, count: 32))
    }
    func byId(generation: UInt32) throws -> Data {
        if let failure { throw failure }
        return Data(repeating: 1, count: 32)
    }
}

print("good:", probe(vault: Vault(failure: nil)))
print("unknown key:", probe(vault: Vault(failure: ForeignVaultError.UnknownKey(generation: 1))))
print("unavailable:", probe(vault: Vault(failure: ForeignVaultError.Unavailable(reason: "locked"))))
print("irrecoverable:", probe(vault: Vault(failure: ForeignVaultError.Irrecoverable(reason: "gone"))))
print("other error:", probe(vault: Vault(failure: OtherLibraryError())))
