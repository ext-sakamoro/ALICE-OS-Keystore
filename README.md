# ALICE-OS-Keystore

Data-encryption keys (DEKs) held by the operating system's key store, behind one `KeyVault` trait.

An application seals its data at rest with a 32-byte key and does not store that key itself: the key store holds it, wrapped by a key the hardware does not release. The application asks a `KeyVault` for the key of a *generation* (`u32`); data sealed under generation `g` records `g`, so after a rotation old data still opens while new data uses the current generation.

| Platform | Implementation | State |
|---|---|---|
| iOS / iPadOS / visionOS | `apple/` Swift package: `SecureEnclaveVault` (a Secure Enclave P-256 key wraps the DEK with ECIES, the wrapped blob is a Keychain item for this device only), `MasterVault` (a biometry-bound secret), `KeychainVault` (Keychain only, for the Simulator) | implemented; reaches Rust through the `uniffi` feature |
| Android | Keystore through the same callback interface | not yet |
| macOS / Windows / Linux | `desktop::*` | not yet: every call fails fast (`todo!`) |
| tests, ephemeral data | `MemoryVault` | implemented (keys only in memory, nothing protected at rest) |

## Rust

```rust
use alice_os_keystore::{KeyVault, MemoryVault};

let vault = MemoryVault::new();
let generation = vault.generate()?;          // a fresh random key as the next generation
let (current, key) = vault.current()?;       // seal new data with `key`, record `current`
assert_eq!(current, generation);
let again = vault.by_id(current)?;            // open data sealed under `current`
assert_eq!(again.as_bytes(), key.as_bytes());
# Ok::<(), alice_os_keystore::VaultError>(())
```

`DataKey` zeroes its bytes on drop and does not print them. `VaultError` separates three cases an application handles differently: a key that does not exist (`UnknownKey`), a store that cannot hand out keys right now (`Unavailable`: device locked, authentication refused; a later call may succeed), and a key that cannot be recovered (`Irrecoverable`: the hardware key that wraps it is gone or the wrapped blob does not open; retrying does not help).

## Swift (Apple platforms)

With the `uniffi` feature the crate exports a callback interface `ForeignKeyVault` (`current() -> GenerationKey`, `by_id(generation) -> bytes`). The application conforms a vault from `apple/` to the generated protocol and passes it to Rust, where `ffi::ForeignVaultAdapter` accepts only 32-byte keys and keeps the error kind.

- `SecureEnclaveVault`: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, so keys open while the device is locked after the first unlock (background work), and never leave the device.
- `MasterVault`: `.biometryCurrentSet`; opening calls `LAContext.evaluatePolicy` first and then uses that context for the key. The secret lives in numbered slots: storing writes a new slot completely before removing the old one, so a failure while storing keeps the previous secret readable. Invalidation on a change of enrolled biometrics is Apple's documented behaviour and has not been tested here.
- Keychain items outlive an iOS app: call `destroy()` before removing test builds.

Generating the Swift binding (library mode; the generator is a separate tool crate so that its build-time dependencies stay out of the library):

```sh
cargo build --release --features uniffi
cargo run --release --manifest-path tools/uniffi-bindgen/Cargo.toml -- generate \
  --library target/release/libalice_os_keystore.dylib --language swift --out-dir generated/
```

The generated module declares `protocol ForeignKeyVault { func current() throws -> GenerationKey; func byId(generation: UInt32) throws -> Data }`. A consumer that sees both modules conforms a vault with a few lines (this snippet is typechecked against the generated binding and `apple/`):

```swift
import Foundation

extension SecureEnclaveVault: ForeignKeyVault {
    public func current() throws -> GenerationKey {
        do { let (g, k) = try current() as (generation: UInt32, key: Data); return GenerationKey(generation: g, key: k) }
        catch KeystoreError.unknownKey(let g) { throw ForeignVaultError.UnknownKey(generation: g) }
        catch KeystoreError.irrecoverable(let why) { throw ForeignVaultError.Irrecoverable(reason: why) }
        catch { throw ForeignVaultError.Unavailable(reason: "\(error)") }
    }
    public func byId(generation: UInt32) throws -> Data {
        do { return try key(generation: generation) }
        catch KeystoreError.unknownKey(let g) { throw ForeignVaultError.UnknownKey(generation: g) }
        catch KeystoreError.irrecoverable(let why) { throw ForeignVaultError.Irrecoverable(reason: why) }
        catch { throw ForeignVaultError.Unavailable(reason: "\(error)") }
    }
}
```

## Gaps

- Desktop key stores (macOS Keychain, Windows DPAPI / CNG, Linux Secret Service)
- Android Keystore
- That `DataKey` is zeroed on drop is not checked by a test (it relies on the `zeroize` crate)

## Tests

Each behaviour was first written as a failing test (the test commit does not compile or fails), then implemented. Rust: `tests/` (run through `scripts/run_tests.sh` with a minimum per test binary) and three fuzz targets. Swift: `apple/Tests` (`swift test`, the slot and error-classification rules). The Secure Enclave paths themselves need a device; they are not run in CI.

## License

MIT OR Apache-2.0. The default build depends only on MIT / Apache-2.0 crates. The optional `uniffi` feature pulls in UniFFI's crates, which are MPL-2.0 (file-level copyleft: changes to those files must be shared, the rest of the program is unaffected).
