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

`DataKey` zeroes its bytes on drop and does not print them. `VaultError` separates a key that does not exist (`UnknownKey`) from a store that cannot hand out keys right now (`Unavailable`: device locked, authentication refused), so an application can tell missing data from a transient state.

## Swift (Apple platforms)

With the `uniffi` feature the crate exports a callback interface `ForeignKeyVault` (`current() -> GenerationKey`, `by_id(generation) -> bytes`). The application conforms a vault from `apple/` to the generated protocol and passes it to Rust, where `ffi::ForeignVaultAdapter` accepts only 32-byte keys and keeps the error kind.

- `SecureEnclaveVault`: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, so keys open while the device is locked after the first unlock (background work), and never leave the device.
- `MasterVault`: `.biometryCurrentSet`; opening calls `LAContext.evaluatePolicy` first and then uses that context for the key. Invalidation on a change of enrolled biometrics is Apple's documented behaviour and has not been tested here.
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
        catch { throw ForeignVaultError.Unavailable(reason: "\(error)") }
    }
    public func byId(generation: UInt32) throws -> Data {
        do { return try key(generation: generation) }
        catch KeystoreError.unknownKey(let g) { throw ForeignVaultError.UnknownKey(generation: g) }
        catch { throw ForeignVaultError.Unavailable(reason: "\(error)") }
    }
}
```

## Gaps

- Desktop key stores (macOS Keychain, Windows DPAPI / CNG, Linux Secret Service)
- Android Keystore
- That `DataKey` is zeroed on drop is not checked by a test (it relies on the `zeroize` crate)

## License

MIT OR Apache-2.0
