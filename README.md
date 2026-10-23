# ALICE-OS-Keystore

Data-encryption keys (DEKs) held by the operating system's key store, served through the `KeyProvider` trait of `alice-crypto` (re-exported here).

An application seals its data at rest with a 32-byte key and does not store that key itself: the key store holds it, wrapped by a key the hardware does not release. The application asks a `KeyProvider` for the key of a *generation* (`KeyGeneration`, a `u32` starting at 1; 0 is never a key); data sealed under generation `g` records `g`, so after a rotation old data still opens while new data uses the current generation. Rotation is a method of each store (`rotate`): it adds the next generation and keeps the older keys.

| Platform | Implementation | State |
|---|---|---|
| iOS / iPadOS / visionOS | `apple/` Swift package: `SecureEnclaveVault` (a Secure Enclave P-256 key wraps the DEK with ECIES, the wrapped blob is a Keychain item for this device only), `MasterVault` (a biometry-bound secret), `KeychainVault` (Keychain only, for the Simulator) | implemented; reaches Rust through the `uniffi` feature |
| Android | Keystore through the same callback interface | not yet |
| macOS | `desktop::MacosKeychainStore`: one generic password item per generation in the login keychain | implemented |
| Windows | `desktop::WindowsDpapiStore`: one DPAPI-sealed file per generation in `%LOCALAPPDATA%\<service>` | implemented |
| Linux | `desktop::LinuxSecretServiceStore`: one Secret Service item per generation (gnome-keyring, KWallet) | implemented |
| tests, ephemeral data | `MemoryVault` | implemented (keys only in memory, nothing protected at rest) |

## Rust

```rust
use alice_os_keystore::{KeyProvider, MemoryVault};

let vault = MemoryVault::new();
let generation = vault.rotate()?;               // a fresh random key as the next generation
let (current, key) = vault.current()?;          // seal new data with `key`, record `current`
assert_eq!(current, generation);
let again = vault.by_generation(current)?;      // open data sealed under `current`
assert_eq!(again.as_bytes(), key.as_bytes());
# Ok::<(), alice_os_keystore::KeyProviderError>(())
```

The key type is `alice_crypto::Key` (zeroed on drop, no `Debug`). `KeyProviderError` separates three cases an application handles differently: a generation that never existed (`UnknownGeneration`, always for 0), a store that cannot hand out keys right now (`Unavailable`: device locked, access refused; a later call may succeed), and a key that cannot be recovered (`Irrecoverable`: the key of an older generation was removed, the stored item is not a 32-byte key, or the hardware key that wraps it is gone; retrying does not help). The reasons are fixed strings: text from the operating system or from a foreign store is not passed on, since it can name paths or other detail.

### macOS Keychain

```rust,no_run
# #[cfg(target_os = "macos")] {
use alice_os_keystore::{desktop::MacosKeychainStore, KeyProvider};

let store = MacosKeychainStore::new("com.example.app");  // a service name only this application uses
let (generation, key) = store.current()?;                  // creates generation 1 on first use
# }
# Ok::<(), alice_os_keystore::KeyProviderError>(())
```

Each generation is one generic password item in the login keychain (service = the name passed in, account = `gen-<n>`, data = the 32 key bytes), created once with `SecItemAdd` and never rewritten, followed by a create-only marker item `issued-<n>`. The highest issued generation is the highest of the keys and markers, and a number is never issued twice: `rotate` adds the next number above it, even when the newest key item was removed. `current` returns the newest generation and creates generation 1 when there is none; when the newest key item was removed it reports `Irrecoverable` instead of falling back to an older key (an explicit `rotate` continues). Two processes creating the same generation at once cannot both succeed: the keychain refuses the second item and that call reads the first. `by_generation` reports a missing key at or below the highest issued generation as `Irrecoverable` and above it as `UnknownGeneration`. A key item found without its marker (a process stopped between the two writes) gets the marker when it is read. Limit: the markers live in the same keychain; a program that removes both the newest key item and its marker erases the record, and that number is issued again (nothing inside the store can prevent it). The file-based login keychain is used because the data-protection keychain needs a signed app with an access group, which a command-line program does not have. The program that created an item reads it without a dialog; another program, or a rebuild with a different signature, gets the system's access dialog, and a refusal is `Unavailable`. The bytes the Security framework returns are copied into the key and the returned buffer is zeroed; copies inside the framework are outside this crate's reach.

### Windows DPAPI

```rust,no_run
# #[cfg(windows)] {
use alice_os_keystore::{desktop::WindowsDpapiStore, KeyProvider};

let store = WindowsDpapiStore::new("com.example.app").expect("a plain directory name");
let (generation, key) = store.current()?;                  // creates generation 1 on first use
# }
# Ok::<(), alice_os_keystore::KeyProviderError>(())
```

Each generation is one file `gen-<n>.dpapi` in `%LOCALAPPDATA%\<service>` (or a directory given with `in_dir`): the 32 key bytes sealed with DPAPI for the current user, bound to the directory's own name, so a file copied into another store's directory does not open there. A file is written under a temporary name and hard-linked to its final name, which fails when the name exists: a generation appears complete or not at all, and two processes creating it at once cannot both succeed. An empty marker file `issued-<n>` follows each key file, and the model (numbers never issued twice, a removed newest key is `Irrecoverable`, the same limit) is the macOS one. A file that does not open for this user (damaged, another user's, or sealed before an administrator reset the user's password) is `Irrecoverable`. `new` refuses a service name that is not one plain directory name (separators, `.` / `..`, reserved device names such as `NUL`). The plaintext DPAPI returns is zeroed before it is freed.

### Linux Secret Service

```rust,no_run
# #[cfg(target_os = "linux")] {
use alice_os_keystore::{desktop::LinuxSecretServiceStore, KeyProvider};

let store = LinuxSecretServiceStore::new("com.example.app");
let (generation, key) = store.current()?;                  // creates generation 1 on first use
# }
# Ok::<(), alice_os_keystore::KeyProviderError>(())
```

Each generation is one item in the default collection of the Secret Service (gnome-keyring, KWallet) with the attributes `keystore-service` and `keystore-generation`, holding the 32 key bytes, followed by a marker item (`keystore-issued`); the connection to the service encrypts the secrets (Diffie-Hellman). The model is the macOS one (numbers never issued twice, a removed newest key is `Irrecoverable`, the same limit), with one difference the Secret Service forces: it has no "create unless it exists", so two processes creating the same generation at once leave two items. Every reader then picks the same one, by what only the service sets: the earliest `Created`, ties broken by the object path. A creator re-reads after creating and uses its own key only when its item was chosen, otherwise the chosen item's key. The other items stay in place, are logged (`log::warn!`, no key material) and counted by `duplicate_count`. Without a session bus (a headless machine), with a locked keyring that cannot be unlocked, or without a default collection, every call is `Unavailable`, so the caller can fall back to a passphrase.

### Reading a secret from a terminal

```rust,no_run
let secret = alice_os_keystore::prompt::read_secret("Passphrase: ")?; // echo is off while typing
# Ok::<(), alice_os_keystore::prompt::PromptError>(())
```

`prompt::read_secret` writes the prompt to standard error and reads one line from standard input with the terminal's echo turned off. While it reads, the terminal is in line mode with Enter ending the line (unix: canonical mode with a carriage return translated; Windows: line and processed input), and either a line feed or a carriage return ends the line, so a terminal left in another mode by a previous program does not keep the read waiting. The previous mode is restored when the call returns a line or an error or unwinds from a panic. It is not restored when the process ends without unwinding while the prompt waits (the default action of Ctrl-C / `SIGINT`, a console control handler that exits, `panic = "abort"`, `std::process::exit`): `stty sane` restores a unix terminal, and closing the window restores a Windows console. Standard input that is not a terminal is refused (`NotATerminal`) before anything is written, so a program that also accepts the secret from an environment variable chooses that path on purpose. An empty line (`Empty`), a line longer than 512 bytes (`TooLong`), an input that ends early (`Closed`) and a line that is not UTF-8 (`NotUtf8`) are separate errors. The line is read into one fixed heap buffer that never grows or moves and is zeroed before the call returns; the returned string is the only other copy and is zeroed on drop. On Windows the console is read as UTF-16, so a secret typed in any code page arrives as typed.

### Replacing a directory all or nothing

`fs::exchange(a, b)` swaps two existing paths in one step on Linux and Apple platforms, so a process stopped halfway leaves either the old or the new directory, never a mix. Any two entries swap (a directory and a file too), a symbolic link is swapped itself and not followed, the same path twice succeeds and changes nothing, and paths on different file systems are refused (`EXDEV`) without changing anything. On other platforms it returns `Unsupported` and changes nothing. Sync the parent directory afterwards if a crash must not undo the swap.

### Unsafe code

`unsafe` code is allowed only in `src/sys/`, the module that makes the operating system calls this crate makes itself (today the Windows console mode and DPAPI). The macOS Keychain is reached through the `security-framework` crate, with no `unsafe` here. Every `unsafe` block there carries a `SAFETY:` note. The rest of the crate denies `unsafe` code, and `scripts/unsafe_scope_check.py` (run in CI and by `scripts/preflight.sh`) fails on any `unsafe` outside `src/sys/`. On unix the terminal is controlled through `rustix`'s safe API.

## Swift (Apple platforms)

With the `uniffi` feature the crate exports a callback interface `ForeignKeyVault` (`current() -> GenerationKey`, `by_id(generation) -> bytes`). The application conforms a vault from `apple/` to the generated protocol and passes it to Rust, where `ffi::ForeignVaultAdapter` serves it as a `KeyProvider`: it accepts only 32-byte keys and generations of at least 1 (anything else is `Irrecoverable`), never passes generation 0 to the foreign side, and keeps the error kind but not the foreign reason text.

- `SecureEnclaveVault`: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, so keys open while the device is locked after the first unlock (background work), and never leave the device.
- `MasterVault`: `.biometryCurrentSet`; opening calls `LAContext.evaluatePolicy` first and then uses that context for the key. The secret lives in numbered slots: storing writes a new slot completely before removing the old one, so a failure while storing keeps the previous secret readable. Invalidation on a change of enrolled biometrics is Apple's documented behaviour and has not been tested here.
- Keychain items outlive an iOS app: call `destroy()` before removing test builds.
- Every Keychain call uses the data-protection keychain (`kSecUseDataProtectionKeychain`). On iOS / iPadOS / visionOS that is the only keychain. On macOS it is required for Secure Enclave keys, and it needs a signed app with a keychain access group: an unsigned macOS build gets `errSecMissingEntitlement` (-34018). `KeychainVault` items on macOS are therefore in the data-protection keychain too, not in the file-based login keychain (a change from earlier builds of this crate).

Generating the Swift binding (library mode; the generator is a separate tool crate so that its build-time dependencies stay out of the library):

```sh
cargo build --release --features uniffi
cargo run --locked --release --manifest-path tools/uniffi-bindgen/Cargo.toml -- generate \
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

- `tools/uniffi-bindgen` (build-time only) has its own lock; its audit runs as an informational job (its basic-toml advisory is known). The library's `Cargo.lock` also lists basic-toml because uniffi 0.28 records its optional generator dependency; it is not built into the library (cargo-deny, which resolves features, does not report it) and the audit ignores it with an exit condition in `security-audit.yml`

- Linux Secret Service store: run only on the CI Linux runner (gnome-keyring in a private D-Bus bus); KWallet is not tested
- Three advisories are held on a date (`scripts/advisory_holds.toml`): zvariant / zbus_names / zvariant_derive are unmaintained as separate crates and come from zbus 5 through secret-service 5.2; the hold ends when secret-service moves to zbus 6 (or another maintained client with the encrypted session is used)
- Windows DPAPI store: run only on the CI Windows runner; that a file does not open for another Windows user is DPAPI's documented behaviour and not tested here (CI has one user)
- macOS Keychain: the retry in `current` when an item disappears between listing and reading is not exercised by a test (it needs another process deleting at that moment), and that the buffer returned by the Security framework is zeroed is not observable from a test
- Android Keystore
- Reading a secret on a Windows console: the code is built and linted (clippy, pedantic) on Windows, refusing a non-console input is tested there, and the UTF-16 to UTF-8 conversion is unit-tested on every OS, but typing at a console is not tested (CI has no console); on unix the reader is tested through a pseudo-terminal

## Tests

Each behaviour was first written as a failing test (the test commit does not compile or fails), then implemented. Rust: `tests/` (run through `scripts/run_tests.sh` with a minimum per test binary; on macOS the Keychain store is tested against the real login keychain, each test with its own service name, deleting its items afterwards) and three fuzz targets. Swift: `apple/Tests` (`swift test`, the slot and error-classification rules). The Secure Enclave paths themselves need a device; they are not run in CI.

## License

Proprietary (`LicenseRef-Proprietary`, all rights reserved; see [LICENSE](LICENSE)). Commits made before the change to this licence stay under MIT OR Apache-2.0, the licence they were made under. The default build depends on `alice-crypto` (AGPL-3.0-or-later OR commercial; used here under the commercial licence) and otherwise on MIT / Apache-2.0 crates. The optional `uniffi` feature pulls in UniFFI's crates, which are MPL-2.0 (file-level copyleft: changes to those files must be shared, the rest of the program is unaffected).
