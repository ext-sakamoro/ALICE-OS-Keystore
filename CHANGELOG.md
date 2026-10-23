# Changelog

## [Unreleased]

### Changed

- Unsafe code policy: the crate no longer forbids `unsafe` everywhere. It denies it everywhere except one private module, `src/sys/`, which holds the operating system calls (each `unsafe` block with a `SAFETY:` note). `scripts/unsafe_scope_check.py` (CI and preflight) fails on any `unsafe` outside it. Reading a secret on a Windows console needs these calls; the desktop key stores will use the same module

### Added

- `fs::exchange`: swap two directories in one atomic step (Linux `renameat2` `RENAME_EXCHANGE`, Apple `renameatx_np` `RENAME_SWAP`, through `rustix`'s safe API), for replacing a directory of keys and data all or nothing. Other platforms return `ExchangeError::Unsupported` without changing anything, so the caller picks a fallback it can recover from
- `prompt::read_secret` / `read_secret_from`: read a secret from a terminal with echo off (unix: termios through `rustix`, Windows: console mode), restoring the terminal's mode on every exit path. A non-terminal input is refused before anything is written (`PromptError::NotATerminal`); an empty line, a line longer than `prompt::MAX_SECRET_LEN` (512 bytes), input that ends early and non-UTF-8 input are separate errors. The line is read into a fixed buffer and returned in zeroizing memory
- `KeyVault` (data keys by generation), `DataKey` (zeroed on drop, not printed), `VaultError` (`UnknownKey` / `Unavailable` / `InvalidKeyLength`)
- `MemoryVault`: keys in memory only, for tests and ephemeral data
- `DataKey::from_slice`: copies a 32-byte slice straight into the key (other lengths are `VaultError::InvalidKeyLength` with the length), so callers holding the key in a buffer need no array of their own; the `uniffi` adapter and `MemoryVault::generate` now write into the key directly
- `uniffi` feature: `ffi::ForeignKeyVault` callback interface and `ffi::ForeignVaultAdapter` (accepts only 32-byte keys, keeps the error kind)
- `desktop::{MacosKeychainVault, WindowsDpapiVault, LinuxSecretServiceVault}`: not implemented, every call fails fast
- `apple/` Swift package: `SecureEnclaveVault`, `MasterVault`, `KeychainVault`
- CI: fmt / clippy (pedantic, both feature sets) / test on Linux, macOS, Windows through `scripts/run_tests.sh` (each test binary has a minimum count) / doc / Apple (`scripts/apple_check.sh`: iOS and iOS Simulator libraries, the generated Swift binding, the Swift package for device and Simulator, and the README's conformance snippet typechecked) / security & hygiene (audit, deny, unused dependencies, stub guard, package integrity, coverage) / fuzz (3 targets) / public text / line endings; `scripts/preflight.sh` generated from the workflows
- `tools/uniffi-bindgen`: the binding generator as a separate tool crate, so that its build-time dependencies (askama 0.12 -> basic-toml, unmaintained) stay out of the library
- `VaultError::Irrecoverable` / `ForeignVaultError::Irrecoverable` / Swift `KeystoreError.irrecoverable`: a key that cannot be recovered (wrapping key gone, wrapped blob does not open) is no longer reported as the retryable `Unavailable`
- `MasterVault` stores the secret in numbered slots and writes the new slot before removing the old one (a failure while storing keeps the previous secret)
- `apple/Tests`: slot rules and error classification (`swift test`)
- `scripts/audit_ignore_guard.py` (security-audit の audit job): RUSTSEC-2026-0374 の ignore は basic-toml が Cargo.lock にあり、どの feature でも build されない間だけ有効 build される (reachable) か lock から消えた (stale) ら fail、比較できない時も fail 試験は小さな crate 9 通り (iOS だけで到達、feature の後ろで到達、cargo tree の失敗、Cargo.toml と食い違う lock、空の lock を含む) cargo tree は --locked で走り、lock を解決し直さない
- Apple: every Keychain call goes through `SystemKeychain` with `kSecUseDataProtectionKeychain` (on macOS this needs a signed, entitled app; `KeychainVault` items move from the file-based keychain to the data-protection keychain there); the three vaults are tested through an in-memory keychain with injected faults, and the dictionaries reaching the Security functions are recorded in a test
