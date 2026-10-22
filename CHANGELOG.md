# Changelog

## [Unreleased]

### Added

- `KeyVault` (data keys by generation), `DataKey` (zeroed on drop, not printed), `VaultError` (`UnknownKey` / `Unavailable` / `InvalidKeyLength`)
- `MemoryVault`: keys in memory only, for tests and ephemeral data
- `uniffi` feature: `ffi::ForeignKeyVault` callback interface and `ffi::ForeignVaultAdapter` (accepts only 32-byte keys, keeps the error kind)
- `desktop::{MacosKeychainVault, WindowsDpapiVault, LinuxSecretServiceVault}`: not implemented, every call fails fast
- `apple/` Swift package: `SecureEnclaveVault`, `MasterVault`, `KeychainVault`
- CI: fmt / clippy (pedantic, both feature sets) / test on Linux, macOS, Windows through `scripts/run_tests.sh` (each test binary has a minimum count) / doc / Apple (`scripts/apple_check.sh`: iOS and iOS Simulator libraries, the generated Swift binding, the Swift package for device and Simulator, and the README's conformance snippet typechecked) / security & hygiene (audit, deny, unused dependencies, stub guard, package integrity, coverage) / fuzz (3 targets) / public text / line endings; `scripts/preflight.sh` generated from the workflows
- `tools/uniffi-bindgen`: the binding generator as a separate tool crate, so that its build-time dependencies (askama 0.12 -> basic-toml, unmaintained) stay out of the library
- `VaultError::Irrecoverable` / `ForeignVaultError::Irrecoverable` / Swift `KeystoreError.irrecoverable`: a key that cannot be recovered (wrapping key gone, wrapped blob does not open) is no longer reported as the retryable `Unavailable`
- `MasterVault` stores the secret in numbered slots and writes the new slot before removing the old one (a failure while storing keeps the previous secret)
- `apple/Tests`: slot rules and error classification (`swift test`)
- `scripts/audit_ignore_guard.py` (security-audit の audit job): RUSTSEC-2026-0374 の ignore は basic-toml が Cargo.lock にあり、どの feature でも build されない間だけ有効 build される (reachable) か lock から消えた (stale) ら fail、比較できない時も fail 試験は cargo の cache だけで作る小さな crate 4 通り
- Apple: every Keychain call goes through `SystemKeychain` with `kSecUseDataProtectionKeychain` (on macOS this needs a signed, entitled app; `KeychainVault` items move from the file-based keychain to the data-protection keychain there); the three vaults are tested through an in-memory keychain with injected faults, and the dictionaries reaching the Security functions are recorded in a test
