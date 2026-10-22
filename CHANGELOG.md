# Changelog

## [Unreleased]

### Added

- `KeyVault` (data keys by generation), `DataKey` (zeroed on drop, not printed), `VaultError` (`UnknownKey` / `Unavailable` / `InvalidKeyLength`)
- `MemoryVault`: keys in memory only, for tests and ephemeral data
- `uniffi` feature: `ffi::ForeignKeyVault` callback interface and `ffi::ForeignVaultAdapter` (accepts only 32-byte keys, keeps the error kind)
- `desktop::{MacosKeychainVault, WindowsDpapiVault, LinuxSecretServiceVault}`: not implemented, every call fails fast
- `apple/` Swift package: `SecureEnclaveVault`, `MasterVault`, `KeychainVault`
