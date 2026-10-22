//! Desktop key stores: not implemented yet
//!
//! Each type names the store it will use. Until then every call fails fast
//! (`todo!`), so a desktop build never silently runs without a protected key.
//! Gaps, in order: macOS Keychain (data protection keychain, needs a signed
//! binary with an access group), Windows DPAPI / CNG, Linux Secret Service.

use crate::{DataKey, KeyVault, VaultError};

/// macOS Keychain (not implemented)
pub struct MacosKeychainVault;

/// Windows DPAPI / CNG (not implemented)
pub struct WindowsDpapiVault;

/// Linux Secret Service (not implemented)
pub struct LinuxSecretServiceVault;

impl KeyVault for MacosKeychainVault {
    fn current(&self) -> Result<(u32, DataKey), VaultError> {
        todo!("macOS Keychain vault not implemented")
    }
    fn by_id(&self, _generation: u32) -> Result<DataKey, VaultError> {
        todo!("macOS Keychain vault not implemented")
    }
}

impl KeyVault for WindowsDpapiVault {
    fn current(&self) -> Result<(u32, DataKey), VaultError> {
        todo!("Windows DPAPI vault not implemented")
    }
    fn by_id(&self, _generation: u32) -> Result<DataKey, VaultError> {
        todo!("Windows DPAPI vault not implemented")
    }
}

impl KeyVault for LinuxSecretServiceVault {
    fn current(&self) -> Result<(u32, DataKey), VaultError> {
        todo!("Linux Secret Service vault not implemented")
    }
    fn by_id(&self, _generation: u32) -> Result<DataKey, VaultError> {
        todo!("Linux Secret Service vault not implemented")
    }
}
