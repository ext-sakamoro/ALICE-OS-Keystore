//! Desktop key stores
//!
//! | store | state |
//! |---|---|
//! | `MacosKeychainStore` (macOS only) | implemented: login keychain, one generic password item per generation |
//! | [`WindowsDpapiStore`] | not implemented: every call fails fast (`todo!`) |
//! | [`LinuxSecretServiceStore`] | not implemented: every call fails fast (`todo!`) |
//!
//! A store that is not implemented never hands out a key or reports success, so a
//! desktop build never silently runs without a protected key.

use crate::{Key, KeyGeneration, KeyProvider, KeyProviderError};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacosKeychainStore;

/// Windows DPAPI (not implemented)
pub struct WindowsDpapiStore;

/// Linux Secret Service (not implemented)
pub struct LinuxSecretServiceStore;

impl KeyProvider for WindowsDpapiStore {
    fn current(&self) -> Result<(KeyGeneration, Key), KeyProviderError> {
        todo!("Windows DPAPI store not implemented")
    }
    fn by_generation(&self, _generation: KeyGeneration) -> Result<Key, KeyProviderError> {
        todo!("Windows DPAPI store not implemented")
    }
}

impl KeyProvider for LinuxSecretServiceStore {
    fn current(&self) -> Result<(KeyGeneration, Key), KeyProviderError> {
        todo!("Linux Secret Service store not implemented")
    }
    fn by_generation(&self, _generation: KeyGeneration) -> Result<Key, KeyProviderError> {
        todo!("Linux Secret Service store not implemented")
    }
}
