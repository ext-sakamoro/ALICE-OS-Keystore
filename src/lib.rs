//! Data-encryption keys (DEKs) held by the operating system's key store.
//!
//! An application seals its data at rest with a 32-byte DEK and never stores the
//! DEK itself: the key store holds it. Every store here serves keys through one
//! interface, [`KeyProvider`] from `alice-crypto` (re-exported), so the sealing code
//! does not change with the platform:
//!
//! | platform | implementation | state |
//! |---|---|---|
//! | macOS | `desktop::MacosKeychainStore` (macOS only): one generic password item per generation in the login keychain | implemented |
//! | iOS / iPadOS / visionOS | Swift `SecureEnclaveVault` (`apple/`): a Secure Enclave P-256 key wraps the DEK with ECIES, the wrapped blob lives in the Keychain (this device only) | implemented in Swift, reaches Rust through [`ffi::ForeignKeyVault`] |
//! | Android | Keystore (Kotlin) through [`ffi::ForeignKeyVault`] | not yet |
//! | Windows | `desktop::WindowsDpapiStore` (Windows only): one DPAPI-sealed file per generation under `%LOCALAPPDATA%` | implemented |
//! | Linux | `desktop::LinuxSecretServiceStore` (Linux only): one Secret Service item per generation | implemented |
//! | tests, ephemeral use | [`MemoryVault`] | implemented (keys only in memory) |
//!
//! Keys have a *generation* ([`KeyGeneration`], starting at 1; 0 is never a key): data
//! sealed under generation `g` records `g`, so that after a rotation old data still opens
//! with [`KeyProvider::by_generation`] while new data uses [`KeyProvider::current`].
//! Rotation is a method of each store (`rotate`): it adds the next generation and keeps
//! the older keys.
//!
//! ```
//! use alice_os_keystore::{KeyProvider, MemoryVault};
//!
//! let vault = MemoryVault::new();
//! let generation = vault.rotate()?;
//! let (current, key) = vault.current()?;
//! assert_eq!(current, generation);
//! assert_eq!(vault.by_generation(current)?.as_bytes(), key.as_bytes());
//! # Ok::<(), alice_os_keystore::KeyProviderError>(())
//! ```
//!
//! Errors carry fixed reasons only ([`KeyProviderError`] holds `&'static str`): text from
//! the operating system or from a foreign store can name paths or other detail and is not
//! passed on.
//!
//! [`prompt::read_secret`] reads a secret (a passphrase) from a terminal without
//! echoing it, for applications whose keys are derived from what a person types.
//!
//! # Unsafe code
//!
//! `unsafe` code is allowed only in the private `sys` module, which holds the
//! operating system calls this crate makes itself (today the Windows console mode and
//! DPAPI).
//! Every `unsafe` block there carries a `SAFETY:` note. The rest of the crate denies
//! `unsafe` code, and `scripts/unsafe_scope_check.py` (run in CI) fails on any
//! `unsafe` outside `src/sys/`. The macOS Keychain is reached through the
//! `security-framework` crate, without `unsafe` here.

use std::collections::BTreeMap;
use std::sync::Mutex;

pub use alice_crypto::{Key, KeyGeneration, KeyProvider, KeyProviderError};

pub mod desktop;
#[cfg(feature = "uniffi")]
pub mod ffi;
pub mod fs;
#[cfg(any(unix, windows))]
pub mod prompt;
#[cfg(any(unix, windows))]
#[allow(unsafe_code)]
mod sys;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

/// Keys kept only in this process's memory
///
/// For tests and for data that must not outlive the process: nothing is
/// persisted and nothing is protected at rest. Like the desktop stores it never
/// issues a generation number twice: [`MemoryVault::rotate`] takes the next number
/// above every generation ever stored, and a retired generation is
/// [`KeyProviderError::Irrecoverable`].
#[derive(Default)]
pub struct MemoryVault {
    state: Mutex<VaultState>,
}

#[derive(Default)]
struct VaultState {
    keys: BTreeMap<KeyGeneration, Key>,
    /// The highest generation ever stored (0 for none)
    issued: KeyGeneration,
}

impl MemoryVault {
    /// An empty vault
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // a panic while the lock was held cannot leave the state half-written (every
    // operation updates the map and the high-water mark without a call that can panic in
    // between), so a poisoned lock is still usable
    fn lock(&self) -> std::sync::MutexGuard<'_, VaultState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Store `key` as `generation` (replacing a key of the same generation)
    ///
    /// # Panics
    /// When `generation` is 0 (generations start at 1; 0 is never a key)
    pub fn insert(&self, generation: KeyGeneration, key: Key) {
        assert_ne!(generation, 0, "generation 0 is never a key");
        let mut state = self.lock();
        state.keys.insert(generation, key);
        state.issued = state.issued.max(generation);
    }

    /// Add a fresh random key as the next generation (above every generation ever stored,
    /// 1 for a new vault) and return it; the older keys stay
    ///
    /// # Errors
    /// [`KeyProviderError::Unavailable`] when the operating system's entropy source fails,
    /// or when the generation counter would overflow
    pub fn rotate(&self) -> Result<KeyGeneration, KeyProviderError> {
        let key =
            Key::generate().map_err(|_| KeyProviderError::Unavailable("entropy source failed"))?;
        let mut state = self.lock();
        let next = state
            .issued
            .checked_add(1)
            .ok_or(KeyProviderError::Unavailable(
                "generation counter exhausted",
            ))?;
        state.keys.insert(next, key);
        state.issued = next;
        Ok(next)
    }

    /// Forget `generation` (after every value sealed under it was resealed); its number is
    /// not issued again
    pub fn retire(&self, generation: KeyGeneration) {
        self.lock().keys.remove(&generation);
    }
}

impl KeyProvider for MemoryVault {
    /// The highest generation still held (a retired generation was removed on purpose)
    fn current(&self) -> Result<(KeyGeneration, Key), KeyProviderError> {
        self.lock()
            .keys
            .iter()
            .next_back()
            .map(|(g, k)| (*g, k.clone()))
            .ok_or(KeyProviderError::Unavailable("no key in the vault"))
    }

    fn by_generation(&self, generation: KeyGeneration) -> Result<Key, KeyProviderError> {
        if generation == 0 {
            return Err(KeyProviderError::UnknownGeneration(0));
        }
        let state = self.lock();
        match state.keys.get(&generation) {
            Some(key) => Ok(key.clone()),
            None if generation <= state.issued => Err(KeyProviderError::Irrecoverable(
                "the key of this generation was retired",
            )),
            None => Err(KeyProviderError::UnknownGeneration(generation)),
        }
    }
}
