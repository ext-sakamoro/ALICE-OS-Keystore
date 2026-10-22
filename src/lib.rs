//! Data-encryption keys (DEKs) held by the operating system's key store.
//!
//! An application seals its data at rest with a 32-byte DEK and never stores the
//! DEK itself: the key store holds it, wrapped by a key the hardware does not
//! release. [`KeyVault`] is the one interface the application sees, whatever
//! holds the key:
//!
//! | platform | implementation | state |
//! |---|---|---|
//! | iOS / iPadOS / visionOS | Swift `SecureEnclaveVault` (`apple/`): a Secure Enclave P-256 key wraps the DEK with ECIES, the wrapped blob lives in the Keychain (this device only) | implemented in Swift, reaches Rust through [`ffi::ForeignKeyVault`] |
//! | Android | Keystore (Kotlin) through [`ffi::ForeignKeyVault`] | not yet |
//! | macOS / Windows / Linux | [`desktop`] | not yet: fails fast |
//! | tests, ephemeral use | [`MemoryVault`] | implemented (keys only in memory) |
//!
//! Keys have a *generation* (a `u32`): data sealed under generation `g` records
//! `g`, so that after a key rotation old data still opens with [`KeyVault::by_id`]
//! while new data uses [`KeyVault::current`].
//!
//! ```
//! use alice_os_keystore::{KeyVault, MemoryVault};
//!
//! let vault = MemoryVault::new();
//! let generation = vault.generate()?;
//! let (current, key) = vault.current()?;
//! assert_eq!(current, generation);
//! assert_eq!(vault.by_id(current)?.as_bytes(), key.as_bytes());
//! # Ok::<(), alice_os_keystore::VaultError>(())
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use zeroize::Zeroize;

pub mod desktop;
#[cfg(feature = "uniffi")]
pub mod ffi;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

/// A 32-byte data-encryption key, zeroed on drop
///
/// `Debug` does not print the bytes.
#[derive(Clone)]
pub struct DataKey([u8; 32]);

impl DataKey {
    /// Wrap raw key bytes
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The key bytes (copy them only into memory that is zeroed afterwards)
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for DataKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataKey(..)")
    }
}

/// Why a key store did not hand out a key
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultError {
    /// The store holds no key of this generation (data sealed under a key that is gone)
    UnknownKey(u32),
    /// The store cannot hand out keys right now (device locked, user refused authentication, store empty)
    Unavailable(String),
    /// A key store implemented outside Rust returned a key that is not 32 bytes
    InvalidKeyLength(usize),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey(g) => write!(f, "no data key of generation {g}"),
            Self::Unavailable(why) => write!(f, "key store unavailable: {why}"),
            Self::InvalidKeyLength(n) => write!(f, "key store returned {n} bytes, expected 32"),
        }
    }
}

impl std::error::Error for VaultError {}

/// Hands out data-encryption keys by generation
pub trait KeyVault: Send + Sync {
    /// The generation and key to seal new data with
    ///
    /// # Errors
    /// [`VaultError::Unavailable`] when no key can be handed out now
    fn current(&self) -> Result<(u32, DataKey), VaultError>;

    /// The key of `generation`, to open data sealed under it
    ///
    /// # Errors
    /// [`VaultError::UnknownKey`] when the store has no such generation,
    /// [`VaultError::Unavailable`] when it cannot hand out keys now
    fn by_id(&self, generation: u32) -> Result<DataKey, VaultError>;
}

/// Keys kept only in this process's memory
///
/// For tests and for data that must not outlive the process: nothing is
/// persisted and nothing is protected at rest.
#[derive(Default)]
pub struct MemoryVault {
    keys: Mutex<BTreeMap<u32, DataKey>>,
}

impl MemoryVault {
    /// An empty vault
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // a panic while the lock was held cannot leave the map half-written (every
    // operation is one insert / remove / read), so a poisoned lock is still usable
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u32, DataKey>> {
        self.keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Store `key` as `generation` (replacing a key of the same generation)
    pub fn insert(&self, generation: u32, key: DataKey) {
        self.lock().insert(generation, key);
    }

    /// Add a fresh random key as the next generation (1 for an empty vault) and return it
    ///
    /// # Errors
    /// [`VaultError::Unavailable`] when the operating system's entropy source fails,
    /// or when the generation counter would overflow
    pub fn generate(&self) -> Result<u32, VaultError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| VaultError::Unavailable(format!("entropy: {e}")))?;
        let key = DataKey::from_bytes(bytes);
        bytes.zeroize();
        let mut keys = self.lock();
        let next = match keys.keys().next_back() {
            None => 1,
            Some(&g) => g
                .checked_add(1)
                .ok_or_else(|| VaultError::Unavailable("generation counter exhausted".into()))?,
        };
        keys.insert(next, key);
        Ok(next)
    }

    /// Forget `generation` (after every value sealed under it was resealed)
    pub fn retire(&self, generation: u32) {
        self.lock().remove(&generation);
    }
}

impl KeyVault for MemoryVault {
    fn current(&self) -> Result<(u32, DataKey), VaultError> {
        let keys = self.lock();
        keys.iter()
            .next_back()
            .map(|(g, k)| (*g, k.clone()))
            .ok_or_else(|| VaultError::Unavailable("no key in the vault".into()))
    }

    fn by_id(&self, generation: u32) -> Result<DataKey, VaultError> {
        self.lock()
            .get(&generation)
            .cloned()
            .ok_or(VaultError::UnknownKey(generation))
    }
}
