//! Desktop key stores
//!
//! | store | state |
//! |---|---|
//! | `MacosKeychainStore` (macOS only) | implemented: login keychain, one generic password item per generation |
//! | `WindowsDpapiStore` (Windows only) | implemented: one DPAPI-sealed file per generation under `%LOCALAPPDATA%` |
//! | [`LinuxSecretServiceStore`] | not implemented: every call fails fast (`todo!`) |
//!
//! The implemented stores share one model: one 32-byte random key per generation, each
//! one item in the operating system's store, created once and never rewritten, and for
//! every generation ever issued a create-only marker item, written right after the key
//! item. The highest issued generation is the highest of keys and markers, and a number
//! is never issued twice: `rotate` takes the next number above it, even when the key item
//! of the newest generation was removed. `current` returns the newest generation; when
//! its key item was removed it reports [`KeyProviderError::Irrecoverable`] instead of
//! falling back to an older key (`rotate` is the explicit way on). `by_generation`
//! reports a missing key at or below the highest issued generation as `Irrecoverable`
//! and above it as `UnknownGeneration`. A key item found without its marker (a process
//! stopped between the two writes) gets the marker when it is read.
//!
//! Limit: the markers live in the same store as the keys. A program that removes both the
//! newest key item and its marker erases the record, and that number is issued again.
//!
//! A store that is not implemented never hands out a key or reports success, so a
//! desktop build never silently runs without a protected key.

use crate::{Key, KeyGeneration, KeyProvider, KeyProviderError};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacosKeychainStore;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::WindowsDpapiStore;

/// Linux Secret Service (not implemented)
pub struct LinuxSecretServiceStore;

impl KeyProvider for LinuxSecretServiceStore {
    fn current(&self) -> Result<(KeyGeneration, Key), KeyProviderError> {
        todo!("Linux Secret Service store not implemented")
    }
    fn by_generation(&self, _generation: KeyGeneration) -> Result<Key, KeyProviderError> {
        todo!("Linux Secret Service store not implemented")
    }
}

/// What one store holds for a service: the generations with a key item, and the
/// generations marked as issued (each a canonical number; other names are left out)
#[cfg(any(target_os = "macos", windows))]
#[derive(Default)]
struct Inventory {
    keys: std::collections::BTreeSet<KeyGeneration>,
    issued: std::collections::BTreeSet<KeyGeneration>,
}

#[cfg(any(target_os = "macos", windows))]
impl Inventory {
    /// The highest generation ever issued (key or marker)
    fn high_water(&self) -> Option<KeyGeneration> {
        self.keys.iter().chain(&self.issued).copied().max()
    }
}

/// One operating system store holding one key item and one marker per generation
#[cfg(any(target_os = "macos", windows))]
trait GenerationItems {
    /// The key items and markers present
    fn inventory(&self) -> Result<Inventory, KeyProviderError>;
    /// The key of `generation`, `None` when there is no such key item
    fn read(&self, generation: KeyGeneration) -> Result<Option<Key>, KeyProviderError>;
    /// Create the key item of `generation` holding `key`; `false` when it already exists
    fn create(&self, generation: KeyGeneration, key: &Key) -> Result<bool, KeyProviderError>;
    /// Create the marker of `generation` (an existing marker is success)
    fn mark(&self, generation: KeyGeneration) -> Result<(), KeyProviderError>;
}

/// How often one call re-reads the items when another process changed them meanwhile
/// (each retry follows an item someone else added or removed)
#[cfg(any(target_os = "macos", windows))]
const ATTEMPTS: usize = 64;

#[cfg(any(target_os = "macos", windows))]
const CHANGING: KeyProviderError =
    KeyProviderError::Unavailable("the stored items kept changing during the call");

/// The generation a name `<prefix><n><suffix>` stands for (`n` decimal without a leading
/// zero, at least 1), `None` for any other name
#[cfg(any(target_os = "macos", windows))]
fn generation_of(name: &str, prefix: &str, suffix: &str) -> Option<KeyGeneration> {
    let digits = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(any(target_os = "macos", windows))]
fn fresh_key() -> Result<Key, KeyProviderError> {
    Key::generate().map_err(|_| KeyProviderError::Unavailable("entropy source failed"))
}

/// Read `generation`'s key, recording its marker when the key item has none
#[cfg(any(target_os = "macos", windows))]
fn read_marked<S: GenerationItems>(
    s: &S,
    inv: &Inventory,
    generation: KeyGeneration,
) -> Result<Option<Key>, KeyProviderError> {
    let key = s.read(generation)?;
    if key.is_some() && !inv.issued.contains(&generation) {
        s.mark(generation)?;
    }
    Ok(key)
}

#[cfg(any(target_os = "macos", windows))]
fn current_of<S: GenerationItems>(s: &S) -> Result<(KeyGeneration, Key), KeyProviderError> {
    for _ in 0..ATTEMPTS {
        let inv = s.inventory()?;
        if let Some(top) = inv.high_water() {
            if let Some(key) = read_marked(s, &inv, top)? {
                return Ok((top, key));
            }
            if inv.issued.contains(&top) {
                return Err(KeyProviderError::Irrecoverable(
                    "the key of the newest generation was removed (rotate to issue a new one)",
                ));
            }
            // the key item was listed but is gone now, without a marker: look again
        } else {
            let key = fresh_key()?;
            if s.create(1, &key)? {
                s.mark(1)?;
                return Ok((1, key));
            }
        }
    }
    Err(CHANGING)
}

#[cfg(any(target_os = "macos", windows))]
fn rotate_of<S: GenerationItems>(s: &S) -> Result<KeyGeneration, KeyProviderError> {
    for _ in 0..ATTEMPTS {
        let next = match s.inventory()?.high_water() {
            None => 1,
            Some(top) => top.checked_add(1).ok_or(KeyProviderError::Unavailable(
                "generation counter exhausted",
            ))?,
        };
        if s.create(next, &fresh_key()?)? {
            s.mark(next)?;
            return Ok(next);
        }
    }
    Err(CHANGING)
}

#[cfg(any(target_os = "macos", windows))]
fn by_generation_of<S: GenerationItems>(
    s: &S,
    generation: KeyGeneration,
) -> Result<Key, KeyProviderError> {
    if generation == 0 {
        return Err(KeyProviderError::UnknownGeneration(0));
    }
    let inv = s.inventory()?;
    if let Some(key) = read_marked(s, &inv, generation)? {
        return Ok(key);
    }
    // numbers are issued in order and never reused: one at or below the highest issued
    // existed, so its key was removed
    if inv.high_water().is_some_and(|top| generation <= top) {
        Err(KeyProviderError::Irrecoverable(
            "the key of this generation was removed from the store",
        ))
    } else {
        Err(KeyProviderError::UnknownGeneration(generation))
    }
}
