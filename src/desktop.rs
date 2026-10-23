//! Desktop key stores
//!
//! | store | state |
//! |---|---|
//! | `MacosKeychainStore` (macOS only) | implemented: login keychain, one generic password item per generation |
//! | `WindowsDpapiStore` (Windows only) | implemented: one DPAPI-sealed file per generation under `%LOCALAPPDATA%` |
//! | `LinuxSecretServiceStore` (Linux only) | implemented: one Secret Service item per generation (duplicates from racing creators resolve to one) |
//!
//! The implemented stores share one model: one 32-byte random key per generation, each
//! one item in the operating system's store, created once and never rewritten. `current`
//! returns the highest generation and creates generation 1 when there is none; `rotate`
//! adds the next one; `by_generation` reports a missing item as `Irrecoverable` when a
//! higher generation shows it existed, and as `UnknownGeneration` otherwise. Creating an
//! item that already exists fails in the store itself, so two processes creating the same
//! generation at once cannot both succeed: the loser reads the winner's item. (The Secret
//! Service cannot refuse a second item; there every reader chooses the same one, see the
//! Linux store.)
//!

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
use crate::{Key, KeyGeneration, KeyProviderError};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacosKeychainStore;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::WindowsDpapiStore;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxSecretServiceStore;

/// One operating system store holding one item per generation
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
trait GenerationItems {
    /// The generations present, in any order (names that are not canonical are left out)
    fn generations(&self) -> Result<Vec<KeyGeneration>, KeyProviderError>;
    /// The key of `generation`, `None` when there is no such item
    fn read(&self, generation: KeyGeneration) -> Result<Option<Key>, KeyProviderError>;
    /// Create `generation` holding `key`; `false` when the item already exists
    fn create(&self, generation: KeyGeneration, key: &Key) -> Result<bool, KeyProviderError>;
}

/// How often one call re-reads the items when another process changed them meanwhile
/// (each retry follows an item someone else added, so a retry is progress)
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
const ATTEMPTS: usize = 64;

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
const CHANGING: KeyProviderError =
    KeyProviderError::Unavailable("the stored items kept changing during the call");

/// The generation a name `<prefix><n><suffix>` stands for (`n` decimal without a leading
/// zero, at least 1), `None` for any other name
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn generation_of(name: &str, prefix: &str, suffix: &str) -> Option<KeyGeneration> {
    let digits = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn highest<S: GenerationItems>(s: &S) -> Result<Option<KeyGeneration>, KeyProviderError> {
    Ok(s.generations()?.into_iter().max())
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn fresh_key() -> Result<Key, KeyProviderError> {
    Key::generate().map_err(|_| KeyProviderError::Unavailable("entropy source failed"))
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn current_of<S: GenerationItems>(s: &S) -> Result<(KeyGeneration, Key), KeyProviderError> {
    for _ in 0..ATTEMPTS {
        if let Some(max) = highest(s)? {
            if let Some(key) = s.read(max)? {
                return Ok((max, key));
            }
        } else {
            let key = fresh_key()?;
            if s.create(1, &key)? {
                return Ok((1, key));
            }
        }
    }
    Err(CHANGING)
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn rotate_of<S: GenerationItems>(s: &S) -> Result<KeyGeneration, KeyProviderError> {
    for _ in 0..ATTEMPTS {
        let next = match highest(s)? {
            None => 1,
            Some(max) => max.checked_add(1).ok_or(KeyProviderError::Unavailable(
                "generation counter exhausted",
            ))?,
        };
        if s.create(next, &fresh_key()?)? {
            return Ok(next);
        }
    }
    Err(CHANGING)
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn by_generation_of<S: GenerationItems>(
    s: &S,
    generation: KeyGeneration,
) -> Result<Key, KeyProviderError> {
    if generation == 0 {
        return Err(KeyProviderError::UnknownGeneration(0));
    }
    if let Some(key) = s.read(generation)? {
        return Ok(key);
    }
    // generations are added in order and never removed by these stores: a higher one
    // shows that this one existed
    if s.generations()?.iter().any(|&g| g > generation) {
        Err(KeyProviderError::Irrecoverable(
            "the key of this generation was removed from the store",
        ))
    } else {
        Err(KeyProviderError::UnknownGeneration(generation))
    }
}
