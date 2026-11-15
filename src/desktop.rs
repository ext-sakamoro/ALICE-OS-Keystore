//! Desktop key stores
//!
//! | store | state |
//! |---|---|
//! | `MacosKeychainStore` (macOS only) | implemented: login keychain, one generic password item per generation |
//! | `WindowsDpapiStore` (Windows only) | implemented: one DPAPI-sealed file per generation under `%LOCALAPPDATA%` |
//! | `LinuxSecretServiceStore` (Linux only) | implemented: one Secret Service item per generation (creators and rotations serialized by a per-service lock under `$XDG_RUNTIME_DIR`) |
//!
//! The implemented stores share one model: one 32-byte random key per generation, each
//! one item in the operating system's store, created once and never rewritten, and for
//! every generation ever issued a create-only marker item, written right after the key
//! item. The highest issued generation is the highest of keys and markers, and a number
//! is never issued twice: `rotate` takes the next number above it, even when the key item
//! of the newest generation was removed. `current` returns the newest generation; when
//! its key item was removed it reports [`crate::KeyProviderError::Irrecoverable`] instead of
//! falling back to an older key (`rotate` is the explicit way on). `by_generation`
//! reports a missing key at or below the highest issued generation as `Irrecoverable`
//! and above it as `UnknownGeneration`. A key item found without its marker (a process
//! stopped between the two writes) gets the marker when it is read.
//!
//! Limit: the markers live in the same store as the keys. A program that removes both the
//! newest key item and its marker erases the record, and that number is issued again.
//!
//! # Floors
//!
//! Each store also implements [`crate::MonotonicFloor`] on the same model: a raise creates one
//! item for the new value (`floor-<name>-<hi>-<lo>`, each number as 20 decimal digits; on Linux
//! the attributes `keystore-floor` = the name and `keystore-floor-value` = `<hi>-<lo>`), never
//! rewritten, then removes the older items of that name (best effort, after the create); a read
//! takes the largest value among the items of that name, and items whose name or value does
//! not parse are ignored. The floor value is not secret and is not sealed.
//!
//! | store | floor items | who can remove them (so lower the floor to "never raised") |
//! |---|---|---|
//! | `MacosKeychainStore` | generic password items in the login keychain, service = the store's, account `floor-<name>-<hi>-<lo>` | any process running as the same macOS user, through the Security framework (`SecItemDelete`), and the user in Keychain Access |
//! | `WindowsDpapiStore` | empty files `floor-<name>-<hi>-<lo>` in the store's directory (`%LOCALAPPDATA%\<service>`) | any process running as the same Windows user (the directory has the user profile's ACL) |
//! | `LinuxSecretServiceStore` | Secret Service items (`keystore-service`, `keystore-floor`, `keystore-floor-value`) in the default collection | any process of the same user that reaches the session bus while the keyring is unlocked |
//!
//! So on desktop a floor means that writing the application's data directory is not enough to
//! roll its state back; it is not protection against a process of the same user, which can
//! delete every floor item (the name then reads `None`) or create one with a value as high as
//! it likes (the consumer then refuses its data: a denial of service, not a rollback). A raise
//! removes the older items only after the new one is listed. On iOS / Android the floor belongs in
//! the platform's key store, reached through `crate::ffi::ForeignMonotonicFloor` (feature
//! `uniffi`).
//!

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
use crate::{FloorError, FloorName, Key, KeyGeneration, KeyProviderError};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub use macos::keychain_serialized;
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

/// What one store holds for a service: the generations with a key item, and the
/// generations marked as issued (each a canonical number; other names are left out)
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
#[derive(Default)]
struct Inventory {
    keys: std::collections::BTreeSet<KeyGeneration>,
    issued: std::collections::BTreeSet<KeyGeneration>,
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
impl Inventory {
    /// The highest generation ever issued (key or marker)
    fn high_water(&self) -> Option<KeyGeneration> {
        self.keys.iter().chain(&self.issued).copied().max()
    }
}

/// One operating system store holding one key item and one marker per generation
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
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
fn fresh_key() -> Result<Key, KeyProviderError> {
    Key::generate().map_err(|_| KeyProviderError::Unavailable("entropy source failed"))
}

/// Read `generation`'s key, recording its marker when the key item has none
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
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

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
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

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
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

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
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

/// One operating system store holding create-only floor items
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
trait FloorItems {
    /// The values of the items of floor `name` present (items that do not parse left out)
    fn floor_values(&self, name: &FloorName) -> Result<Vec<(u64, u64)>, FloorError>;
    /// Create the item of value `v` of floor `name` (an existing item of that value is success)
    fn create_floor(&self, name: &FloorName, v: (u64, u64)) -> Result<(), FloorError>;
    /// Remove the item of value `v` of floor `name` (an absent item is success)
    fn remove_floor(&self, name: &FloorName, v: (u64, u64)) -> Result<(), FloorError>;
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn floor_read_of<S: FloorItems>(s: &S, name: &FloorName) -> Result<Option<(u64, u64)>, FloorError> {
    Ok(s.floor_values(name)?.into_iter().max())
}

/// Raise: create the item of `to` unless a value at least as high is stored, then remove the
/// items below the result (best effort: a leftover only costs an item, the read takes the max)
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn floor_raise_of<S: FloorItems>(
    s: &S,
    name: &FloorName,
    to: (u64, u64),
) -> Result<(u64, u64), FloorError> {
    let present = s.floor_values(name)?;
    let floor = match present.iter().copied().max() {
        Some(stored) if stored >= to => stored,
        _ => {
            s.create_floor(name, to)?;
            // the new item must be listed before any older one is removed, so a reader never sees
            // none (and a create that hit an existing name it cannot parse is not taken as done)
            if !s.floor_values(name)?.contains(&to) {
                return Err(FloorError::Unavailable(
                    "the new floor item is not listed after it was created",
                ));
            }
            to
        }
    };
    for v in present {
        if v < floor {
            let _ = s.remove_floor(name, v);
        }
    }
    Ok(floor)
}
