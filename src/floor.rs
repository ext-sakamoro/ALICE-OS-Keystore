//! Named floors that only go up
//!
//! A floor is a pair `(u64, u64)` stored under a name, compared lexicographically. It can be
//! read and raised, never lowered through this interface: [`MonotonicFloor::raise`] keeps the
//! larger of the stored pair and the one given, so a lower value changes nothing (and is not an
//! error). An application that keeps state in its data directory stores, outside that
//! directory, the lowest version it will accept back, so that whoever can only write the data
//! directory cannot put back an older copy that is otherwise valid.
//!
//! One counter is the pair `(n, 0)`.
//!
//! What a floor gives depends on who else can write where it lives:
//!
//! | store | where | who can remove or lower it |
//! |---|---|---|
//! | [`MemoryFloor`] | this process's memory | nothing persists (tests, reference) |
//! | `desktop::MacosKeychainStore` | generic password items of the login keychain, account `floor-<name>-<hi>-<lo>` | any process of the same macOS user can delete the items through the Security framework (`SecItemDelete` on an item of another program's access list may raise the access dialog, but deleting is not reading); the user can delete them in Keychain Access |
//! | `desktop::LinuxSecretServiceStore` | Secret Service items (attributes `keystore-service`, `keystore-floor`, `keystore-floor-value`) | any process that can talk to the user's session bus (the same user) can delete them while the keyring is unlocked |
//! | `desktop::WindowsDpapiStore` | empty files `floor-<name>-<hi>-<lo>` in `%LOCALAPPDATA%\<service>` | any process of the same Windows user can delete the files (the directory inherits the user's profile ACL); the files are not sealed (the value is not secret) |
//! | `web::WebCryptoStore` (wasm32, feature `web`) | the `IndexedDB` object store `meta`, key `floor/<name>` | the page's own scripts (same origin), clearing the site's data, and eviction when persistence was not granted; values must be below 2^53 |
//! | Apple mobile / Android, through `ffi::ForeignMonotonicFloor` (feature `uniffi`) | what the app implements: the Keychain / the Android Keystore | items there are outside the app's data directory: something that can only write that directory cannot change them (the app itself and the OS can) |
//!
//! So on desktop and in the browser a floor raises the bar for rolling back data (writing the
//! data directory is no longer enough), but it is **not** protection against a process running
//! as the same user, which can delete every floor item: a name whose items were all removed
//! reads `None` again, as if it had never been raised. On iOS and Android the key store is
//! outside what an attacker who can only write the app's data directory reaches.
//!
//! The desktop stores keep one item per raise, created once and never rewritten; a raise
//! creates the item of the new value, then removes the older items of that name (best effort),
//! and a read takes the largest value among the items of that name. Item names that do not
//! parse are ignored. A raise interrupted between the create and the removals leaves an older
//! item next to the newer one, which reads the newer one.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

/// The longest floor name, in bytes
pub const FLOOR_NAME_MAX: usize = 64;

/// The name of a floor: 1 to 64 bytes of ASCII `a-z`, `0-9` and `-`
///
/// The alphabet keeps the name usable inside keychain accounts, Secret Service attributes,
/// file names and `IndexedDB` keys without escaping.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FloorName(String);

impl FloorName {
    /// `name` as a floor name
    ///
    /// # Errors
    /// [`FloorError::InvalidName`] when `name` is empty, longer than [`FLOOR_NAME_MAX`] bytes,
    /// or holds a byte outside `a-z`, `0-9`, `-`
    pub fn new(name: &str) -> Result<Self, FloorError> {
        let ok = !name.is_empty()
            && name.len() <= FLOOR_NAME_MAX
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok {
            Ok(Self(name.to_owned()))
        } else {
            Err(FloorError::InvalidName)
        }
    }

    /// The name as given
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for FloorName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FloorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for FloorName {
    type Error = FloorError;

    fn try_from(name: &str) -> Result<Self, FloorError> {
        Self::new(name)
    }
}

/// Why a floor could not be read or raised
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FloorError {
    /// The name is not a [`FloorName`] (empty, too long, or a byte outside `a-z0-9-`)
    InvalidName,
    /// The store cannot be reached or refused the request (a fixed reason; the operating
    /// system's text is not passed on)
    Unavailable(&'static str),
    /// The value cannot be stored by this store (the browser store keeps JavaScript numbers,
    /// exact only below 2^53)
    OutOfRange,
}

impl fmt::Display for FloorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => f.write_str("a floor name is 1 to 64 bytes of a-z, 0-9 and '-'"),
            Self::Unavailable(why) => write!(f, "the floor store is unavailable: {why}"),
            Self::OutOfRange => f.write_str("the floor value is out of this store's range"),
        }
    }
}

impl std::error::Error for FloorError {}

/// Named `(u64, u64)` values that are raised, never lowered, compared lexicographically
pub trait MonotonicFloor {
    /// The floor of `name`, `None` when it was never raised (or all its items were removed)
    ///
    /// # Errors
    /// [`FloorError::Unavailable`] when the store cannot be read
    fn read(&self, name: &FloorName) -> Result<Option<(u64, u64)>, FloorError>;

    /// Raise the floor of `name` to at least `to` and return the floor after the call: the
    /// larger of the stored value and `to` (a lower `to` changes nothing)
    ///
    /// # Errors
    /// [`FloorError::Unavailable`] when the store cannot be read or written;
    /// [`FloorError::OutOfRange`] when the store cannot hold `to`
    fn raise(&self, name: &FloorName, to: (u64, u64)) -> Result<(u64, u64), FloorError>;
}

/// Floors kept only in this process's memory: for tests and as the reference behaviour
#[derive(Default)]
pub struct MemoryFloor {
    floors: Mutex<BTreeMap<FloorName, (u64, u64)>>,
}

impl MemoryFloor {
    /// No floors
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // every operation replaces one map entry with no call that can panic in between, so a
    // poisoned lock still holds a consistent map
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<FloorName, (u64, u64)>> {
        self.floors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Forget the floor of `name` (what deleting every item of a name does to a persistent
    /// store)
    pub fn remove(&self, name: &FloorName) {
        self.lock().remove(name);
    }
}

impl MonotonicFloor for MemoryFloor {
    fn read(&self, name: &FloorName) -> Result<Option<(u64, u64)>, FloorError> {
        Ok(self.lock().get(name).copied())
    }

    fn raise(&self, name: &FloorName, to: (u64, u64)) -> Result<(u64, u64), FloorError> {
        let mut floors = self.lock();
        let entry = floors.entry(name.clone()).or_insert(to);
        *entry = (*entry).max(to);
        Ok(*entry)
    }
}

/// The item name of value `v` of floor `name`: `floor-<name>-<hi>-<lo>`, each number as 20
/// decimal digits (zero-padded), so names sort by value
#[cfg(any(target_os = "macos", windows))]
pub(crate) fn item_name(name: &FloorName, v: (u64, u64)) -> String {
    format!("floor-{name}-{}", value_text(v))
}

/// `<hi>-<lo>`, each as 20 decimal digits
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
pub(crate) fn value_text(v: (u64, u64)) -> String {
    format!("{:020}-{:020}", v.0, v.1)
}

/// The value of a `<hi>-<lo>` text (exactly 20 digits each, within `u64`), `None` otherwise
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
pub(crate) fn parse_value(text: &str) -> Option<(u64, u64)> {
    let (hi, lo) = text.split_once('-')?;
    Some((digits20(hi)?, digits20(lo)?))
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn digits20(s: &str) -> Option<u64> {
    (s.len() == 20 && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// The value an item name `floor-<name>-<hi>-<lo>` holds for floor `name`; `None` for an item
/// of another floor and for a name that does not parse
#[cfg(any(target_os = "macos", windows))]
pub(crate) fn parse_item(item: &str, name: &FloorName) -> Option<(u64, u64)> {
    let rest = item.strip_prefix("floor-")?;
    // the value is the last 41 bytes (`<20>-<20>`), after a '-'
    let split = rest.len().checked_sub(42)?;
    if !rest.is_char_boundary(split) {
        return None;
    }
    let (owner, value) = rest.split_at(split);
    let value = value.strip_prefix('-')?;
    if owner != name.as_str() {
        return None;
    }
    parse_value(value)
}

#[cfg(all(test, any(target_os = "macos", windows)))]
mod tests {
    use super::*;

    #[test]
    fn item_names_round_trip_and_sort_by_value() {
        let n = FloorName::new("relay-a").unwrap();
        for v in [(0, 0), (1, 2), (u64::MAX, u64::MAX), (7, u64::MAX)] {
            assert_eq!(parse_item(&item_name(&n, v), &n), Some(v));
        }
        assert_eq!(
            item_name(&n, (1, 2)),
            "floor-relay-a-00000000000000000001-00000000000000000002"
        );
        assert!(item_name(&n, (2, 0)) > item_name(&n, (1, u64::MAX)));
    }

    #[test]
    fn items_of_other_floors_and_malformed_items_do_not_parse() {
        let n = FloorName::new("a").unwrap();
        let longer = FloorName::new("a-00000000000000000001").unwrap();
        // the floor `a-00..1` is not the floor `a`
        assert_eq!(parse_item(&item_name(&longer, (2, 3)), &n), None);
        assert_eq!(
            parse_item(&item_name(&longer, (2, 3)), &longer),
            Some((2, 3))
        );
        for bad in [
            "floor-a-1-2",
            "gen-1",
            "issued-1",
            "floor-a-0000000000000000000x-00000000000000000002",
            "floor-a-99999999999999999999-00000000000000000000",
            "floor-a-00000000000000000001_00000000000000000002",
            "floor-a00000000000000000001-00000000000000000002",
            "floor--00000000000000000001-00000000000000000002",
            "floor-a-+0000000000000000001-00000000000000000002",
            "floor-é-00000000000000000001-0000000000000000002",
        ] {
            assert_eq!(parse_item(bad, &n), None, "{bad}");
        }
    }
}
