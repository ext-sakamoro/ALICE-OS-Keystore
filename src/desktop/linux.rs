//! Linux Secret Service store
//!
//! Each generation is one item in the default collection of the Secret Service
//! (gnome-keyring, `KWallet`) with the attributes `keystore-service` = the store's service
//! name and `keystore-generation` = the generation (decimal, no leading zero), holding the
//! 32 key bytes. The session with the service is encrypted (Diffie-Hellman, as the
//! specification offers).
//!
//! The contract: a caller of [`KeyProvider::current`] that returns generation `g` returns the key
//! every later reader of `g` gets ([`KeyProvider::by_generation`]), so whatever it seals opens
//! again; each successful [`LinuxSecretServiceStore::rotate`] adds a generation of its own, so
//! concurrent successful calls return distinct generations.
//!
//! The Secret Service has no "create unless it exists", and while another creator's `CreateItem`
//! is still running its item (whose object path is already assigned) is not yet listed, so a
//! creator that re-reads cannot know it has seen every competing creator. Choosing a winner from
//! the items afterwards is therefore not enough: a creator could return its own key and a
//! competitor's item, listed a moment later, be the one readers choose (measured against gnome-keyring: racing creators
//! returned different keys for one generation, and two of six racing rotations returned the same
//! generation, in 7 of 91 runs of the two racing tests). So `current` and `rotate` hold a lock for the
//! service while they read, create and re-read: an exclusive lock on a file under
//! `$XDG_RUNTIME_DIR/alice-os-keystore/` (directory 0700, file 0600, named by the SHA-256 of the
//! service name), taken by every call through its own open file, so it excludes other threads and
//! other processes alike and is released when the call ends or the process exits. Before it is
//! released, the creator also waits until its new item is returned by the same search readers use,
//! so the next holder sees it even from a service that lists an item only after `CreateItem` has
//! answered (not observed with gnome-keyring; the wait costs one search when the item is there). The wait for the lock is bounded ([`LinuxSecretServiceStore::lock_deadline`]):
//! a holder stuck on D-Bus makes the others fail with [`KeyProviderError::Unavailable`], not hang.
//! Without `XDG_RUNTIME_DIR` there is no place for the lock (nor, in practice, a session bus) and
//! every `current` / `rotate` is `Unavailable`. Reading a generation takes no lock.
//!
//! Duplicates can still exist: left by an older version of this crate (which had no lock) or by
//! another program writing the same service name. Every reader picks the same one, by what the
//! service alone sets: the earliest `Created` (a read-only property, set by the service when the
//! item is made), ties broken by the item's object path (assigned by the service) compared as a
//! string. That rule must not change: data sealed after such a set settled used the key it picks.
//! A creator re-reads after creating and uses its own key only when its item is the one chosen;
//! otherwise it returns the chosen item's key. An older binary without the lock, running at the
//! same time, can still race with this one: no rule over the items prevents that without an atomic
//! create. The other items are left in place, logged (`log::warn!`, no key material) and counted by
//! [`LinuxSecretServiceStore::duplicate_count`], so a later explicit cleanup can remove them safely.
//! For every generation issued a marker
//! item (attribute `keystore-issued`, no secret) follows the key item (see the generation
//! model in `desktop`); the store looks for a marker before making one, and a duplicate marker
//! from a race is harmless (only its presence counts).
//!
//! Without a reachable service (no D-Bus session bus, as on a headless machine), a locked
//! keyring that cannot be unlocked, or no default collection, every call is
//! [`KeyProviderError::Unavailable`], so the caller can fall back to a passphrase.

use std::collections::{BTreeSet, HashMap};
use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use secret_service::blocking::{Collection, Item, SecretService};
use secret_service::{EncryptionType, Error as SsError};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::{by_generation_of, current_of, generation_of, rotate_of, GenerationItems, Inventory};
use crate::{Key, KeyGeneration, KeyProvider, KeyProviderError};

const SERVICE_ATTR: &str = "keystore-service";
const GENERATION_ATTR: &str = "keystore-generation";
const ISSUED_ATTR: &str = "keystore-issued";
const CONTENT_TYPE: &str = "application/octet-stream";

/// How long `current` / `rotate` wait for the service's lock by default
const LOCK_DEADLINE: Duration = Duration::from_secs(30);
/// How long a creator waits for its new item to be listed by the search readers use
const LISTED_DEADLINE: Duration = Duration::from_secs(10);
/// The pause between attempts while waiting for the lock or for an item to be listed
const POLL: Duration = Duration::from_millis(10);

const LOCK_TIMEOUT: KeyProviderError =
    KeyProviderError::Unavailable("another call held the key store's lock past the deadline");

/// Keys kept in the Secret Service, one item per generation
pub struct LinuxSecretServiceStore {
    service: String,
    lock_deadline: Duration,
}

/// The service's lock, held while the file stays open (closing it releases the lock)
struct ServiceLock {
    _file: File,
}

// the service's own error text can name objects or paths; only the kind is passed on
fn unavailable(e: &SsError) -> KeyProviderError {
    KeyProviderError::Unavailable(match e {
        SsError::Locked | SsError::Prompt | SsError::PromptDisconnected => {
            "the keyring is locked or access was refused"
        }
        SsError::NoResult => "the Secret Service has no default keyring",
        SsError::Unavailable | SsError::Zbus(_) | SsError::ZbusFdo(_) => {
            "the Secret Service cannot be reached"
        }
        _ => "the Secret Service answered unexpectedly",
    })
}

/// The index of the item every reader chooses, from each item's (`Created`, object path):
/// earliest `Created`, then the lowest path compared as a string
///
/// The comparison must stay as it is: for duplicates that already settled, data was sealed with
/// the key this picks (`…/100` is chosen over `…/99` created in the same second).
fn chosen_index(ranks: &[(u64, String)]) -> Option<usize> {
    ranks
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| a.cmp(b))
        .map(|(i, _)| i)
}

/// The item every reader chooses among items of one generation ([`chosen_index`])
fn choose<'a, 'b>(items: &'b [Item<'a>]) -> Result<Option<&'b Item<'a>>, KeyProviderError> {
    let mut ranks = Vec::with_capacity(items.len());
    for item in items {
        ranks.push((
            item.get_created().map_err(|e| unavailable(&e))?,
            item.item_path.to_string(),
        ));
    }
    Ok(chosen_index(&ranks).map(|i| &items[i]))
}

/// Wait until `listed()` reports the new item, polling until `deadline` has passed (a new
/// item's object path exists before a search returns it)
fn wait_listed(
    mut listed: impl FnMut() -> Result<bool, KeyProviderError>,
    deadline: Duration,
) -> Result<(), KeyProviderError> {
    let start = Instant::now();
    loop {
        if listed()? {
            return Ok(());
        }
        if start.elapsed() >= deadline {
            return Err(KeyProviderError::Unavailable(
                "the new Secret Service item was not listed before the deadline",
            ));
        }
        std::thread::sleep(POLL);
    }
}

/// The lock file of `service` under `runtime`: `<runtime>/alice-os-keystore/<SHA-256 of the name>.lock`
fn lock_path_in(runtime: &std::ffi::OsStr, service: &str) -> PathBuf {
    use std::fmt::Write as _;
    let digest = Sha256::digest(service.as_bytes());
    let mut name = String::with_capacity(2 * digest.len());
    for b in &digest {
        // writing to a String cannot fail
        let _ = write!(name, "{b:02x}");
    }
    PathBuf::from(runtime)
        .join("alice-os-keystore")
        .join(format!("{name}.lock"))
}

/// The lock file of `service` under `$XDG_RUNTIME_DIR` (`None` when it is unset or empty)
fn lock_path_of(service: &str) -> Option<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty())?;
    Some(lock_path_in(&runtime, service))
}

/// Take the exclusive lock of `service`, waiting at most `deadline`
fn lock_service(service: &str, deadline: Duration) -> Result<ServiceLock, KeyProviderError> {
    let path = lock_path_of(service).ok_or(KeyProviderError::Unavailable(
        "XDG_RUNTIME_DIR is not set: the key store has no place for its lock",
    ))?;
    let dir = path.parent().expect("the lock path has a directory");
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => {
            return Err(KeyProviderError::Unavailable(
                "the key store's lock directory cannot be created",
            ))
        }
    }
    // an existing directory must be a private directory, not a link or a shared one
    let meta = std::fs::symlink_metadata(dir).map_err(|_| {
        KeyProviderError::Unavailable("the key store's lock directory cannot be read")
    })?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err(KeyProviderError::Unavailable(
            "the key store's lock directory is not a private directory",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .map_err(|_| KeyProviderError::Unavailable("the key store's lock file cannot be opened"))?;
    let start = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(ServiceLock { _file: file }),
            Err(TryLockError::WouldBlock) if start.elapsed() < deadline => {
                std::thread::sleep(POLL);
            }
            Err(TryLockError::WouldBlock) => return Err(LOCK_TIMEOUT),
            Err(TryLockError::Error(_)) => {
                return Err(KeyProviderError::Unavailable(
                    "the key store's lock cannot be taken",
                ))
            }
        }
    }
}

fn with_collection<T>(
    f: impl FnOnce(&Collection<'_>) -> Result<T, KeyProviderError>,
) -> Result<T, KeyProviderError> {
    let ss = SecretService::connect(EncryptionType::Dh).map_err(|e| unavailable(&e))?;
    let collection = ss.get_default_collection().map_err(|e| unavailable(&e))?;
    collection.ensure_unlocked().map_err(|e| unavailable(&e))?;
    f(&collection)
}

impl LinuxSecretServiceStore {
    /// A store for the keys of `service` (a name only this application uses, such as a
    /// reverse-DNS identifier)
    ///
    /// Nothing is read or created until the first call.
    ///
    /// # Panics
    /// When `service` is empty (it would share items with any other program that leaves
    /// the service empty)
    #[must_use]
    pub fn new(service: &str) -> Self {
        assert!(!service.is_empty(), "the Secret Service name is empty");
        Self {
            service: service.to_owned(),
            lock_deadline: LOCK_DEADLINE,
        }
    }

    /// The same store, waiting at most `deadline` for the service's lock (30 s by default);
    /// past it `current` and `rotate` return [`KeyProviderError::Unavailable`]
    #[must_use]
    pub fn lock_deadline(mut self, deadline: Duration) -> Self {
        self.lock_deadline = deadline;
        self
    }

    /// The file whose exclusive lock serializes `current` and `rotate` for this service
    /// (`None` without `XDG_RUNTIME_DIR`)
    #[must_use]
    pub fn lock_path(&self) -> Option<PathBuf> {
        lock_path_of(&self.service)
    }

    /// Add a fresh random key as the next generation (1 when the service holds none) and
    /// return it; the older items stay
    ///
    /// # Errors
    /// [`KeyProviderError::Unavailable`] when the Secret Service cannot be reached or
    /// refuses, the entropy source fails, the generation counter would overflow, or other
    /// processes keep adding generations faster than this call can claim one
    pub fn rotate(&self) -> Result<KeyGeneration, KeyProviderError> {
        let _lock = lock_service(&self.service, self.lock_deadline)?;
        rotate_of(self)
    }

    /// How many stored items are duplicates (left by creators that lost a race), never used
    ///
    /// # Errors
    /// [`KeyProviderError::Unavailable`] when the Secret Service cannot be reached
    pub fn duplicate_count(&self) -> Result<usize, KeyProviderError> {
        with_collection(|c| {
            let items = self.service_items(c)?;
            let generations: BTreeSet<KeyGeneration> = items.iter().map(|(g, _)| *g).collect();
            Ok(items.len() - generations.len())
        })
    }

    /// The items of this service with a canonical generation attribute
    fn service_items<'a>(
        &self,
        c: &'a Collection<'_>,
    ) -> Result<Vec<(KeyGeneration, Item<'a>)>, KeyProviderError> {
        let items = c
            .search_items(HashMap::from([(SERVICE_ATTR, self.service.as_str())]))
            .map_err(|e| unavailable(&e))?;
        let mut out = Vec::new();
        for item in items {
            let attrs = item.get_attributes().map_err(|e| unavailable(&e))?;
            if let Some(g) = attrs
                .get(GENERATION_ATTR)
                .and_then(|v| generation_of(v, "", ""))
            {
                out.push((g, item));
            }
        }
        Ok(out)
    }

    fn generation_items<'a>(
        &self,
        c: &'a Collection<'_>,
        generation: KeyGeneration,
    ) -> Result<Vec<Item<'a>>, KeyProviderError> {
        let g = generation.to_string();
        c.search_items(HashMap::from([
            (SERVICE_ATTR, self.service.as_str()),
            (GENERATION_ATTR, g.as_str()),
        ]))
        .map_err(|e| unavailable(&e))
    }

    fn read_chosen(item: &Item<'_>) -> Result<Key, KeyProviderError> {
        let mut bytes = item.get_secret().map_err(|e| unavailable(&e))?;
        let key = Key::from_slice(&bytes).map_err(|_| {
            KeyProviderError::Irrecoverable("the Secret Service item is not a 32-byte key")
        });
        bytes.zeroize();
        key
    }
}

impl GenerationItems for LinuxSecretServiceStore {
    fn inventory(&self) -> Result<Inventory, KeyProviderError> {
        with_collection(|c| {
            let items = c
                .search_items(HashMap::from([(SERVICE_ATTR, self.service.as_str())]))
                .map_err(|e| unavailable(&e))?;
            let mut inv = Inventory::default();
            for item in items {
                let attrs = item.get_attributes().map_err(|e| unavailable(&e))?;
                if let Some(g) = attrs
                    .get(GENERATION_ATTR)
                    .and_then(|v| generation_of(v, "", ""))
                {
                    inv.keys.insert(g);
                } else if let Some(g) = attrs
                    .get(ISSUED_ATTR)
                    .and_then(|v| generation_of(v, "", ""))
                {
                    inv.issued.insert(g);
                }
            }
            Ok(inv)
        })
    }

    fn read(&self, generation: KeyGeneration) -> Result<Option<Key>, KeyProviderError> {
        with_collection(|c| {
            let items = self.generation_items(c, generation)?;
            if items.len() > 1 {
                log::warn!(
                    "alice-os-keystore: {} duplicate Secret Service items for generation {generation} (the earliest is used)",
                    items.len() - 1
                );
            }
            choose(&items)?.map(Self::read_chosen).transpose()
        })
    }

    /// Create an item for `generation`; `true` only when, re-read afterwards, the item
    /// chosen for that generation is the one just created
    ///
    /// Called under the service's lock; returns only once the new item is listed by the search
    /// readers use, so the next holder of the lock sees it.
    fn create(&self, generation: KeyGeneration, key: &Key) -> Result<bool, KeyProviderError> {
        with_collection(|c| {
            let g = generation.to_string();
            let created = c
                .create_item(
                    &format!("{} key generation {generation}", self.service),
                    HashMap::from([
                        (SERVICE_ATTR, self.service.as_str()),
                        (GENERATION_ATTR, g.as_str()),
                    ]),
                    key.as_bytes(),
                    false,
                    CONTENT_TYPE,
                )
                .map_err(|e| unavailable(&e))?;
            let mut items = Vec::new();
            wait_listed(
                || {
                    items = self.generation_items(c, generation)?;
                    Ok(items.iter().any(|i| i.item_path == created.item_path))
                },
                LISTED_DEADLINE,
            )?;
            Ok(choose(&items)?.is_some_and(|chosen| chosen.item_path == created.item_path))
        })
    }

    fn mark(&self, generation: KeyGeneration) -> Result<(), KeyProviderError> {
        with_collection(|c| {
            let g = generation.to_string();
            let attrs = HashMap::from([
                (SERVICE_ATTR, self.service.as_str()),
                (ISSUED_ATTR, g.as_str()),
            ]);
            let existing = c.search_items(attrs.clone()).map_err(|e| unavailable(&e))?;
            if existing.is_empty() {
                c.create_item(
                    &format!("{} issued generation {generation}", self.service),
                    attrs,
                    b"issued",
                    false,
                    CONTENT_TYPE,
                )
                .map_err(|e| unavailable(&e))?;
            }
            Ok(())
        })
    }
}

impl KeyProvider for LinuxSecretServiceStore {
    /// The highest generation, creating generation 1 when the service holds none
    fn current(&self) -> Result<(KeyGeneration, Key), KeyProviderError> {
        let _lock = lock_service(&self.service, self.lock_deadline)?;
        current_of(self)
    }

    fn by_generation(&self, generation: KeyGeneration) -> Result<Key, KeyProviderError> {
        by_generation_of(self, generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chosen_item_compares_paths_as_strings() {
        // settled data was sealed with the key of the item this picks: `…/100` before `…/99`
        // when both were created in the same second; the rule must not change
        let ranks = [
            (
                1_794_683_208,
                "/org/freedesktop/secrets/collection/login/99".to_owned(),
            ),
            (
                1_794_683_208,
                "/org/freedesktop/secrets/collection/login/100".to_owned(),
            ),
        ];
        assert_eq!(chosen_index(&ranks), Some(1));
        // an earlier `Created` wins whatever the path
        let ranks = [
            (
                1_794_683_207,
                "/org/freedesktop/secrets/collection/login/99".to_owned(),
            ),
            (
                1_794_683_208,
                "/org/freedesktop/secrets/collection/login/100".to_owned(),
            ),
        ];
        assert_eq!(chosen_index(&ranks), Some(0));
        assert_eq!(chosen_index(&[]), None);
    }

    #[test]
    fn a_creator_waits_until_its_item_is_listed() {
        // the item appears on the third search: the wait returns after it, not before
        let mut searches = 0;
        wait_listed(
            || {
                searches += 1;
                Ok(searches >= 3)
            },
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(searches, 3);
    }

    #[test]
    fn an_item_never_listed_fails_the_creator_at_the_deadline() {
        let start = Instant::now();
        let r = wait_listed(|| Ok(false), Duration::from_millis(50));
        assert!(matches!(r, Err(KeyProviderError::Unavailable(m)) if m.contains("not listed")));
        assert!(start.elapsed() >= Duration::from_millis(50));
    }

    #[test]
    fn the_lock_file_is_named_by_the_service_hash_under_the_runtime_dir() {
        // SHA-256("abc") is the FIPS 180-2 example digest: the name is the hash, not the text
        let p = lock_path_in(std::ffi::OsStr::new("/run/user/1000"), "abc");
        assert_eq!(
            p,
            PathBuf::from(
                "/run/user/1000/alice-os-keystore/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.lock"
            )
        );
    }
}
