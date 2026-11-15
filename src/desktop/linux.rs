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
//! A store opens one connection to the session bus and one encrypted session with the service on
//! first use and keeps them for its lifetime, shared by every call of that instance (calls of one
//! instance take turns on it). Before, every call opened its own connection and session; the churn
//! of connections that came and went every few milliseconds is what gnome-keyring was handling
//! when it aborted. Each D-Bus call waits at most [`LinuxSecretServiceStore::call_timeout`] (5 s by
//! default) for its answer. A call that finds the service unreachable (no answer in time, the
//! connection gone, the daemon restarted) drops the connection and runs once more on a new one; a
//! second failure is [`KeyProviderError::Unavailable`]. Reads simply run again. A create that runs
//! again first looks for the item it was making, since a lost answer does not mean the service did
//! not create it: an item holding this call's key is adopted, any other item means another creator
//! got there first, and only when the generation has no item is it created again. In the worst case
//! one call therefore takes the lock wait, plus two attempts of (the calls it makes + 2 for a new
//! connection) times the call timeout, plus the listing wait of a create.
//!
//! The session's key (the AES key both sides derive from the Diffie-Hellman exchange, used to
//! encrypt the secrets on the bus) is held in memory for as long as the store lives, instead of for
//! one call; dropping the store ends the session and closes the connection. It is kept inside the
//! `secret-service` crate, which does not zero it when the session is dropped and gives no access
//! to it; the key bytes this crate reads from the service are zeroed after use, as before.
//!
//! Without a reachable service (no D-Bus session bus, as on a headless machine), a locked
//! keyring that cannot be unlocked, or no default collection, every call is
//! [`KeyProviderError::Unavailable`], so the caller can fall back to a passphrase.

use std::collections::{BTreeSet, HashMap};
use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
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
/// How long one D-Bus call waits for its answer by default
const CALL_TIMEOUT: Duration = Duration::from_secs(5);
/// The error of a service that cannot be reached: the one kind of failure a new connection can cure
const UNREACHABLE: &str = "the Secret Service cannot be reached";
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
    call_timeout: Duration,
    /// The connection and session of this store, made on first use and kept
    session: Mutex<Option<SecretService<'static>>>,
}

/// Which run of a call this is: the first, or the one on a new connection after the service could
/// not be reached
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attempt {
    First,
    Retry,
}

/// What a create that runs again finds for its generation
#[derive(Debug, PartialEq, Eq)]
enum Found {
    /// No item: the first run did not create one
    Nothing,
    /// An item holding this call's key: the first run created it; `chosen` as in `create`
    Ours { chosen: bool },
    /// Items, none holding this call's key: another creator got there first
    Others,
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
        SsError::Unavailable | SsError::Zbus(_) | SsError::ZbusFdo(_) => UNREACHABLE,
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

fn is_unreachable(e: &KeyProviderError) -> bool {
    matches!(e, KeyProviderError::Unavailable(m) if *m == UNREACHABLE)
}

/// Run `op` on the session in `slot`, made by `connect` when there is none; when the service cannot
/// be reached, the session is dropped and `op` runs once more ([`Attempt::Retry`]) on a new one, and
/// a second such failure is returned. Other errors are returned at once.
fn with_retry<S, T>(
    slot: &mut Option<S>,
    mut connect: impl FnMut() -> Result<S, KeyProviderError>,
    mut op: impl FnMut(&S, Attempt) -> Result<T, KeyProviderError>,
) -> Result<T, KeyProviderError> {
    let mut last = KeyProviderError::Unavailable(UNREACHABLE);
    for attempt in [Attempt::First, Attempt::Retry] {
        if slot.is_none() {
            match connect() {
                Ok(session) => *slot = Some(session),
                Err(e) if is_unreachable(&e) => {
                    last = e;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        match op(slot.as_ref().expect("a session was just made"), attempt) {
            Ok(v) => return Ok(v),
            Err(e) if is_unreachable(&e) => {
                *slot = None;
                last = e;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// The create of `attempt`: on a run after a lost answer, look first (`look`) and create (`create`)
/// only when the generation has no item
fn create_or_adopt(
    attempt: Attempt,
    look: impl FnOnce() -> Result<Found, KeyProviderError>,
    create: impl FnOnce() -> Result<bool, KeyProviderError>,
) -> Result<bool, KeyProviderError> {
    if attempt == Attempt::Retry {
        match look()? {
            Found::Ours { chosen } => return Ok(chosen),
            Found::Others => return Ok(false),
            Found::Nothing => {}
        }
    }
    create()
}

/// A connection to the session bus whose calls wait at most `timeout`, with an encrypted session
fn connect(timeout: Duration) -> Result<SecretService<'static>, KeyProviderError> {
    let conn = zbus::blocking::connection::Builder::session()
        .and_then(|b| b.method_timeout(timeout).build())
        .map_err(|_| KeyProviderError::Unavailable(UNREACHABLE))?;
    SecretService::connect_with_existing(EncryptionType::Dh, conn).map_err(|e| unavailable(&e))
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
            call_timeout: CALL_TIMEOUT,
            session: Mutex::new(None),
        }
    }

    /// The same store, waiting at most `timeout` for the answer to each D-Bus call (5 s by
    /// default); a call with no answer in time is retried once on a new connection, then
    /// [`KeyProviderError::Unavailable`]
    #[must_use]
    pub fn call_timeout(mut self, timeout: Duration) -> Self {
        self.call_timeout = timeout;
        self
    }

    /// Run `op` on the default collection over this store's connection (made on first use and
    /// kept), once more on a new connection when the service cannot be reached
    fn with_collection<T>(
        &self,
        mut op: impl FnMut(&Collection<'_>, Attempt) -> Result<T, KeyProviderError>,
    ) -> Result<T, KeyProviderError> {
        let mut slot = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        with_retry(
            &mut slot,
            || connect(self.call_timeout),
            |ss, attempt| {
                let collection = ss.get_default_collection().map_err(|e| unavailable(&e))?;
                collection.ensure_unlocked().map_err(|e| unavailable(&e))?;
                op(&collection, attempt)
            },
        )
    }

    /// What the items of `generation` say about `key`, for a create that runs again
    fn look(
        &self,
        c: &Collection<'_>,
        generation: KeyGeneration,
        key: &Key,
    ) -> Result<Found, KeyProviderError> {
        let items = self.generation_items(c, generation)?;
        let mut ours = None;
        for item in &items {
            let mut bytes = item.get_secret().map_err(|e| unavailable(&e))?;
            let same = bytes.as_slice() == key.as_bytes().as_slice();
            bytes.zeroize();
            if same {
                ours = Some(item.item_path.clone());
                break;
            }
        }
        Ok(match ours {
            Some(path) => Found::Ours {
                chosen: choose(&items)?.is_some_and(|c| c.item_path == path),
            },
            None if items.is_empty() => Found::Nothing,
            None => Found::Others,
        })
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
        self.with_collection(|c, _| {
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
        self.with_collection(|c, _| {
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
        self.with_collection(|c, _| {
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
        self.with_collection(|c, attempt| {
            create_or_adopt(
                attempt,
                || self.look(c, generation, key),
                || {
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
                },
            )
        })
    }

    fn mark(&self, generation: KeyGeneration) -> Result<(), KeyProviderError> {
        // looks before it creates, so running it again is safe
        self.with_collection(|c, _| {
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

    const OTHER: KeyProviderError = KeyProviderError::Unavailable("locked");

    #[test]
    fn the_session_is_made_once_and_kept() {
        let mut slot = None;
        let mut connects = 0;
        for _ in 0..3 {
            let r: Result<u8, _> = with_retry(
                &mut slot,
                || {
                    connects += 1;
                    Ok(connects)
                },
                |s, a| {
                    assert_eq!(a, Attempt::First);
                    Ok(*s)
                },
            );
            assert_eq!(r.unwrap(), 1);
        }
        assert_eq!(connects, 1);
    }

    #[test]
    fn an_unreachable_service_gets_one_new_connection_then_fails() {
        let mut slot = Some(0_u8);
        let (mut connects, mut runs) = (0, Vec::new());
        let r: Result<(), _> = with_retry(
            &mut slot,
            || {
                connects += 1;
                Ok(connects)
            },
            |s, a| {
                runs.push((*s, a));
                Err(KeyProviderError::Unavailable(UNREACHABLE))
            },
        );
        assert!(r.is_err_and(|e| is_unreachable(&e)));
        // the kept session, then exactly one new one
        assert_eq!(runs, [(0, Attempt::First), (1, Attempt::Retry)]);
        assert_eq!(connects, 1);
        assert!(slot.is_none());
    }

    #[test]
    fn other_errors_are_not_retried() {
        let mut slot = Some(0_u8);
        let mut runs = 0;
        let r: Result<(), _> = with_retry(
            &mut slot,
            || Ok(1),
            |_, _| {
                runs += 1;
                Err(OTHER)
            },
        );
        assert!(matches!(r, Err(KeyProviderError::Unavailable("locked"))));
        assert_eq!(runs, 1);
        assert_eq!(slot, Some(0), "the session is kept");
    }

    /// A stand-in for the service: the items of one generation as (key byte), and whether the next
    /// create's answer is lost after the item was made
    struct Service {
        items: Vec<u8>,
        lose_next_answer: bool,
    }

    fn create_with_retry(service: &mut Service, key: u8) -> Result<bool, KeyProviderError> {
        let mut slot = Some(());
        let cell = std::cell::RefCell::new(service);
        with_retry(
            &mut slot,
            || Ok(()),
            |(), attempt| {
                create_or_adopt(
                    attempt,
                    || {
                        let s = cell.borrow();
                        Ok(match s.items.iter().position(|k| *k == key) {
                            Some(i) => Found::Ours { chosen: i == 0 },
                            None if s.items.is_empty() => Found::Nothing,
                            None => Found::Others,
                        })
                    },
                    || {
                        let mut s = cell.borrow_mut();
                        s.items.push(key);
                        if std::mem::take(&mut s.lose_next_answer) {
                            return Err(KeyProviderError::Unavailable(UNREACHABLE));
                        }
                        Ok(s.items[0] == key)
                    },
                )
            },
        )
    }

    #[test]
    fn a_create_whose_answer_was_lost_is_adopted_not_made_twice() {
        let mut service = Service {
            items: Vec::new(),
            lose_next_answer: true,
        };
        assert_eq!(create_with_retry(&mut service, 7), Ok(true));
        assert_eq!(service.items, [7], "exactly one item after the lost answer");
    }

    #[test]
    fn a_retried_create_that_finds_another_item_does_not_create() {
        let mut service = Service {
            items: vec![9],
            lose_next_answer: false,
        };
        let r = create_or_adopt(
            Attempt::Retry,
            || Ok(Found::Others),
            || {
                service.items.push(7);
                Ok(true)
            },
        );
        assert_eq!(r, Ok(false));
        assert_eq!(service.items, [9]);
    }

    #[test]
    fn a_retried_create_that_finds_nothing_creates() {
        let mut made = 0;
        let r = create_or_adopt(
            Attempt::Retry,
            || Ok(Found::Nothing),
            || {
                made += 1;
                Ok(true)
            },
        );
        assert_eq!((r, made), (Ok(true), 1));
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
