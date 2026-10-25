//! Oracle for the macOS Keychain store, against the real login keychain.
//!
//! The model (fixed before the implementation): one 32-byte random key per generation, each a
//! generic password item with service = the store's service name and account = `gen-<n>`, and
//! for each generation ever issued a create-only marker item `issued-<n>`, so no generation
//! number is issued twice even when its key item is removed.
//! `current` returns the highest generation, creating generation 1 when the service holds none;
//! `rotate` adds `max + 1` and keeps the older items; `by_generation(g)` returns the item's bytes,
//! `UnknownGeneration` when no item `gen-<g>` exists and no higher generation does either, and
//! `Irrecoverable` when the item is gone but a higher generation shows it once existed (or when the
//! item does not hold 32 bytes).
//!
//! Each test uses its own service name (`alice-os-keystore-test.<test>.<pid>.<nanos>`) and deletes
//! its items at the end, also when it panics. A run that is killed cannot clean up, so each run
//! writes the service names it creates to a manifest file before creating them, and the first
//! test of every run sweeps the services listed in other runs' manifests whose time stamp is older
//! than `STALE` (and never any other service name). The sweep looks each listed service up by
//! name: a keychain-wide search can miss items another process added just before. The items are
//! read and removed behind the store's back with Security.framework directly, as another program
//! would.
#![cfg(target_os = "macos")]

use alice_crypto::{KeyProvider, KeyProviderError};
use alice_os_keystore::desktop::{keychain_serialized, MacosKeychainStore};
use security_framework::base::Error as SecError;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
use security_framework::passwords;

// The direct Security.framework calls below take the store's process-wide lock, as the store
// does for its own: the file-based keychain can deadlock inside the framework when threads of
// one process add, search and delete at once

fn get_generic_password(service: &str, account: &str) -> Result<Vec<u8>, SecError> {
    keychain_serialized(|| passwords::get_generic_password(service, account))
}

fn set_generic_password(service: &str, account: &str, data: &[u8]) -> Result<(), SecError> {
    keychain_serialized(|| passwords::set_generic_password(service, account, data))
}

fn delete_generic_password(service: &str, account: &str) -> Result<(), SecError> {
    keychain_serialized(|| passwords::delete_generic_password(service, account))
}

const PREFIX: &str = "alice-os-keystore-test.";

/// Items of a test run this old were left by a run that was killed
const STALE: std::time::Duration = std::time::Duration::from_mins(30);

#[allow(
    clippy::disallowed_methods,
    reason = "a unique, sortable test item name and the age of items left by killed runs; it reaches no output of the crate"
)]
fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// A keychain-wide search (no service), its result and any error thrown away. Only
/// `a_marker_added_after_another_threads_search_still_counts` runs it, as the interference that
/// test is about; it can fail or miss items while other tests add and delete theirs, so nothing
/// relies on what it finds, and the sweep never searches this way
fn wide_search() {
    keychain_serialized(|| {
        let _ = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .load_attributes(true)
            .limit(Limit::All)
            .search();
    });
}

/// The services among `names` that belong to a test run older than `max_age` at `now`
/// (nanoseconds since the epoch): only `alice-os-keystore-test.<name>.<pid>.<nanos>` with a
/// numeric pid and time stamp; any other name, and a test service without a time stamp, is never
/// selected. Pure: no keychain.
fn select_stale(names: &[String], now: u128, max_age: std::time::Duration) -> Vec<String> {
    names
        .iter()
        .filter(|svce| {
            let Some(rest) = svce.strip_prefix(PREFIX) else {
                return false;
            };
            let parts: Vec<&str> = rest.split('.').collect();
            if parts.len() < 3
                || parts[0].is_empty()
                || parts[parts.len() - 2].parse::<u32>().is_err()
            {
                return false;
            }
            let Ok(stamp) = parts[parts.len() - 1].parse::<u128>() else {
                return false;
            };
            now.saturating_sub(stamp) > max_age.as_nanos()
        })
        .cloned()
        .collect()
}

/// The accounts the keychain holds under `service`, sorted (a search filtered by the service)
fn accounts_of(service: &str) -> Vec<String> {
    let found = keychain_serialized(|| {
        ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(service)
            .load_attributes(true)
            .limit(Limit::All)
            .search()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|r| r.simplify_dict()?.get("acct").cloned())
                    .collect::<Vec<String>>()
            })
    });
    let mut accounts: Vec<String> = match found {
        Ok(accounts) => accounts,
        Err(e) if e.code() == -25300 => Vec::new(), // errSecItemNotFound
        Err(e) => panic!("keychain search failed: {e}"),
    };
    accounts.sort();
    accounts
}

/// The directory of the run manifests: one file per test run, named like a test service
/// (`alice-os-keystore-test.run.<pid>.<nanos>`), one service name per line
fn manifest_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("keystore-test-runs")
}

static RUN_MANIFEST: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// This run's manifest of the test services it creates
fn run_manifest() -> std::path::PathBuf {
    RUN_MANIFEST
        .get_or_init(|| {
            let root = manifest_root();
            std::fs::create_dir_all(&root).unwrap();
            root.join(format!(
                "{PREFIX}run.{}.{}",
                std::process::id(),
                now_nanos()
            ))
        })
        .clone()
}

static RECORD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Append `service` to this run's manifest (written through before any item of it exists). The
/// tests run on several threads: one write of the whole line, under a lock, so lines never mix
fn record(service: &str) {
    use std::io::Write;
    let _guard = RECORD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(run_manifest())
        .unwrap();
    f.write_all(format!("{service}\n").as_bytes()).unwrap();
    f.sync_all().unwrap();
}

/// Remove the items of every test service named in a manifest under `dir` whose own time stamp
/// is older than `max_age` (see `select_stale`), each looked up by its service; a manifest whose
/// test services are all stale is removed too. Lines outside the test prefix are never touched.
/// Returns how many items were removed; a missing or empty directory removes nothing.
fn sweep_manifests(dir: &std::path::Path, now: u128, max_age: std::time::Duration) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let own = RUN_MANIFEST.get().cloned();
    let mut removed = 0;
    for path in entries.filter_map(|e| Some(e.ok()?.path())) {
        if Some(&path) == own.as_ref() {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let listed: Vec<String> = text
            .lines()
            .filter(|l| l.starts_with(PREFIX))
            .map(str::to_owned)
            .collect();
        let stale = select_stale(&listed, now, max_age);
        for service in &stale {
            for account in accounts_of(service) {
                if delete_generic_password(service, &account).is_ok() {
                    removed += 1;
                }
            }
        }
        if stale.len() == listed.len() {
            let _ = std::fs::remove_file(&path);
        }
    }
    removed
}

static SWEEP: std::sync::Once = std::sync::Once::new();

/// A service name no other test or program uses; its items are deleted on drop
struct Service(String);

impl Service {
    fn new(test: &str) -> Self {
        SWEEP.call_once(|| {
            sweep_manifests(&manifest_root(), now_nanos(), STALE);
        });
        let name = format!("{PREFIX}{test}.{}.{}", std::process::id(), now_nanos());
        record(&name);
        Self(name)
    }

    /// The accounts the keychain holds under this service, sorted
    fn accounts(&self) -> Vec<String> {
        accounts_of(&self.0)
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        for account in self.accounts() {
            let _ = delete_generic_password(&self.0, &account);
        }
    }
}

#[test]
fn the_first_current_creates_generation_1_as_one_keychain_item() {
    let s = Service::new("first");
    let store = MacosKeychainStore::new(&s.0);
    assert!(s.accounts().is_empty());
    let (g, k) = store.current().unwrap();
    assert_eq!(g, 1);
    assert_eq!(s.accounts(), ["gen-1", "issued-1"]);
    // the item holds exactly the key, and the key is not all zero
    assert_eq!(get_generic_password(&s.0, "gen-1").unwrap(), k.as_bytes());
    assert_ne!(k.as_bytes(), &[0; 32]);
    // a second call, and a second store on the same service, return the same key
    let (g2, k2) = store.current().unwrap();
    let (g3, k3) = MacosKeychainStore::new(&s.0).current().unwrap();
    assert_eq!((g2, g3), (1, 1));
    assert_eq!(k2.as_bytes(), k.as_bytes());
    assert_eq!(k3.as_bytes(), k.as_bytes());
    assert_eq!(s.accounts(), ["gen-1", "issued-1"]);
}

#[test]
fn rotate_adds_the_next_generation_and_keeps_the_old_key() {
    let s = Service::new("rotate");
    let store = MacosKeychainStore::new(&s.0);
    let (_, k1) = store.current().unwrap();
    assert_eq!(store.rotate().unwrap(), 2);
    assert_eq!(store.rotate().unwrap(), 3);
    assert_eq!(
        s.accounts(),
        ["gen-1", "gen-2", "gen-3", "issued-1", "issued-2", "issued-3"]
    );
    let (g, k3) = store.current().unwrap();
    assert_eq!(g, 3);
    assert_eq!(store.by_generation(1).unwrap().as_bytes(), k1.as_bytes());
    let k2 = store.by_generation(2).unwrap();
    assert_ne!(k1.as_bytes(), k2.as_bytes());
    assert_ne!(k2.as_bytes(), k3.as_bytes());
    assert_eq!(get_generic_password(&s.0, "gen-2").unwrap(), k2.as_bytes());
}

#[test]
fn rotate_on_an_empty_service_creates_generation_1() {
    let s = Service::new("rotate-empty");
    let store = MacosKeychainStore::new(&s.0);
    assert_eq!(store.rotate().unwrap(), 1);
    assert_eq!(s.accounts(), ["gen-1", "issued-1"]);
}

#[test]
fn unknown_and_zero_generations_are_unknown() {
    let s = Service::new("unknown");
    let store = MacosKeychainStore::new(&s.0);
    assert_eq!(
        store.by_generation(1).err().expect("an error"),
        KeyProviderError::UnknownGeneration(1)
    );
    store.current().unwrap();
    assert_eq!(
        store.by_generation(0).err().expect("an error"),
        KeyProviderError::UnknownGeneration(0)
    );
    assert_eq!(
        store.by_generation(2).err().expect("an error"),
        KeyProviderError::UnknownGeneration(2)
    );
    // reading does not create items
    assert_eq!(s.accounts(), ["gen-1", "issued-1"]);
}

#[test]
fn a_removed_older_generation_is_irrecoverable() {
    let s = Service::new("removed");
    let store = MacosKeychainStore::new(&s.0);
    store.current().unwrap();
    store.rotate().unwrap();
    delete_generic_password(&s.0, "gen-1").unwrap();
    assert!(matches!(
        store.by_generation(1),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert_eq!(store.current().unwrap().0, 2);
}

#[test]
fn an_item_that_is_not_32_bytes_is_irrecoverable() {
    let s = Service::new("short");
    set_generic_password(&s.0, "gen-1", &[7; 16]).unwrap();
    let store = MacosKeychainStore::new(&s.0);
    assert!(matches!(
        store.by_generation(1),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert!(matches!(
        store.current(),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    // the broken item is left as it was: nothing is overwritten
    assert_eq!(get_generic_password(&s.0, "gen-1").unwrap(), [7; 16]);
}

#[test]
fn accounts_that_are_not_canonical_generations_are_ignored() {
    let s = Service::new("foreign");
    for account in ["gen-0", "gen-01", "gen-x", "other", "gen-4294967296"] {
        set_generic_password(&s.0, account, &[1; 32]).unwrap();
    }
    let store = MacosKeychainStore::new(&s.0);
    let (g, _) = store.current().unwrap();
    assert_eq!(g, 1);
    assert_eq!(store.rotate().unwrap(), 2);
}

#[test]
fn concurrent_first_use_agrees_on_one_key() {
    let s = Service::new("race");
    let keys: Vec<(u32, [u8; 32])> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    let (g, k) = MacosKeychainStore::new(&s.0).current().unwrap();
                    (g, *k.as_bytes())
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(keys.iter().all(|k| *k == keys[0]), "{keys:?}");
    assert_eq!(s.accounts(), ["gen-1", "issued-1"]);
}

#[test]
fn concurrent_rotations_each_get_their_own_generation() {
    let s = Service::new("rotate-race");
    MacosKeychainStore::new(&s.0).current().unwrap();
    let mut got: Vec<u32> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..6)
            .map(|_| scope.spawn(|| MacosKeychainStore::new(&s.0).rotate().unwrap()))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    got.sort_unstable();
    assert_eq!(got, [2, 3, 4, 5, 6, 7]);
    assert_eq!(s.accounts().len(), 14);
}

#[test]
fn the_store_is_a_shareable_key_provider_object() {
    let s = Service::new("object");
    let store: std::sync::Arc<dyn KeyProvider> = std::sync::Arc::new(MacosKeychainStore::new(&s.0));
    let other = store.clone();
    let g = std::thread::spawn(move || other.current().unwrap().0)
        .join()
        .unwrap();
    assert_eq!(g, 1);
}

#[test]
fn a_removed_newest_generation_is_never_issued_again() {
    // probe: rotate 1, rotate 2, remove gen-2 behind the store's back
    let s = Service::new("removed-top");
    let store = MacosKeychainStore::new(&s.0);
    assert_eq!(store.rotate().unwrap(), 1);
    let k1 = store.by_generation(1).unwrap();
    assert_eq!(store.rotate().unwrap(), 2);
    delete_generic_password(&s.0, "gen-2").unwrap();
    // generation 2 existed: its key is gone, not unknown, and no other key is handed out for it
    assert!(matches!(
        store.by_generation(2),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    // current does not fall back to generation 1 silently
    assert!(matches!(
        store.current(),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    // the way forward is an explicit rotation, which skips the removed number
    assert_eq!(store.rotate().unwrap(), 3);
    assert_eq!(store.current().unwrap().0, 3);
    assert!(matches!(
        store.by_generation(2),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert_eq!(store.by_generation(1).unwrap().as_bytes(), k1.as_bytes());
}

#[test]
fn a_key_item_without_its_marker_gets_the_marker_when_read() {
    // a process stopped between writing the key item and its marker leaves the key alone; the
    // next read records the marker, so removing the key afterwards cannot free the number
    let s = Service::new("heal");
    set_generic_password(&s.0, "gen-1", &[5; 32]).unwrap();
    let store = MacosKeychainStore::new(&s.0);
    assert_eq!(store.current().unwrap().0, 1);
    assert_eq!(s.accounts(), ["gen-1", "issued-1"]);
    delete_generic_password(&s.0, "gen-1").unwrap();
    assert!(matches!(
        store.current(),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert_eq!(store.rotate().unwrap(), 2);
}

#[test]
fn removing_both_the_newest_key_and_its_marker_frees_the_number() {
    // documented limit: the store keeps its record in the same keychain; a program that removes
    // both items of the newest generation erases the record, and the number is issued again
    let s = Service::new("removed-both");
    let store = MacosKeychainStore::new(&s.0);
    store.rotate().unwrap();
    store.rotate().unwrap();
    delete_generic_password(&s.0, "gen-2").unwrap();
    delete_generic_password(&s.0, "issued-2").unwrap();
    assert_eq!(store.current().unwrap().0, 1);
    assert_eq!(store.rotate().unwrap(), 2);
}

#[test]
fn select_stale_takes_only_old_test_runs() {
    let min = 60 * 1_000_000_000u128;
    let now = 1_000_000 * min;
    let name = |n: &str| format!("{PREFIX}{n}");
    let names = vec![
        name(&format!("a.12.{}", now - 31 * min)),         // stale
        name(&format!("a.12.{}", now - 29 * min)),         // live
        name(&format!("a.12.{}", now - 30 * min)),         // exactly the limit: kept
        name(&format!("a.b.c.12.{}", now - 2 * 60 * min)), // dots in the test name: stale
        name(&format!("a.12.{}", now + min)),              // from the future: kept
        name(&format!("a.notapid.{}", now - 2 * 60 * min)),
        name(&format!(".12.{}", now - 2 * 60 * min)), // empty test name
        name("no-stamp"),
        name(&format!("a.12.x{}", now - 2 * 60 * min)),
        format!("alice-os-keystore-tests.a.12.{}", now - 2 * 60 * min),
        format!("x-{PREFIX}a.12.{}", now - 2 * 60 * min),
        "alice-os-keystore-test".to_owned(),
        "other-app.keys".to_owned(),
    ];
    let got = select_stale(&names, now, STALE);
    assert_eq!(got, [names[0].clone(), names[3].clone()]);
    assert!(select_stale(&[], now, STALE).is_empty());
}

/// A manifest directory of its own for one sweep test (the real runs' manifests stay apart)
fn manifest_dir(test: &str) -> std::path::PathBuf {
    let d = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "keystore-sweep-{test}-{}-{}",
        std::process::id(),
        now_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn the_sweep_removes_the_services_of_a_stale_run_manifest_and_keeps_a_live_one() {
    // a killed run left a manifest naming its services; the sweep finds those items by their
    // service only (no keychain-wide search), deletes them and the manifest, and leaves a live
    // run, an unlisted service and a listed name outside the test prefix alone
    let min = 60 * 1_000_000_000u128;
    let now = now_nanos();
    let dir = manifest_dir("stale");
    let tag = format!("sweep{}x{now}", std::process::id());
    let old_run = format!("{PREFIX}run.{}.{}", std::process::id(), now - 31 * min);
    let live_run = format!("{PREFIX}run.{}.{now}", std::process::id());
    let old = format!("{PREFIX}{tag}-old.1.{}", now - 31 * min);
    let live = format!("{PREFIX}{tag}-live.1.{now}");
    let unlisted = format!("{PREFIX}{tag}-unlisted.1.{}", now - 31 * min);
    let outside = format!("x-{PREFIX}{tag}-outside.1.{}", now - 31 * min);
    for s in [&old, &live, &unlisted, &outside] {
        for account in ["gen-1", "issued-1"] {
            set_generic_password(s, account, &[1; 32]).unwrap();
        }
    }
    std::fs::write(dir.join(&old_run), format!("{old}\n{outside}\n")).unwrap();
    std::fs::write(dir.join(&live_run), format!("{live}\n")).unwrap();
    let removed = sweep_manifests(&dir, now, STALE);
    let gone = get_generic_password(&old, "gen-1").is_err()
        && get_generic_password(&old, "issued-1").is_err();
    let kept = |s: &str| {
        get_generic_password(s, "gen-1").is_ok() && get_generic_password(s, "issued-1").is_ok()
    };
    let (live_kept, unlisted_kept, outside_kept) = (kept(&live), kept(&unlisted), kept(&outside));
    for s in [&old, &live, &unlisted, &outside] {
        for account in ["gen-1", "issued-1"] {
            let _ = delete_generic_password(s, account);
        }
    }
    let old_manifest_gone = !dir.join(&old_run).exists();
    let live_manifest_kept = dir.join(&live_run).exists();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(gone, "the stale run's items were not swept");
    assert_eq!(
        removed, 2,
        "two items (gen-1 and issued-1) of the stale run's one test service"
    );
    assert!(live_kept, "a live run's item was swept");
    assert!(unlisted_kept, "a service no manifest names was swept");
    assert!(
        outside_kept,
        "a listed name outside the test prefix was swept"
    );
    assert!(old_manifest_gone, "the stale manifest was kept");
    assert!(live_manifest_kept, "a live run's manifest was removed");
}

#[test]
fn the_sweep_of_an_empty_or_missing_manifest_directory_removes_nothing() {
    let dir = manifest_dir("empty");
    assert_eq!(sweep_manifests(&dir, now_nanos(), STALE), 0);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(sweep_manifests(&dir, now_nanos(), STALE), 0);
}

#[test]
fn a_service_is_recorded_in_this_runs_manifest_before_it_is_used() {
    let s = Service::new("manifest");
    let listed = std::fs::read_to_string(run_manifest()).unwrap();
    assert!(listed.lines().any(|l| l == s.0), "{} not in {listed}", s.0);
}

#[test]
fn a_marker_added_after_another_threads_search_still_counts() {
    // the store lists its items with a search filtered by its service; another thread's
    // keychain-wide search must not hide a marker made afterwards, or a removed newest key
    // would free its number
    let s = Service::new("wide-search");
    let store = MacosKeychainStore::new(&s.0);
    for round in 1..=5u32 {
        std::thread::spawn(|| {
            wide_search();
        })
        .join()
        .unwrap();
        assert_eq!(store.rotate().unwrap(), round * 2 - 1);
        delete_generic_password(&s.0, &format!("gen-{}", round * 2 - 1)).unwrap();
        std::thread::spawn(|| {
            wide_search();
        })
        .join()
        .unwrap();
        // the number of the removed key is not issued again
        assert_eq!(store.rotate().unwrap(), round * 2);
    }
}
