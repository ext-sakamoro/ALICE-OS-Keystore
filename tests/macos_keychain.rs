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
//! its items at the end, also when it panics. A run that is killed cannot clean up, so the first
//! test of every run sweeps items under that prefix whose time stamp is older than `STALE` (and
//! never any other service name). The items are read and removed behind the store's back with
//! Security.framework directly, as another program would.
#![cfg(target_os = "macos")]

use alice_crypto::{KeyProvider, KeyProviderError};
use alice_os_keystore::desktop::MacosKeychainStore;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

const PREFIX: &str = "alice-os-keystore-test.";

/// Items of a test run this old were left by a run that was killed
const STALE: std::time::Duration = std::time::Duration::from_mins(30);

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// (service, account) of every generic password item whose service starts with `prefix`
fn items_under(prefix: &str) -> Vec<(String, String)> {
    let found = ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .load_attributes(true)
        .limit(Limit::All)
        .search();
    match found {
        Ok(items) => items
            .iter()
            .filter_map(|r| {
                let d = r.simplify_dict()?;
                let svce = d.get("svce")?;
                svce.starts_with(prefix)
                    .then(|| (svce.clone(), d.get("acct").cloned().unwrap_or_default()))
            })
            .collect(),
        Err(e) if e.code() == -25300 => Vec::new(), // errSecItemNotFound
        Err(e) => panic!("keychain search failed: {e}"),
    }
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

/// Remove the items of test runs older than `max_age` (see `select_stale`); returns how many.
/// It lists the keychain with a search that has no service, which in this process may not show
/// items added after another thread's search of the same kind: in use the stale items come from
/// earlier processes, and the test of this function runs it in a child process.
fn sweep_stale(now: u128, max_age: std::time::Duration) -> usize {
    let items = items_under(PREFIX);
    let names: Vec<String> = items.iter().map(|(s, _)| s.clone()).collect();
    let stale = select_stale(&names, now, max_age);
    items
        .iter()
        .filter(|(s, _)| stale.contains(s))
        .filter(|(s, a)| delete_generic_password(s, a).is_ok())
        .count()
}

static SWEEP: std::sync::Once = std::sync::Once::new();

/// A service name no other test or program uses; its items are deleted on drop
struct Service(String);

impl Service {
    fn new(test: &str) -> Self {
        SWEEP.call_once(|| {
            sweep_stale(now_nanos(), STALE);
        });
        Self(format!(
            "{PREFIX}{test}.{}.{}",
            std::process::id(),
            now_nanos()
        ))
    }

    /// The accounts the keychain holds under this service, sorted
    fn accounts(&self) -> Vec<String> {
        let found = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(&self.0)
            .load_attributes(true)
            .limit(Limit::All)
            .search();
        let mut accounts: Vec<String> = match found {
            Ok(items) => items
                .iter()
                .filter_map(|r| r.simplify_dict()?.get("acct").cloned())
                .collect(),
            Err(e) if e.code() == -25300 => Vec::new(), // errSecItemNotFound
            Err(e) => panic!("keychain search failed: {e}"),
        };
        accounts.sort();
        accounts
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

/// Run by `the_sweep_removes_items_of_a_killed_run_and_keeps_a_live_one` in a child process
#[test]
#[ignore = "run in a child process by the_sweep_removes_items_of_a_killed_run_and_keeps_a_live_one"]
fn sweep_child() {
    assert_eq!(
        std::env::var("ALICE_KEYSTORE_SWEEP_CHILD").as_deref(),
        Ok("1"),
        "run only through the parent test"
    );
    sweep_stale(now_nanos(), STALE);
}

#[test]
fn the_sweep_removes_items_of_a_killed_run_and_keeps_a_live_one() {
    // fixtures stamped from the real clock under this run's own test name; the sweep runs in a
    // new process, as the next run of the suite would
    let min = 60 * 1_000_000_000u128;
    let now = now_nanos();
    let run = format!("sweep{}x{now}", std::process::id());
    let old = format!("{PREFIX}{run}.1.{}", now - 31 * min);
    let live = format!("{PREFIX}{run}.1.{now}");
    let other = format!("x-{PREFIX}{run}.1.{}", now - 31 * min);
    for s in [&old, &live, &other] {
        set_generic_password(s, "gen-1", &[1; 32]).unwrap();
    }
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "sweep_child", "--test-threads=1"])
        .env("ALICE_KEYSTORE_SWEEP_CHILD", "1")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let gone = get_generic_password(&old, "gen-1").is_err();
    let kept = get_generic_password(&live, "gen-1").is_ok();
    let other_kept = get_generic_password(&other, "gen-1").is_ok();
    for s in [&old, &live, &other] {
        let _ = delete_generic_password(s, "gen-1");
    }
    assert!(out.status.success() && text.contains("1 passed"), "{text}");
    assert!(gone, "the stale item was not swept");
    assert!(kept, "a live item was swept");
    assert!(other_kept, "a service outside the test prefix was swept");
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
            let _ = items_under(PREFIX);
        })
        .join()
        .unwrap();
        assert_eq!(store.rotate().unwrap(), round * 2 - 1);
        delete_generic_password(&s.0, &format!("gen-{}", round * 2 - 1)).unwrap();
        std::thread::spawn(|| {
            let _ = items_under(PREFIX);
        })
        .join()
        .unwrap();
        // the number of the removed key is not issued again
        assert_eq!(store.rotate().unwrap(), round * 2);
    }
}
