//! Oracle for the macOS Keychain store, against the real login keychain.
//!
//! The model (fixed before the implementation): one 32-byte random key per generation, each a
//! generic password item with service = the store's service name and account = `gen-<n>`.
//! `current` returns the highest generation, creating generation 1 when the service holds none;
//! `rotate` adds `max + 1` and keeps the older items; `by_generation(g)` returns the item's bytes,
//! `UnknownGeneration` when no item `gen-<g>` exists and no higher generation does either, and
//! `Irrecoverable` when the item is gone but a higher generation shows it once existed (or when the
//! item does not hold 32 bytes).
//!
//! Each test uses its own service name and deletes its items at the end. The items are read and
//! removed behind the store's back with Security.framework directly, as another program would.
#![cfg(target_os = "macos")]

use alice_crypto::{KeyProvider, KeyProviderError};
use alice_os_keystore::desktop::MacosKeychainStore;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

/// A service name no other test or program uses; its items are deleted on drop
struct Service(String);

impl Service {
    fn new(test: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(format!(
            "alice-os-keystore-test.{test}.{}.{nanos}",
            std::process::id()
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
    assert_eq!(s.accounts(), ["gen-1"]);
    // the item holds exactly the key, and the key is not all zero
    assert_eq!(get_generic_password(&s.0, "gen-1").unwrap(), k.as_bytes());
    assert_ne!(k.as_bytes(), &[0; 32]);
    // a second call, and a second store on the same service, return the same key
    let (g2, k2) = store.current().unwrap();
    let (g3, k3) = MacosKeychainStore::new(&s.0).current().unwrap();
    assert_eq!((g2, g3), (1, 1));
    assert_eq!(k2.as_bytes(), k.as_bytes());
    assert_eq!(k3.as_bytes(), k.as_bytes());
    assert_eq!(s.accounts(), ["gen-1"]);
}

#[test]
fn rotate_adds_the_next_generation_and_keeps_the_old_key() {
    let s = Service::new("rotate");
    let store = MacosKeychainStore::new(&s.0);
    let (_, k1) = store.current().unwrap();
    assert_eq!(store.rotate().unwrap(), 2);
    assert_eq!(store.rotate().unwrap(), 3);
    assert_eq!(s.accounts(), ["gen-1", "gen-2", "gen-3"]);
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
    assert_eq!(s.accounts(), ["gen-1"]);
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
    assert_eq!(s.accounts(), ["gen-1"]);
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
    assert_eq!(s.accounts(), ["gen-1"]);
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
    assert_eq!(s.accounts().len(), 7);
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
