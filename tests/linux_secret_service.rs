//! Oracle for the Linux Secret Service store, against a real Secret Service (gnome-keyring in CI,
//! started unlocked under `dbus-run-session`).
//!
//! The model is the one of the macOS and Windows stores (one 32-byte random key per generation,
//! each one item; `current` creates generation 1 when there is none; `rotate` adds the next one;
//! a removed older generation and an item that is not 32 bytes are `Irrecoverable`), with one
//! difference the Secret Service forces: it has no "create unless it exists", so two processes
//! creating the same generation at once leave two items. Every reader then picks the same one:
//! the earliest `created` (set by the service), ties broken by the object path (assigned by the
//! service). A creator re-reads after creating and returns the chosen item's key, never its own
//! unless its item was chosen. The other items are left in place and counted
//! (`duplicate_count`). For every generation issued a marker item (attribute `keystore-issued`)
//! follows the key item, so no number is issued twice even when its key item is removed.
//!
//! Each test uses its own service name and deletes its items at the end. Items are made and
//! removed behind the store's back with the `secret-service` crate, as another program would.
#![cfg(target_os = "linux")]

use std::collections::HashMap;

use alice_crypto::{KeyProvider, KeyProviderError};
use alice_os_keystore::desktop::LinuxSecretServiceStore;
use secret_service::blocking::SecretService;
use secret_service::EncryptionType;

/// A service name no other test uses; its items are deleted on drop
struct Service(String);

fn attrs<'a>(service: &'a str, generation: &'a str) -> HashMap<&'a str, &'a str> {
    HashMap::from([
        ("keystore-service", service),
        ("keystore-generation", generation),
    ])
}

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

    /// (generation attribute, created, object path) of every key item of this service
    fn items(&self) -> Vec<(String, u64, String)> {
        self.with_attr("keystore-generation")
    }

    /// The generations marked as issued (marker items), sorted
    fn markers(&self) -> Vec<String> {
        let mut m: Vec<String> = self
            .with_attr("keystore-issued")
            .into_iter()
            .map(|(g, _, _)| g)
            .collect();
        m.dedup();
        m
    }

    fn with_attr(&self, attr: &str) -> Vec<(String, u64, String)> {
        let ss = SecretService::connect(EncryptionType::Dh).unwrap();
        let c = ss.get_default_collection().unwrap();
        let mut out: Vec<_> = c
            .search_items(HashMap::from([("keystore-service", self.0.as_str())]))
            .unwrap()
            .iter()
            .filter_map(|i| {
                let value = i.get_attributes().unwrap().get(attr)?.clone();
                Some((value, i.get_created().unwrap(), i.item_path.to_string()))
            })
            .collect();
        out.sort();
        out
    }

    fn remove_marker(&self, generation: &str) {
        let ss = SecretService::connect(EncryptionType::Dh).unwrap();
        let c = ss.get_default_collection().unwrap();
        for i in c
            .search_items(HashMap::from([
                ("keystore-service", self.0.as_str()),
                ("keystore-issued", generation),
            ]))
            .unwrap()
        {
            i.delete().unwrap();
        }
    }

    fn generations(&self) -> Vec<String> {
        let mut g: Vec<String> = self.items().into_iter().map(|(g, _, _)| g).collect();
        g.dedup();
        g
    }

    /// Make an item behind the store's back
    fn put(&self, generation: &str, secret: &[u8]) {
        let ss = SecretService::connect(EncryptionType::Dh).unwrap();
        let c = ss.get_default_collection().unwrap();
        c.create_item(
            "test",
            attrs(&self.0, generation),
            secret,
            false,
            "application/octet-stream",
        )
        .unwrap();
    }

    fn remove(&self, generation: &str) {
        let ss = SecretService::connect(EncryptionType::Dh).unwrap();
        let c = ss.get_default_collection().unwrap();
        for i in c.search_items(attrs(&self.0, generation)).unwrap() {
            i.delete().unwrap();
        }
    }

    /// The secret of the item every reader must choose for `generation`
    fn chosen(&self, generation: &str) -> Vec<u8> {
        let ss = SecretService::connect(EncryptionType::Dh).unwrap();
        let c = ss.get_default_collection().unwrap();
        let items = c.search_items(attrs(&self.0, generation)).unwrap();
        let first = items
            .iter()
            .min_by_key(|i| (i.get_created().unwrap(), i.item_path.to_string()))
            .unwrap();
        first.get_secret().unwrap()
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Ok(ss) = SecretService::connect(EncryptionType::Dh) {
            if let Ok(c) = ss.get_default_collection() {
                if let Ok(items) =
                    c.search_items(HashMap::from([("keystore-service", self.0.as_str())]))
                {
                    for i in items {
                        let _ = i.delete();
                    }
                }
            }
        }
    }
}

#[test]
fn the_first_current_creates_generation_1_as_one_item() {
    let s = Service::new("first");
    let store = LinuxSecretServiceStore::new(&s.0);
    let (g, k) = store.current().unwrap();
    assert_eq!(g, 1);
    assert_eq!(s.generations(), ["1"]);
    assert_eq!(s.markers(), ["1"]);
    assert_eq!(s.chosen("1"), k.as_bytes());
    assert_ne!(k.as_bytes(), &[0; 32]);
    let (g2, k2) = LinuxSecretServiceStore::new(&s.0).current().unwrap();
    assert_eq!(g2, 1);
    assert_eq!(k2.as_bytes(), k.as_bytes());
    assert_eq!(s.items().len(), 1);
}

#[test]
fn rotate_adds_the_next_generation_and_keeps_the_old_key() {
    let s = Service::new("rotate");
    let store = LinuxSecretServiceStore::new(&s.0);
    let (_, k1) = store.current().unwrap();
    assert_eq!(store.rotate().unwrap(), 2);
    assert_eq!(store.rotate().unwrap(), 3);
    assert_eq!(s.generations(), ["1", "2", "3"]);
    let (g, k3) = store.current().unwrap();
    assert_eq!(g, 3);
    assert_eq!(store.by_generation(1).unwrap().as_bytes(), k1.as_bytes());
    assert_ne!(store.by_generation(2).unwrap().as_bytes(), k3.as_bytes());
}

#[test]
fn unknown_and_zero_generations_are_unknown() {
    let s = Service::new("unknown");
    let store = LinuxSecretServiceStore::new(&s.0);
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
    assert_eq!(s.items().len(), 1);
}

#[test]
fn a_removed_older_generation_is_irrecoverable() {
    let s = Service::new("removed");
    let store = LinuxSecretServiceStore::new(&s.0);
    store.current().unwrap();
    store.rotate().unwrap();
    s.remove("1");
    assert!(matches!(
        store.by_generation(1),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert_eq!(store.current().unwrap().0, 2);
}

#[test]
fn an_item_that_is_not_32_bytes_is_irrecoverable() {
    let s = Service::new("short");
    s.put("1", &[7; 16]);
    let store = LinuxSecretServiceStore::new(&s.0);
    assert!(matches!(
        store.by_generation(1),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert!(matches!(
        store.current(),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert_eq!(s.items().len(), 1);
}

#[test]
fn generation_attributes_that_are_not_canonical_are_ignored() {
    let s = Service::new("foreign");
    for g in ["0", "01", "x", "", "4294967296"] {
        s.put(g, &[1; 32]);
    }
    let store = LinuxSecretServiceStore::new(&s.0);
    assert_eq!(store.current().unwrap().0, 1);
    assert_eq!(store.rotate().unwrap(), 2);
}

#[test]
fn duplicates_resolve_to_the_earliest_created_then_the_lowest_path_and_are_counted() {
    let s = Service::new("duplicates");
    s.put("1", &[1; 32]);
    s.put("1", &[2; 32]);
    s.put("1", &[3; 32]);
    let store = LinuxSecretServiceStore::new(&s.0);
    let want = s.chosen("1");
    let (g, k) = store.current().unwrap();
    assert_eq!(g, 1);
    assert_eq!(k.as_bytes().as_slice(), want.as_slice());
    assert_eq!(
        store.by_generation(1).unwrap().as_bytes().as_slice(),
        want.as_slice()
    );
    assert_eq!(store.duplicate_count().unwrap(), 2);
    // the losing items are left in place
    assert_eq!(s.items().len(), 3);
}

#[test]
fn creators_that_lose_a_race_return_the_winners_key() {
    // Secret Service cannot refuse a second item, so racing creators make duplicates; each must
    // return the chosen item's key. Rounds repeat until a race actually produced a duplicate, so
    // the losing path is known to have run (a run where no round races fails).
    for round in 0..40 {
        let s = Service::new(&format!("race{round}"));
        let barrier = std::sync::Barrier::new(8);
        let keys: Vec<(u32, [u8; 32])> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        let store = LinuxSecretServiceStore::new(&s.0);
                        barrier.wait();
                        let (g, k) = store.current().unwrap();
                        (g, *k.as_bytes())
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let want = s.chosen("1");
        assert!(
            keys.iter()
                .all(|(g, k)| *g == 1 && k.as_slice() == want.as_slice()),
            "round {round}: {keys:?}"
        );
        if s.items().len() > 1 {
            assert_eq!(
                LinuxSecretServiceStore::new(&s.0)
                    .duplicate_count()
                    .unwrap(),
                s.items().len() - 1
            );
            return;
        }
    }
    panic!("no round produced a duplicate: the losing path was not exercised");
}

#[test]
fn concurrent_rotations_each_get_their_own_generation() {
    let s = Service::new("rotate-race");
    LinuxSecretServiceStore::new(&s.0).current().unwrap();
    let mut got: Vec<u32> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..6)
            .map(|_| scope.spawn(|| LinuxSecretServiceStore::new(&s.0).rotate().unwrap()))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    got.sort_unstable();
    assert_eq!(got, [2, 3, 4, 5, 6, 7]);
    assert_eq!(s.generations().len(), 7);
}

#[test]
fn the_store_is_a_shareable_key_provider_object() {
    let s = Service::new("object");
    let store: std::sync::Arc<dyn KeyProvider> =
        std::sync::Arc::new(LinuxSecretServiceStore::new(&s.0));
    let other = store.clone();
    assert_eq!(
        std::thread::spawn(move || other.current().unwrap().0)
            .join()
            .unwrap(),
        1
    );
}

#[test]
fn a_removed_newest_generation_is_never_issued_again() {
    // probe: rotate 1, rotate 2, remove generation 2's key item behind the store's back
    let s = Service::new("removed-top");
    let store = LinuxSecretServiceStore::new(&s.0);
    assert_eq!(store.rotate().unwrap(), 1);
    let k1 = store.by_generation(1).unwrap();
    assert_eq!(store.rotate().unwrap(), 2);
    s.remove("2");
    assert!(matches!(
        store.by_generation(2),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert!(matches!(
        store.current(),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert_eq!(store.rotate().unwrap(), 3);
    assert_eq!(store.current().unwrap().0, 3);
    assert_eq!(store.by_generation(1).unwrap().as_bytes(), k1.as_bytes());
}

#[test]
fn a_key_item_without_its_marker_gets_the_marker_when_read() {
    let s = Service::new("heal");
    s.put("1", &[5; 32]);
    let store = LinuxSecretServiceStore::new(&s.0);
    assert_eq!(store.current().unwrap().0, 1);
    assert_eq!(s.markers(), ["1"]);
    s.remove("1");
    assert!(matches!(
        store.current(),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert_eq!(store.rotate().unwrap(), 2);
}

#[test]
fn removing_both_the_newest_key_and_its_marker_frees_the_number() {
    // documented limit: the record lives in the same keyring as the keys
    let s = Service::new("removed-both");
    let store = LinuxSecretServiceStore::new(&s.0);
    store.rotate().unwrap();
    store.rotate().unwrap();
    s.remove("2");
    s.remove_marker("2");
    assert_eq!(store.current().unwrap().0, 1);
    assert_eq!(store.rotate().unwrap(), 2);
}
