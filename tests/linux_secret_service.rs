//! Oracle for the Linux Secret Service store, against a real Secret Service (gnome-keyring in CI,
//! started unlocked under `dbus-run-session`).
//!
//! The model is the one of the macOS and Windows stores (one 32-byte random key per generation,
//! each one item; `current` creates generation 1 when there is none; `rotate` adds the next one;
//! a removed older generation and an item that is not 32 bytes are `Irrecoverable`), with one
//! difference the Secret Service forces: it has no "create unless it exists", so the store holds a
//! lock for the service (a file under `$XDG_RUNTIME_DIR`, exclusive across threads and processes)
//! while `current` / `rotate` read, create and re-read, and a creator waits until its item is
//! listed before releasing it. The laws: every caller that returns a generation returns the key
//! later readers get, and concurrent successful rotations return distinct generations (checked
//! with threads and with separate processes, over many rounds). Duplicates made behind the store's
//! back (an older version without the lock, another program) are read the same way by everyone:
//! the earliest `created` (set by the service), ties broken by the object path (assigned by the
//! service) compared as a string; they are left in place and counted (`duplicate_count`).
//! For every generation issued a marker item (attribute `keystore-issued`)
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
fn racing_creators_make_one_item_and_agree_on_its_key() {
    // the store's lock serializes creators, so racing creators make one item for generation 1
    // and every one returns its key (before the lock, racing creators left duplicates and one
    // could return a key readers do not get)
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
        assert_eq!(s.items().len(), 1, "round {round}: {:?}", s.items());
        assert_eq!(
            LinuxSecretServiceStore::new(&s.0).duplicate_count().unwrap(),
            0
        );
    }
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

// The laws the two racing tests above sample once per run, checked over many rounds (a run of the
// pair against a real gnome-keyring disagreed about 3 times in 37):
//   current(): every caller that returns generation g returns the key every later reader of g gets
//     (`by_generation(g)`), so data sealed by any caller opens again;
//   rotate(): each successful call adds a generation of its own, so concurrent successful calls
//     return distinct generations.
// A failing round prints every key item (generation, created, object path) of its service.

const STRESS_ROUNDS: usize = 60;

#[test]
fn racing_creators_agree_on_one_key_in_every_round() {
    for round in 0..STRESS_ROUNDS {
        let s = Service::new(&format!("stress-create{round}"));
        let barrier = std::sync::Barrier::new(8);
        let got: Vec<(u32, [u8; 32])> = std::thread::scope(|scope| {
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
        let read = LinuxSecretServiceStore::new(&s.0).by_generation(1).unwrap();
        let disagree = got
            .iter()
            .filter(|(g, k)| *g != 1 || k.as_slice() != read.as_bytes().as_slice())
            .count();
        assert_eq!(
            disagree,
            0,
            "round {round}: {disagree} of 8 callers hold a key later readers do not get; items {:?}",
            s.items()
        );
    }
}

#[test]
fn racing_rotations_issue_each_generation_once_in_every_round() {
    for round in 0..STRESS_ROUNDS {
        let s = Service::new(&format!("stress-rotate{round}"));
        LinuxSecretServiceStore::new(&s.0).current().unwrap();
        let barrier = std::sync::Barrier::new(6);
        let mut got: Vec<u32> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..6)
                .map(|_| {
                    scope.spawn(|| {
                        let store = LinuxSecretServiceStore::new(&s.0);
                        barrier.wait();
                        store.rotate().unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        got.sort_unstable();
        assert_eq!(
            got,
            [2, 3, 4, 5, 6, 7],
            "round {round}: concurrent rotations shared a generation; items {:?}",
            s.items()
        );
    }
}

// The same laws across processes, not only threads: the store's lock must exclude another process
// as it excludes another thread. The test binary is re-invoked as `helper_process` (it does
// nothing unless ALICE_KEYSTORE_TEST_HELPER is set); the children start together when a file appears.

const PROCESS_ROUNDS: usize = 20;

#[test]
fn helper_process() {
    let Ok(op) = std::env::var("ALICE_KEYSTORE_TEST_HELPER") else {
        return;
    };
    let service = std::env::var("ALICE_KEYSTORE_TEST_SERVICE").unwrap();
    let go = std::path::PathBuf::from(std::env::var("ALICE_KEYSTORE_TEST_GO").unwrap());
    let store = LinuxSecretServiceStore::new(&service);
    while !go.exists() {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    match op.as_str() {
        "current" => {
            let (g, k) = store.current().unwrap();
            let hex: String = k.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            println!("RESULT {g} {hex}");
        }
        "rotate" => println!("RESULT {}", store.rotate().unwrap()),
        other => panic!("unknown helper operation {other}"),
    }
}

/// Run `n` children doing `op` on `service` at once; each child's RESULT line (all must report one)
fn in_processes(op: &str, service: &str, n: usize) -> Vec<String> {
    let dir = tempfile_dir();
    let go = dir.join("go");
    let children: Vec<_> = (0..n)
        .map(|_| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "helper_process", "--nocapture", "--test-threads=1"])
                .env("ALICE_KEYSTORE_TEST_HELPER", op)
                .env("ALICE_KEYSTORE_TEST_SERVICE", service)
                .env("ALICE_KEYSTORE_TEST_GO", &go)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    std::fs::write(&go, b"").unwrap();
    let results: Vec<String> = children
        .into_iter()
        .map(|c| {
            let out = c.wait_with_output().unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success(),
                "a child failed: {stdout} {}",
                String::from_utf8_lossy(&out.stderr)
            );
            stdout
                .lines()
                // libtest prints `test helper_process ... ` on the same line before the output
                .find_map(|l| l.split_once("RESULT ").map(|(_, r)| r.trim().to_owned()))
                .unwrap_or_else(|| panic!("a child printed no result: {stdout}"))
        })
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    // nothing compared is a failure
    assert_eq!(results.len(), n);
    results
}

fn tempfile_dir() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("alice-os-keystore-go.{}.{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn creators_in_separate_processes_agree_on_one_key() {
    for round in 0..PROCESS_ROUNDS {
        let s = Service::new(&format!("proc-create{round}"));
        let got = in_processes("current", &s.0, 8);
        let read = LinuxSecretServiceStore::new(&s.0).by_generation(1).unwrap();
        let want: String = read.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let disagree = got.iter().filter(|r| **r != format!("1 {want}")).count();
        assert_eq!(
            disagree,
            0,
            "round {round}: {disagree} of 8 processes hold a key later readers do not get; items {:?}",
            s.items()
        );
    }
}

#[test]
fn rotations_in_separate_processes_issue_each_generation_once() {
    for round in 0..PROCESS_ROUNDS {
        let s = Service::new(&format!("proc-rotate{round}"));
        LinuxSecretServiceStore::new(&s.0).current().unwrap();
        let mut got: Vec<u32> = in_processes("rotate", &s.0, 6)
            .iter()
            .map(|r| r.parse().unwrap())
            .collect();
        got.sort_unstable();
        assert_eq!(
            got,
            [2, 3, 4, 5, 6, 7],
            "round {round}: rotations in separate processes shared a generation; items {:?}",
            s.items()
        );
    }
}

#[test]
fn a_held_lock_makes_current_and_rotate_unavailable_at_the_deadline() {
    let s = Service::new("held-lock");
    let deadline = std::time::Duration::from_millis(300);
    let store = LinuxSecretServiceStore::new(&s.0).lock_deadline(deadline);
    store.current().unwrap();
    let path = store.lock_path().expect("XDG_RUNTIME_DIR is set (scripts/with_keyring.sh)");
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    holder.lock().unwrap();
    for (name, call) in [
        ("current", Box::new(|| store.current().map(|_| ())) as Box<dyn Fn() -> _>),
        ("rotate", Box::new(|| store.rotate().map(|_| ()))),
    ] {
        let start = std::time::Instant::now();
        match call() {
            Err(KeyProviderError::Unavailable(m)) => {
                assert!(m.contains("lock past the deadline"), "{name}: {m}")
            }
            other => panic!("{name} under a held lock: {other:?}"),
        }
        let waited = start.elapsed();
        assert!(
            waited >= deadline && waited < std::time::Duration::from_secs(10),
            "{name} waited {waited:?}"
        );
    }
    drop(holder);
    assert_eq!(store.rotate().unwrap(), 2);
}

#[test]
fn the_lock_lives_in_a_private_directory_under_the_runtime_dir() {
    use std::os::unix::fs::PermissionsExt;
    let s = Service::new("lock-file");
    let store = LinuxSecretServiceStore::new(&s.0);
    store.current().unwrap();
    let path = store.lock_path().expect("XDG_RUNTIME_DIR is set (scripts/with_keyring.sh)");
    let runtime = std::path::PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").unwrap());
    assert_eq!(path.parent().unwrap().parent().unwrap(), runtime);
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    assert_eq!(mode(&path), 0o600);
    assert!(!path.file_name().unwrap().to_str().unwrap().contains("lock-file"));
}
