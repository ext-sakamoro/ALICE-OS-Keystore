//! Oracle for the Windows DPAPI store, against the real DPAPI of the user running the tests.
//!
//! The model (fixed before the implementation, the same as the macOS Keychain store): one 32-byte
//! random key per generation, each sealed with DPAPI for the current user in its own file
//! `gen-<n>.dpapi` in the store's directory (by default `%LOCALAPPDATA%\<service>`). `current`
//! returns the highest generation, creating generation 1 when the directory holds none; `rotate`
//! adds `max + 1` and keeps the older files; `by_generation(g)` returns the key, `UnknownGeneration`
//! when no file `gen-<g>.dpapi` exists and no higher generation does either, and `Irrecoverable`
//! when the file is gone but a higher generation shows it once existed, when the file does not open
//! under this user, or when it does not hold a 32-byte key. A file is never rewritten.
//!
//! Each test uses its own directory under the system temporary directory and removes it.
#![cfg(windows)]

use std::path::{Path, PathBuf};

use alice_crypto::{KeyProvider, KeyProviderError};
use alice_os_keystore::desktop::WindowsDpapiStore;

/// A directory no other test uses; removed on drop
struct Dir(PathBuf);

impl Dir {
    fn new(test: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "alice-os-keystore-test.{test}.{}.{nanos}",
            std::process::id()
        )))
    }

    /// The file names in the directory, sorted (none when it does not exist)
    fn files(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.0) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn store(d: &Dir) -> WindowsDpapiStore {
    WindowsDpapiStore::in_dir(&d.0)
}

fn bytes(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

#[test]
fn the_first_current_creates_generation_1_as_one_sealed_file() {
    let d = Dir::new("first");
    let s = store(&d);
    let (g, k) = s.current().unwrap();
    assert_eq!(g, 1);
    assert_eq!(d.files(), ["gen-1.dpapi"]);
    assert_ne!(k.as_bytes(), &[0; 32]);
    // the file is sealed: the key bytes do not appear in it
    let sealed = bytes(&d.file("gen-1.dpapi"));
    assert!(sealed.len() > 32);
    assert!(!sealed.windows(32).any(|w| w == k.as_bytes()));
    // a second call, and a second store on the same directory, return the same key
    let (g2, k2) = s.current().unwrap();
    let (g3, k3) = store(&d).current().unwrap();
    assert_eq!((g2, g3), (1, 1));
    assert_eq!(k2.as_bytes(), k.as_bytes());
    assert_eq!(k3.as_bytes(), k.as_bytes());
    assert_eq!(d.files(), ["gen-1.dpapi"]);
}

#[test]
fn rotate_adds_the_next_generation_and_keeps_the_old_key() {
    let d = Dir::new("rotate");
    let s = store(&d);
    let (_, k1) = s.current().unwrap();
    let sealed1 = bytes(&d.file("gen-1.dpapi"));
    assert_eq!(s.rotate().unwrap(), 2);
    assert_eq!(s.rotate().unwrap(), 3);
    assert_eq!(d.files(), ["gen-1.dpapi", "gen-2.dpapi", "gen-3.dpapi"]);
    let (g, k3) = s.current().unwrap();
    assert_eq!(g, 3);
    assert_eq!(s.by_generation(1).unwrap().as_bytes(), k1.as_bytes());
    let k2 = s.by_generation(2).unwrap();
    assert_ne!(k1.as_bytes(), k2.as_bytes());
    assert_ne!(k2.as_bytes(), k3.as_bytes());
    // an existing generation is never rewritten
    assert_eq!(bytes(&d.file("gen-1.dpapi")), sealed1);
}

#[test]
fn rotate_on_an_empty_directory_creates_generation_1() {
    let d = Dir::new("rotate-empty");
    assert_eq!(store(&d).rotate().unwrap(), 1);
    assert_eq!(d.files(), ["gen-1.dpapi"]);
}

#[test]
fn unknown_and_zero_generations_are_unknown() {
    let d = Dir::new("unknown");
    let s = store(&d);
    assert_eq!(
        s.by_generation(1).err().expect("an error"),
        KeyProviderError::UnknownGeneration(1)
    );
    s.current().unwrap();
    assert_eq!(
        s.by_generation(0).err().expect("an error"),
        KeyProviderError::UnknownGeneration(0)
    );
    assert_eq!(
        s.by_generation(2).err().expect("an error"),
        KeyProviderError::UnknownGeneration(2)
    );
    assert_eq!(d.files(), ["gen-1.dpapi"]);
}

#[test]
fn a_removed_older_generation_is_irrecoverable() {
    let d = Dir::new("removed");
    let s = store(&d);
    s.current().unwrap();
    s.rotate().unwrap();
    std::fs::remove_file(d.file("gen-1.dpapi")).unwrap();
    assert!(matches!(
        s.by_generation(1),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert_eq!(s.current().unwrap().0, 2);
}

#[test]
fn a_file_that_does_not_open_is_irrecoverable_and_left_as_it_was() {
    let d = Dir::new("tampered");
    let s = store(&d);
    s.current().unwrap();
    let mut sealed = bytes(&d.file("gen-1.dpapi"));
    let last = sealed.len() - 1;
    sealed[last] ^= 0x01;
    std::fs::write(d.file("gen-1.dpapi"), &sealed).unwrap();
    assert!(matches!(
        s.by_generation(1),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert!(matches!(
        s.current(),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert_eq!(bytes(&d.file("gen-1.dpapi")), sealed);
}

#[test]
fn a_file_moved_to_another_store_name_does_not_open() {
    // the sealing is bound to the store: a file copied from another directory does not open
    let a = Dir::new("bind-a");
    let b = Dir::new("bind-b");
    store(&a).current().unwrap();
    std::fs::create_dir_all(&b.0).unwrap();
    std::fs::copy(a.file("gen-1.dpapi"), b.file("gen-1.dpapi")).unwrap();
    assert!(matches!(
        store(&b).by_generation(1),
        Err(KeyProviderError::Irrecoverable(_))
    ));
}

#[test]
fn files_that_are_not_canonical_generations_are_ignored() {
    let d = Dir::new("foreign");
    std::fs::create_dir_all(&d.0).unwrap();
    for name in [
        "gen-0.dpapi",
        "gen-01.dpapi",
        "gen-x.dpapi",
        "other",
        "gen-4294967296.dpapi",
        "gen-7.tmp",
    ] {
        std::fs::write(d.file(name), [1; 64]).unwrap();
    }
    let s = store(&d);
    assert_eq!(s.current().unwrap().0, 1);
    assert_eq!(s.rotate().unwrap(), 2);
}

#[test]
fn concurrent_first_use_agrees_on_one_key() {
    let d = Dir::new("race");
    let keys: Vec<(u32, [u8; 32])> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    let (g, k) = store(&d).current().unwrap();
                    (g, *k.as_bytes())
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(keys.iter().all(|k| *k == keys[0]), "{keys:?}");
    assert_eq!(d.files(), ["gen-1.dpapi"]);
}

#[test]
fn concurrent_rotations_each_get_their_own_generation() {
    let d = Dir::new("rotate-race");
    store(&d).current().unwrap();
    let mut got: Vec<u32> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..6)
            .map(|_| scope.spawn(|| store(&d).rotate().unwrap()))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    got.sort_unstable();
    assert_eq!(got, [2, 3, 4, 5, 6, 7]);
    assert_eq!(d.files().len(), 7);
}

#[test]
fn the_default_directory_is_under_local_app_data() {
    let s = WindowsDpapiStore::new("alice-os-keystore-test.default-dir").unwrap();
    let local = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
    assert_eq!(s.dir(), local.join("alice-os-keystore-test.default-dir"));
    // nothing is created until the first call
    assert!(!s.dir().exists());
}

#[test]
fn a_service_name_that_is_not_one_plain_directory_name_is_refused() {
    for bad in ["", ".", "..", "a\\b", "a/b", "C:x", "a:b", "nul\0"] {
        assert!(WindowsDpapiStore::new(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn the_store_is_a_shareable_key_provider_object() {
    let d = Dir::new("object");
    let s: std::sync::Arc<dyn KeyProvider> = std::sync::Arc::new(store(&d));
    let other = s.clone();
    let g = std::thread::spawn(move || other.current().unwrap().0)
        .join()
        .unwrap();
    assert_eq!(g, 1);
}
