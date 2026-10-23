//! Swapping two paths in one step
//!
//! On Linux and Apple platforms the two paths change places atomically: an
//! observer sees either both old or both new, never one missing. Elsewhere the
//! call reports `Unsupported` and changes nothing, so the caller can choose its
//! own fallback.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use alice_os_keystore::fs::{exchange, ExchangeError};

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("exchange-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn put(dir: &Path, file: &str, text: &str) {
    std::fs::write(dir.join(file), text).unwrap();
}

fn read(dir: &Path, file: &str) -> String {
    std::fs::read_to_string(dir.join(file)).unwrap()
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
#[test]
fn two_directories_change_places() {
    let root = dir("swap");
    let a = root.join("a");
    let b = root.join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    put(&a, "only-in-a", "from a");
    put(&b, "only-in-b", "from b");
    exchange(&a, &b).unwrap();
    assert_eq!(read(&a, "only-in-b"), "from b");
    assert_eq!(read(&b, "only-in-a"), "from a");
    assert!(!a.join("only-in-a").exists());
    assert!(!b.join("only-in-b").exists());
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
#[test]
fn a_missing_path_is_an_error_and_nothing_moves() {
    let root = dir("missing");
    let a = root.join("a");
    std::fs::create_dir(&a).unwrap();
    put(&a, "f", "kept");
    let r = exchange(&a, root.join("absent"));
    assert!(matches!(r, Err(ExchangeError::Io(_))), "{r:?}");
    assert_eq!(read(&a, "f"), "kept");
    assert!(!root.join("absent").exists());
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
#[test]
fn the_same_path_twice_succeeds_and_changes_nothing() {
    let root = dir("same");
    let a = root.join("a");
    std::fs::create_dir(&a).unwrap();
    put(&a, "f", "kept");
    exchange(&a, &a).unwrap();
    assert_eq!(read(&a, "f"), "kept");
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
}

/// Any two entries swap, not only directories: a directory and a file change places
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
#[test]
fn a_directory_and_a_file_change_places() {
    let root = dir("mixed");
    let d = root.join("d");
    let f = root.join("f");
    std::fs::create_dir(&d).unwrap();
    put(&d, "inner", "in the directory");
    std::fs::write(&f, "a file").unwrap();
    exchange(&d, &f).unwrap();
    assert_eq!(std::fs::read_to_string(&d).unwrap(), "a file");
    assert_eq!(read(&f, "inner"), "in the directory");
}

/// A symbolic link is swapped itself, not the entry it points to
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
#[test]
fn a_symbolic_link_is_swapped_not_followed() {
    let root = dir("link");
    let target = root.join("target");
    let link = root.join("link");
    let other = root.join("other");
    std::fs::create_dir(&target).unwrap();
    put(&target, "t", "target");
    std::fs::create_dir(&other).unwrap();
    put(&other, "o", "other");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    exchange(&link, &other).unwrap();
    // `other` is now the link, `link` the directory that was `other`; the target is untouched
    assert!(std::fs::symlink_metadata(&other)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read_link(&other).unwrap(), target);
    assert_eq!(read(&link, "o"), "other");
    assert!(std::fs::symlink_metadata(&target).unwrap().is_dir());
    assert_eq!(read(&target, "t"), "target");
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
#[test]
fn elsewhere_the_swap_is_unsupported_and_nothing_moves() {
    let root = dir("unsupported");
    let a = root.join("a");
    let b = root.join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    put(&a, "f", "a");
    put(&b, "f", "b");
    let r = exchange(&a, &b);
    assert!(matches!(r, Err(ExchangeError::Unsupported)), "{r:?}");
    assert_eq!(read(&a, "f"), "a");
    assert_eq!(read(&b, "f"), "b");
}

/// Two paths on different file systems are refused (`EXDEV`) and nothing
/// moves. Linux only: the temporary directory and `/dev/shm` (a tmpfs) are two
/// file systems on the CI runner; if they are not, the test fails instead of
/// passing without having compared anything.
#[cfg(target_os = "linux")]
#[test]
fn paths_on_different_file_systems_are_refused_and_nothing_moves() {
    use std::os::unix::fs::MetadataExt;
    let here = dir("exdev");
    let shm =
        std::path::Path::new("/dev/shm").join(format!("exchange-{}-exdev", std::process::id()));
    let _ = std::fs::remove_dir_all(&shm);
    std::fs::create_dir_all(&shm).unwrap();
    assert_ne!(
        std::fs::metadata(&here).unwrap().dev(),
        std::fs::metadata(&shm).unwrap().dev(),
        "the temporary directory and /dev/shm are one file system: nothing would be compared"
    );
    let a = here.join("a");
    let b = shm.join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    put(&a, "f", "in a");
    put(&b, "f", "in b");
    let r = exchange(&a, &b);
    match r {
        Err(ExchangeError::Io(e)) => assert_eq!(e.raw_os_error(), Some(18), "{e:?}"), // EXDEV
        other => panic!("expected EXDEV, got {other:?}"),
    }
    assert_eq!(read(&a, "f"), "in a");
    assert_eq!(read(&b, "f"), "in b");
    let _ = std::fs::remove_dir_all(&shm);
}
