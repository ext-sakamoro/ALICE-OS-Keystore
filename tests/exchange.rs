//! Swapping two directories in one step
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
