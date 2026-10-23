//! Without a reachable Secret Service (a headless machine: no D-Bus session bus), the Linux store
//! reports `Unavailable` and creates nothing, so a caller can fall back to a passphrase.
//!
//! The check runs in a child process of this test binary whose session bus points at a path
//! that does not exist (the environment is set for the child only, not changed in this process).
#![cfg(target_os = "linux")]

use alice_crypto::{KeyProvider, KeyProviderError};
use alice_os_keystore::desktop::LinuxSecretServiceStore;

const NO_BUS: &str = "unix:path=/nonexistent/alice-os-keystore-test-bus";

#[test]
fn without_a_session_bus_every_call_is_unavailable() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "headless_child", "--test-threads=1"])
        .env("DBUS_SESSION_BUS_ADDRESS", NO_BUS)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // the child really ran (an empty filter would also succeed)
    assert!(text.contains("1 passed"), "{text}");
}

#[test]
#[ignore = "run by without_a_session_bus_every_call_is_unavailable in a child process"]
fn headless_child() {
    assert_eq!(
        std::env::var("DBUS_SESSION_BUS_ADDRESS").as_deref(),
        Ok(NO_BUS),
        "run only through the parent test"
    );
    let store = LinuxSecretServiceStore::new("alice-os-keystore-test.headless");
    assert!(matches!(
        store.current(),
        Err(KeyProviderError::Unavailable(_))
    ));
    assert!(matches!(
        store.by_generation(1),
        Err(KeyProviderError::Unavailable(_))
    ));
    assert!(matches!(
        store.rotate(),
        Err(KeyProviderError::Unavailable(_))
    ));
}
