//! The Windows and Linux key stores are not implemented yet. They must fail loudly, never
//! hand out a key or report success.

use alice_crypto::KeyProvider;
use alice_os_keystore::desktop::{LinuxSecretServiceStore, WindowsDpapiStore};

#[test]
#[should_panic(expected = "not implemented")]
fn windows_dpapi_is_a_gap() {
    let _ = WindowsDpapiStore.by_generation(1);
}

#[test]
#[should_panic(expected = "not implemented")]
fn linux_secret_service_is_a_gap() {
    let _ = LinuxSecretServiceStore.current();
}
