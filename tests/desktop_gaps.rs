//! The desktop key stores are not implemented yet. They must fail loudly, never
//! hand out a key or report success.

use alice_os_keystore::desktop::{LinuxSecretServiceVault, MacosKeychainVault, WindowsDpapiVault};
use alice_os_keystore::KeyVault;

#[test]
#[should_panic(expected = "not implemented")]
fn macos_keychain_is_a_gap() {
    let _ = MacosKeychainVault.current();
}

#[test]
#[should_panic(expected = "not implemented")]
fn windows_dpapi_is_a_gap() {
    let _ = WindowsDpapiVault.by_id(1);
}

#[test]
#[should_panic(expected = "not implemented")]
fn linux_secret_service_is_a_gap() {
    let _ = LinuxSecretServiceVault.current();
}
