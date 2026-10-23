//! The Linux key store is not implemented yet. It must fail loudly, never hand out a key
//! or report success.

use alice_crypto::KeyProvider;
use alice_os_keystore::desktop::LinuxSecretServiceStore;

#[test]
#[should_panic(expected = "not implemented")]
fn linux_secret_service_is_a_gap() {
    let _ = LinuxSecretServiceStore.current();
}
