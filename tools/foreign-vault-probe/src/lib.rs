//! Reports what the adapter makes of a key store implemented on the other side of the FFI

use alice_os_keystore::ffi::{ForeignKeyVault, ForeignVaultAdapter};
use alice_os_keystore::KeyProvider;

uniffi::setup_scaffolding!();

/// One line: the result of `current` and of `by_generation(1)`
#[uniffi::export]
pub fn probe(vault: Box<dyn ForeignKeyVault>) -> String {
    let adapter = ForeignVaultAdapter::new(vault);
    let current = match adapter.current() {
        Ok((generation, _)) => format!("generation {generation}"),
        Err(e) => format!("{e:?}"),
    };
    let by_generation = match adapter.by_generation(1) {
        Ok(_) => "key".to_string(),
        Err(e) => format!("{e:?}"),
    };
    format!("{current} | {by_generation}")
}
