#![no_main]
//! Errors from a foreign key store keep their kind and payload through the adapter.

use alice_os_keystore::ffi::{ForeignKeyVault, ForeignVaultAdapter, ForeignVaultError, GenerationKey};
use alice_os_keystore::{KeyVault, VaultError};
use libfuzzer_sys::fuzz_target;

struct Fails {
    unknown: bool,
    generation: u32,
    reason: String,
}

impl Fails {
    fn error(&self) -> ForeignVaultError {
        if self.unknown {
            ForeignVaultError::UnknownKey { generation: self.generation }
        } else {
            ForeignVaultError::Unavailable { reason: self.reason.clone() }
        }
    }
}

impl ForeignKeyVault for Fails {
    fn current(&self) -> Result<GenerationKey, ForeignVaultError> {
        Err(self.error())
    }
    fn by_id(&self, _generation: u32) -> Result<Vec<u8>, ForeignVaultError> {
        Err(self.error())
    }
}

fuzz_target!(|input: (bool, u32, String)| {
    let (unknown, generation, reason) = input;
    let want = if unknown {
        VaultError::UnknownKey(generation)
    } else {
        VaultError::Unavailable(reason.clone())
    };
    let adapter = ForeignVaultAdapter::new(Box::new(Fails { unknown, generation, reason }));
    assert_eq!(adapter.current().unwrap_err(), want);
    assert_eq!(adapter.by_id(generation).unwrap_err(), want);
});
