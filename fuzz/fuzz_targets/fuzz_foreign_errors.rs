#![no_main]
//! Errors from a foreign key store keep their kind through the adapter, and the
//! foreign reason text never reaches the error.

use alice_os_keystore::ffi::{
    ForeignKeyVault, ForeignVaultAdapter, ForeignVaultError, GenerationKey,
};
use alice_os_keystore::{KeyProvider, KeyProviderError};
use libfuzzer_sys::fuzz_target;

struct Fails {
    kind: u8,
    generation: u32,
    reason: String,
}

impl Fails {
    fn error(&self) -> ForeignVaultError {
        match self.kind % 3 {
            0 => ForeignVaultError::UnknownKey {
                generation: self.generation,
            },
            1 => ForeignVaultError::Unavailable {
                reason: self.reason.clone(),
            },
            _ => ForeignVaultError::Irrecoverable {
                reason: self.reason.clone(),
            },
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

fuzz_target!(|input: (u8, u32, u32, String)| {
    let (kind, generation, asked, reason) = input;
    let adapter = ForeignVaultAdapter::new(Box::new(Fails {
        kind,
        generation,
        reason: reason.clone(),
    }));
    let current = adapter
        .current()
        .err()
        .expect("the foreign store always fails");
    let by_gen = adapter
        .by_generation(asked)
        .err()
        .expect("the foreign store always fails");
    match kind % 3 {
        0 => {
            assert!(matches!(current, KeyProviderError::Unavailable(_)));
            assert_eq!(by_gen, KeyProviderError::UnknownGeneration(asked));
        }
        1 => {
            assert!(matches!(current, KeyProviderError::Unavailable(_)));
            let want = if asked == 0 {
                KeyProviderError::UnknownGeneration(0)
            } else {
                current
            };
            assert_eq!(by_gen, want);
        }
        _ => {
            assert!(matches!(current, KeyProviderError::Irrecoverable(_)));
            if asked != 0 {
                assert!(matches!(by_gen, KeyProviderError::Irrecoverable(_)));
            }
        }
    }
    for e in [current, by_gen] {
        if reason.len() >= 4 {
            assert!(
                !format!("{e} {e:?}").contains(&reason),
                "the foreign reason leaked"
            );
        }
    }
});
