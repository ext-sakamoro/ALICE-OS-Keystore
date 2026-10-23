#![no_main]
//! Errors from a foreign key store keep their kind through the adapter, and the
//! reason is always one of the adapter's fixed strings, never the foreign text.

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
    // the reason is one of the adapter's fixed strings, never the foreign text (comparing
    // the whole reason: a short foreign text can be a substring of a fixed one)
    const FIXED: [&str; 2] = [
        "the foreign key store cannot hand out keys now",
        "the foreign key store cannot recover this key",
    ];
    for e in [current, by_gen] {
        match e {
            KeyProviderError::Unavailable(why) | KeyProviderError::Irrecoverable(why) => {
                assert!(FIXED.contains(&why), "reason {why:?} is not a fixed one");
            }
            _ => {}
        }
    }
});
