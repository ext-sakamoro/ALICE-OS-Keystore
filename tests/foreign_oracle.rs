//! Oracle for the adapter that turns a key store implemented on the other side
//! of the FFI (Swift / Kotlin) into a `KeyProvider`. The foreign side hands raw
//! bytes; the adapter must accept exactly 32 and pass errors through by kind.
//! The foreign reason strings are not passed on (they may carry paths or other
//! detail); each kind gets a fixed reason.
#![cfg(feature = "uniffi")]

use alice_crypto::{KeyProvider, KeyProviderError};
use alice_os_keystore::ffi::{
    ForeignKeyVault, ForeignVaultAdapter, ForeignVaultError, GenerationKey,
};

struct Fixed {
    key: Vec<u8>,
    locked: bool,
}

impl ForeignKeyVault for Fixed {
    fn current(&self) -> Result<GenerationKey, ForeignVaultError> {
        if self.locked {
            return Err(ForeignVaultError::Unavailable {
                reason: "locked".into(),
            });
        }
        Ok(GenerationKey {
            generation: 4,
            key: self.key.clone(),
        })
    }
    fn by_id(&self, generation: u32) -> Result<Vec<u8>, ForeignVaultError> {
        if self.locked {
            return Err(ForeignVaultError::Unavailable {
                reason: "locked".into(),
            });
        }
        if generation == 4 {
            Ok(self.key.clone())
        } else {
            Err(ForeignVaultError::UnknownKey { generation })
        }
    }
}

fn adapter(key: Vec<u8>, locked: bool) -> ForeignVaultAdapter {
    ForeignVaultAdapter::new(Box::new(Fixed { key, locked }))
}

#[test]
fn a_32_byte_key_passes_through() {
    let a = adapter(vec![9; 32], false);
    let (g, k) = a.current().unwrap();
    assert_eq!((g, k.as_bytes()), (4, &[9; 32]));
    assert_eq!(a.by_generation(4).unwrap().as_bytes(), &[9; 32]);
}

#[test]
fn errors_keep_their_kind() {
    assert_eq!(
        adapter(vec![9; 32], false)
            .by_generation(5)
            .err()
            .expect("an error"),
        KeyProviderError::UnknownGeneration(5)
    );
    assert!(matches!(
        adapter(vec![9; 32], true).current(),
        Err(KeyProviderError::Unavailable(_))
    ));
    assert!(matches!(
        adapter(vec![9; 32], true).by_generation(4),
        Err(KeyProviderError::Unavailable(_))
    ));
}

#[test]
fn generation_zero_never_reaches_the_foreign_side() {
    struct Panics;
    impl ForeignKeyVault for Panics {
        fn current(&self) -> Result<GenerationKey, ForeignVaultError> {
            panic!("not called")
        }
        fn by_id(&self, _generation: u32) -> Result<Vec<u8>, ForeignVaultError> {
            panic!("generation 0 was passed to the foreign store")
        }
    }
    let a = ForeignVaultAdapter::new(Box::new(Panics));
    assert_eq!(
        a.by_generation(0).err().expect("an error"),
        KeyProviderError::UnknownGeneration(0)
    );
}

#[test]
fn a_current_generation_of_zero_is_irrecoverable() {
    struct Zero;
    impl ForeignKeyVault for Zero {
        fn current(&self) -> Result<GenerationKey, ForeignVaultError> {
            Ok(GenerationKey {
                generation: 0,
                key: vec![1; 32],
            })
        }
        fn by_id(&self, _generation: u32) -> Result<Vec<u8>, ForeignVaultError> {
            Ok(vec![1; 32])
        }
    }
    let a = ForeignVaultAdapter::new(Box::new(Zero));
    assert!(matches!(
        a.current(),
        Err(KeyProviderError::Irrecoverable(_))
    ));
}

#[test]
fn a_key_of_the_wrong_length_is_irrecoverable() {
    // the foreign store broke the contract: retrying returns the same bytes
    for len in [0usize, 16, 31, 33, 64] {
        assert!(
            matches!(
                adapter(vec![1; len], false).current(),
                Err(KeyProviderError::Irrecoverable(_))
            ),
            "len {len}"
        );
        assert!(matches!(
            adapter(vec![1; len], false).by_generation(4),
            Err(KeyProviderError::Irrecoverable(_))
        ));
    }
}

#[test]
fn foreign_errors_say_what_happened() {
    assert_eq!(
        ForeignVaultError::UnknownKey { generation: 2 }.to_string(),
        "no data key of generation 2"
    );
    assert_eq!(
        ForeignVaultError::Unavailable { reason: "x".into() }.to_string(),
        "key store unavailable: x"
    );
}

struct Broken;

impl ForeignKeyVault for Broken {
    fn current(&self) -> Result<GenerationKey, ForeignVaultError> {
        Err(ForeignVaultError::Irrecoverable {
            reason: "blob does not open /Users/someone/secret".into(),
        })
    }
    fn by_id(&self, _generation: u32) -> Result<Vec<u8>, ForeignVaultError> {
        Err(ForeignVaultError::Irrecoverable {
            reason: "blob does not open /Users/someone/secret".into(),
        })
    }
}

#[test]
fn an_irrecoverable_foreign_error_stays_irrecoverable_without_its_text() {
    let a = ForeignVaultAdapter::new(Box::new(Broken));
    for e in [
        a.current().err().expect("an error"),
        a.by_generation(1).err().expect("an error"),
    ] {
        assert!(matches!(e, KeyProviderError::Irrecoverable(_)));
        assert!(!format!("{e} {e:?}").contains("/Users/someone"));
    }
    assert_eq!(
        ForeignVaultError::Irrecoverable { reason: "x".into() }.to_string(),
        "key store cannot recover this key: x"
    );
}
