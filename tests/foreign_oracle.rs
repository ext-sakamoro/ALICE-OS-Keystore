//! Oracle for the adapter that turns a key store implemented on the other side
//! of the FFI (Swift / Kotlin) into a `KeyVault`. The foreign side hands raw
//! bytes; the adapter must accept exactly 32 and pass errors through by kind.
#![cfg(feature = "uniffi")]

use alice_os_keystore::ffi::{
    ForeignKeyVault, ForeignVaultAdapter, ForeignVaultError, GenerationKey,
};
use alice_os_keystore::{KeyVault, VaultError};

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
    assert_eq!(a.by_id(4).unwrap().as_bytes(), &[9; 32]);
}

#[test]
fn errors_keep_their_kind() {
    assert_eq!(
        adapter(vec![9; 32], false).by_id(5).unwrap_err(),
        VaultError::UnknownKey(5)
    );
    assert!(matches!(
        adapter(vec![9; 32], true).current(),
        Err(VaultError::Unavailable(_))
    ));
    assert!(matches!(
        adapter(vec![9; 32], true).by_id(4),
        Err(VaultError::Unavailable(_))
    ));
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    for len in [0usize, 16, 31, 33, 64] {
        assert_eq!(
            adapter(vec![1; len], false).current().unwrap_err(),
            VaultError::InvalidKeyLength(len),
            "len {len}"
        );
        assert_eq!(
            adapter(vec![1; len], false).by_id(4).unwrap_err(),
            VaultError::InvalidKeyLength(len)
        );
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
            reason: "blob does not open".into(),
        })
    }
    fn by_id(&self, _generation: u32) -> Result<Vec<u8>, ForeignVaultError> {
        Err(ForeignVaultError::Irrecoverable {
            reason: "blob does not open".into(),
        })
    }
}

#[test]
fn an_irrecoverable_foreign_error_stays_irrecoverable() {
    let a = ForeignVaultAdapter::new(Box::new(Broken));
    assert_eq!(
        a.current().unwrap_err(),
        VaultError::Irrecoverable("blob does not open".into())
    );
    assert_eq!(
        a.by_id(1).unwrap_err(),
        VaultError::Irrecoverable("blob does not open".into())
    );
    assert_eq!(
        ForeignVaultError::Irrecoverable { reason: "x".into() }.to_string(),
        "key store cannot recover this key: x"
    );
}
