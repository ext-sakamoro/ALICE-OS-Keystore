#![no_main]
//! A foreign key store may return any bytes and any generation: the adapter accepts
//! exactly 32 bytes and a generation of at least 1, reports `Irrecoverable` otherwise,
//! and never panics.

use alice_os_keystore::ffi::{
    ForeignKeyVault, ForeignVaultAdapter, ForeignVaultError, GenerationKey,
};
use alice_os_keystore::{KeyProvider, KeyProviderError};
use libfuzzer_sys::fuzz_target;

struct Returns(Vec<u8>, u32);

impl ForeignKeyVault for Returns {
    fn current(&self) -> Result<GenerationKey, ForeignVaultError> {
        Ok(GenerationKey {
            generation: self.1,
            key: self.0.clone(),
        })
    }
    fn by_id(&self, _generation: u32) -> Result<Vec<u8>, ForeignVaultError> {
        Ok(self.0.clone())
    }
}

fuzz_target!(|input: (Vec<u8>, u32)| {
    let (bytes, generation) = input;
    let len = bytes.len();
    let adapter = ForeignVaultAdapter::new(Box::new(Returns(bytes.clone(), generation)));
    match adapter.current() {
        Ok((g, k)) => {
            assert_eq!(len, 32);
            assert_ne!(g, 0);
            assert_eq!(g, generation);
            assert_eq!(&k.as_bytes()[..], &bytes[..]);
        }
        Err(e) => {
            assert!(len != 32 || generation == 0);
            assert!(matches!(e, KeyProviderError::Irrecoverable(_)));
        }
    }
    match adapter.by_generation(generation) {
        Ok(k) => {
            assert_ne!(generation, 0);
            assert_eq!(&k.as_bytes()[..], &bytes[..]);
        }
        Err(KeyProviderError::UnknownGeneration(0)) => assert_eq!(generation, 0),
        Err(e) => {
            assert_ne!(len, 32);
            assert!(matches!(e, KeyProviderError::Irrecoverable(_)));
        }
    }
});
