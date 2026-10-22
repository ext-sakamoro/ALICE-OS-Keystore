#![no_main]
//! A foreign key store may return any bytes: the adapter accepts exactly 32 and
//! reports the length otherwise, never panicking.

use alice_os_keystore::ffi::{ForeignKeyVault, ForeignVaultAdapter, ForeignVaultError, GenerationKey};
use alice_os_keystore::{KeyVault, VaultError};
use libfuzzer_sys::fuzz_target;

struct Returns(Vec<u8>, u32);

impl ForeignKeyVault for Returns {
    fn current(&self) -> Result<GenerationKey, ForeignVaultError> {
        Ok(GenerationKey { generation: self.1, key: self.0.clone() })
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
            assert_eq!(g, generation);
            assert_eq!(&k.as_bytes()[..], &bytes[..]);
        }
        Err(e) => assert_eq!(e, VaultError::InvalidKeyLength(len)),
    }
    match adapter.by_id(generation) {
        Ok(k) => assert_eq!(&k.as_bytes()[..], &bytes[..]),
        Err(e) => assert_eq!(e, VaultError::InvalidKeyLength(len)),
    }
});
