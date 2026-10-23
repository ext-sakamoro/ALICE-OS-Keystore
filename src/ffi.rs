//! A key store implemented in Swift or Kotlin, handed to Rust as a [`KeyProvider`]
//!
//! The foreign side implements [`ForeignKeyVault`] (generated as a Swift protocol /
//! Kotlin interface by `UniFFI`) and passes it in; [`ForeignVaultAdapter`] checks
//! what comes back (exactly 32 bytes, a generation of at least 1) and maps errors by
//! kind. The foreign reason text is not passed on: [`KeyProviderError`] carries fixed
//! reasons, and a foreign message can name paths or other detail.

use crate::{Key, KeyGeneration, KeyProvider, KeyProviderError};

/// A generation and its raw key bytes, as the foreign side returns them
#[derive(uniffi::Record)]
pub struct GenerationKey {
    pub generation: u32,
    pub key: Vec<u8>,
}

/// Errors a foreign key store reports
#[derive(Debug, uniffi::Error)]
pub enum ForeignVaultError {
    /// No key of this generation
    UnknownKey { generation: u32 },
    /// Cannot hand out keys now (locked, authentication refused); a later call may succeed
    Unavailable { reason: String },
    /// The key cannot be recovered (wrapping key gone, wrapped blob does not open); retrying will not help
    Irrecoverable { reason: String },
}

impl std::fmt::Display for ForeignVaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownKey { generation } => write!(f, "no data key of generation {generation}"),
            Self::Unavailable { reason } => write!(f, "key store unavailable: {reason}"),
            Self::Irrecoverable { reason } => {
                write!(f, "key store cannot recover this key: {reason}")
            }
        }
    }
}

impl std::error::Error for ForeignVaultError {}

/// The key store as the foreign side implements it
#[uniffi::export(callback_interface)]
pub trait ForeignKeyVault: Send + Sync {
    /// The generation and key to seal new data with
    ///
    /// # Errors
    /// [`ForeignVaultError::Unavailable`] when no key can be handed out now
    fn current(&self) -> Result<GenerationKey, ForeignVaultError>;
    /// The key of `generation`
    ///
    /// # Errors
    /// [`ForeignVaultError::UnknownKey`] / [`ForeignVaultError::Unavailable`]
    fn by_id(&self, generation: u32) -> Result<Vec<u8>, ForeignVaultError>;
}

/// A [`ForeignKeyVault`] used as a [`KeyProvider`]
pub struct ForeignVaultAdapter {
    inner: Box<dyn ForeignKeyVault>,
}

impl ForeignVaultAdapter {
    #[must_use]
    pub fn new(inner: Box<dyn ForeignKeyVault>) -> Self {
        Self { inner }
    }
}

// the foreign store broke the contract (wrong length): asking again returns the same bytes
fn to_key(mut bytes: Vec<u8>) -> Result<Key, KeyProviderError> {
    use zeroize::Zeroize;
    let out = Key::from_slice(&bytes).map_err(|_| {
        KeyProviderError::Irrecoverable("the foreign key store returned a key that is not 32 bytes")
    });
    bytes.zeroize();
    out
}

const FOREIGN_UNAVAILABLE: &str = "the foreign key store cannot hand out keys now";
const FOREIGN_IRRECOVERABLE: &str = "the foreign key store cannot recover this key";

impl KeyProvider for ForeignVaultAdapter {
    fn current(&self) -> Result<(KeyGeneration, Key), KeyProviderError> {
        let gk = self.inner.current().map_err(|e| match e {
            // there is no current key yet: nothing to open, a later call may find one
            ForeignVaultError::UnknownKey { .. } | ForeignVaultError::Unavailable { .. } => {
                KeyProviderError::Unavailable(FOREIGN_UNAVAILABLE)
            }
            ForeignVaultError::Irrecoverable { .. } => {
                KeyProviderError::Irrecoverable(FOREIGN_IRRECOVERABLE)
            }
        })?;
        if gk.generation == 0 {
            return Err(KeyProviderError::Irrecoverable(
                "the foreign key store reported generation 0",
            ));
        }
        Ok((gk.generation, to_key(gk.key)?))
    }

    fn by_generation(&self, generation: KeyGeneration) -> Result<Key, KeyProviderError> {
        if generation == 0 {
            return Err(KeyProviderError::UnknownGeneration(0));
        }
        let bytes = self.inner.by_id(generation).map_err(|e| match e {
            ForeignVaultError::UnknownKey { .. } => KeyProviderError::UnknownGeneration(generation),
            ForeignVaultError::Unavailable { .. } => {
                KeyProviderError::Unavailable(FOREIGN_UNAVAILABLE)
            }
            ForeignVaultError::Irrecoverable { .. } => {
                KeyProviderError::Irrecoverable(FOREIGN_IRRECOVERABLE)
            }
        })?;
        to_key(bytes)
    }
}
