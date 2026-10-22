//! A key store implemented in Swift or Kotlin, handed to Rust as a [`KeyVault`]
//!
//! The foreign side implements [`ForeignKeyVault`] (generated as a Swift protocol /
//! Kotlin interface by `UniFFI`) and passes it in; [`ForeignVaultAdapter`] checks
//! what comes back (exactly 32 bytes) and maps errors by kind.

use crate::{DataKey, KeyVault, VaultError};

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

/// A [`ForeignKeyVault`] used as a [`KeyVault`]
pub struct ForeignVaultAdapter {
    inner: Box<dyn ForeignKeyVault>,
}

impl ForeignVaultAdapter {
    #[must_use]
    pub fn new(inner: Box<dyn ForeignKeyVault>) -> Self {
        Self { inner }
    }
}

fn to_key(mut bytes: Vec<u8>) -> Result<DataKey, VaultError> {
    use zeroize::Zeroize;
    let out = <[u8; 32]>::try_from(bytes.as_slice())
        .map(DataKey::from_bytes)
        .map_err(|_| VaultError::InvalidKeyLength(bytes.len()));
    bytes.zeroize();
    out
}

fn from_foreign(e: ForeignVaultError) -> VaultError {
    match e {
        ForeignVaultError::UnknownKey { generation } => VaultError::UnknownKey(generation),
        ForeignVaultError::Unavailable { reason } => VaultError::Unavailable(reason),
        ForeignVaultError::Irrecoverable { reason } => VaultError::Irrecoverable(reason),
    }
}

impl KeyVault for ForeignVaultAdapter {
    fn current(&self) -> Result<(u32, DataKey), VaultError> {
        let gk = self.inner.current().map_err(from_foreign)?;
        Ok((gk.generation, to_key(gk.key)?))
    }

    fn by_id(&self, generation: u32) -> Result<DataKey, VaultError> {
        to_key(self.inner.by_id(generation).map_err(from_foreign)?)
    }
}
