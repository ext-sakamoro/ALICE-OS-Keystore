//! A key store implemented in Swift or Kotlin, handed to Rust as a [`KeyProvider`]
//!
//! The foreign side implements [`ForeignKeyVault`] (generated as a Swift protocol /
//! Kotlin interface by `UniFFI`) and passes it in; [`ForeignVaultAdapter`] checks
//! what comes back (exactly 32 bytes, a generation of at least 1) and maps errors by
//! kind. The foreign reason text is not passed on: [`KeyProviderError`] carries fixed
//! reasons, and a foreign message can name paths or other detail.
//!
//! A floor kept in the platform's key store (the iOS / Android Keychain or Keystore, outside
//! the app's data directory) is handed in the same way: the foreign side implements
//! [`ForeignMonotonicFloor`] and [`ForeignFloorAdapter`] makes it a [`MonotonicFloor`]. This
//! crate ships no Swift or Kotlin implementation of it; the app supplies one.

use crate::{
    FloorError, FloorName, Key, KeyGeneration, KeyProvider, KeyProviderError, MonotonicFloor,
};

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

// A foreign store threw an error the binding does not know. Without this conversion the scaffolding
// panics and the generated binding aborts the host process. Unavailable, not Irrecoverable: nothing
// says the key is gone, and a caller must not give up on data over an error it cannot read. The
// foreign text is not kept (it may carry paths or other detail).
impl From<uniffi::UnexpectedUniFFICallbackError> for ForeignVaultError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unavailable {
            reason: "the foreign key store threw an error of an unknown type".to_string(),
        }
    }
}

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

/// A floor value as the foreign side passes it: `(hi, lo)`, compared lexicographically
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FloorValue {
    pub hi: u64,
    pub lo: u64,
}

/// Errors a foreign floor store reports
#[derive(Debug, uniffi::Error)]
pub enum ForeignFloorError {
    /// Cannot read or write the floor now (locked, access refused); a later call may succeed
    Unavailable { reason: String },
}

impl std::fmt::Display for ForeignFloorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable { reason } => write!(f, "floor store unavailable: {reason}"),
        }
    }
}

impl std::error::Error for ForeignFloorError {}

// as for ForeignVaultError: an unknown foreign error is Unavailable, never an abort
impl From<uniffi::UnexpectedUniFFICallbackError> for ForeignFloorError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unavailable {
            reason: "the foreign floor store threw an error of an unknown type".to_string(),
        }
    }
}

/// Named floors as the foreign side implements them (the platform's key store)
///
/// `raise_floor` keeps the larger of the stored value and `to` (lexicographic on `(hi, lo)`)
/// and returns the stored value after the call; a lower `to` changes nothing.
#[uniffi::export(callback_interface)]
pub trait ForeignMonotonicFloor: Send + Sync {
    /// The floor of `name`, `None` when it was never raised
    ///
    /// # Errors
    /// [`ForeignFloorError::Unavailable`]
    fn read_floor(&self, name: String) -> Result<Option<FloorValue>, ForeignFloorError>;
    /// Raise the floor of `name` to at least `to` and return the floor after the call
    ///
    /// # Errors
    /// [`ForeignFloorError::Unavailable`]
    fn raise_floor(&self, name: String, to: FloorValue) -> Result<FloorValue, ForeignFloorError>;
}

/// A [`ForeignMonotonicFloor`] used as a [`MonotonicFloor`]
///
/// It checks what comes back: a raise that reports a floor below the value asked for broke
/// the contract and is [`FloorError::Unavailable`] (the floor was not raised as far as asked).
pub struct ForeignFloorAdapter {
    inner: Box<dyn ForeignMonotonicFloor>,
}

impl ForeignFloorAdapter {
    #[must_use]
    pub fn new(inner: Box<dyn ForeignMonotonicFloor>) -> Self {
        Self { inner }
    }
}

const FLOOR_FOREIGN_UNAVAILABLE: &str = "the foreign floor store cannot be used now";

impl MonotonicFloor for ForeignFloorAdapter {
    fn read(&self, name: &FloorName) -> Result<Option<(u64, u64)>, FloorError> {
        self.inner
            .read_floor(name.as_str().to_owned())
            .map(|v| v.map(|v| (v.hi, v.lo)))
            .map_err(|_| FloorError::Unavailable(FLOOR_FOREIGN_UNAVAILABLE))
    }

    fn raise(&self, name: &FloorName, to: (u64, u64)) -> Result<(u64, u64), FloorError> {
        let after = self
            .inner
            .raise_floor(name.as_str().to_owned(), FloorValue { hi: to.0, lo: to.1 })
            .map_err(|_| FloorError::Unavailable(FLOOR_FOREIGN_UNAVAILABLE))?;
        let after = (after.hi, after.lo);
        if after < to {
            return Err(FloorError::Unavailable(
                "the foreign floor store reported a floor below the value asked for",
            ));
        }
        Ok(after)
    }
}
