//! macOS Keychain store
//!
//! Each generation is one generic password item in the login keychain: service = the
//! store's service name, account = `gen-<n>` (decimal, no leading zero), data = the 32
//! key bytes, created once and never rewritten. Items are added with `SecItemAdd`, which
//! refuses an item that already exists, so two processes creating the same generation at
//! once cannot both win: the loser reads the item the winner wrote.
//!
//! The items live in the file-based login keychain, not the data protection keychain: the
//! latter needs a signed binary with an access group, which a command-line program does
//! not have. The keychain lets the program that created an item read it without asking;
//! another program (or a rebuilt one with a different signature) gets the system's
//! "allow access" dialog, and a refusal is [`KeyProviderError::Unavailable`].
//!
//! The key bytes the Security framework hands back are copied into the [`Key`] (zeroed on
//! drop) and the returned buffer is zeroed. Copies the framework makes on its own side
//! are outside this crate's reach.

use core_foundation::data::CFData;
use security_framework::base::Error as SecError;
use security_framework::item::{ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Limit};
use security_framework::passwords::get_generic_password;
use zeroize::Zeroize;

use crate::{Key, KeyGeneration, KeyProvider, KeyProviderError};

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

/// How often one call re-reads the items when another process changed them meanwhile
/// (each retry follows an item that someone else added, so a retry is progress)
const ATTEMPTS: usize = 64;

/// Keys kept in the macOS login keychain, one item per generation
pub struct MacosKeychainStore {
    service: String,
}

// the operating system's message can name the keychain file; only the kind is passed on
fn unavailable(e: SecError) -> KeyProviderError {
    KeyProviderError::Unavailable(match e.code() {
        ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED => "keychain access was refused",
        ERR_SEC_INTERACTION_NOT_ALLOWED => "the keychain is locked or cannot ask for access now",
        _ => "the keychain refused the request",
    })
}

fn account(generation: KeyGeneration) -> String {
    format!("gen-{generation}")
}

/// The generation an account name stands for, `None` for any other name
fn generation_of(account: &str) -> Option<KeyGeneration> {
    let digits = account.strip_prefix("gen-")?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

impl MacosKeychainStore {
    /// A store for the keys of `service` (a name only this application uses, such as a
    /// reverse-DNS identifier)
    ///
    /// Nothing is read or created until the first call.
    ///
    /// # Panics
    /// When `service` is empty (it would share items with any other program that leaves
    /// the service empty)
    #[must_use]
    pub fn new(service: &str) -> Self {
        assert!(!service.is_empty(), "the keychain service name is empty");
        Self {
            service: service.to_owned(),
        }
    }

    /// The generations the keychain holds for this service, ascending
    fn generations(&self) -> Result<Vec<KeyGeneration>, KeyProviderError> {
        let found = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(&self.service)
            .load_attributes(true)
            .limit(Limit::All)
            .search();
        let items = match found {
            Ok(items) => items,
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(Vec::new()),
            Err(e) => return Err(unavailable(e)),
        };
        let mut generations: Vec<KeyGeneration> = items
            .iter()
            .filter_map(|item| generation_of(item.simplify_dict()?.get("acct")?))
            .collect();
        generations.sort_unstable();
        generations.dedup();
        Ok(generations)
    }

    /// The key of `generation`, `None` when there is no such item
    fn read(&self, generation: KeyGeneration) -> Result<Option<Key>, KeyProviderError> {
        match get_generic_password(&self.service, &account(generation)) {
            Ok(mut bytes) => {
                let key = Key::from_slice(&bytes).map_err(|_| {
                    KeyProviderError::Irrecoverable("the keychain item is not a 32-byte key")
                });
                bytes.zeroize();
                key.map(Some)
            }
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(unavailable(e)),
        }
    }

    /// Create `generation` with a fresh random key; `None` when the item already exists
    fn add(&self, generation: KeyGeneration) -> Result<Option<Key>, KeyProviderError> {
        let key =
            Key::generate().map_err(|_| KeyProviderError::Unavailable("entropy source failed"))?;
        let mut item = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(key.as_bytes()),
        });
        item.set_service(&self.service)
            .set_account_name(account(generation))
            .set_label(format!("{} key generation {generation}", self.service));
        match item.add() {
            Ok(()) => Ok(Some(key)),
            Err(e) if e.code() == ERR_SEC_DUPLICATE_ITEM => Ok(None),
            Err(e) => Err(unavailable(e)),
        }
    }

    /// Add a fresh random key as the next generation (1 when the service holds none) and
    /// return it; the older items stay
    ///
    /// # Errors
    /// [`KeyProviderError::Unavailable`] when the keychain refuses, the entropy source
    /// fails, the generation counter would overflow, or other processes keep adding
    /// generations faster than this call can claim one
    pub fn rotate(&self) -> Result<KeyGeneration, KeyProviderError> {
        for _ in 0..ATTEMPTS {
            let next = match self.generations()?.last() {
                None => 1,
                Some(&max) => max.checked_add(1).ok_or(KeyProviderError::Unavailable(
                    "generation counter exhausted",
                ))?,
            };
            if self.add(next)?.is_some() {
                return Ok(next);
            }
        }
        Err(KeyProviderError::Unavailable(
            "the keychain items kept changing during the call",
        ))
    }
}

impl KeyProvider for MacosKeychainStore {
    /// The highest generation, creating generation 1 when the service holds none
    fn current(&self) -> Result<(KeyGeneration, Key), KeyProviderError> {
        for _ in 0..ATTEMPTS {
            match self.generations()?.last() {
                Some(&max) => {
                    if let Some(key) = self.read(max)? {
                        return Ok((max, key));
                    }
                }
                None => {
                    if let Some(key) = self.add(1)? {
                        return Ok((1, key));
                    }
                }
            }
        }
        Err(KeyProviderError::Unavailable(
            "the keychain items kept changing during the call",
        ))
    }

    fn by_generation(&self, generation: KeyGeneration) -> Result<Key, KeyProviderError> {
        if generation == 0 {
            return Err(KeyProviderError::UnknownGeneration(0));
        }
        if let Some(key) = self.read(generation)? {
            return Ok(key);
        }
        // generations are added in order and never removed by this store: a higher one
        // shows that this one existed
        if self.generations()?.iter().any(|&g| g > generation) {
            Err(KeyProviderError::Irrecoverable(
                "the key of this generation was removed from the keychain",
            ))
        } else {
            Err(KeyProviderError::UnknownGeneration(generation))
        }
    }
}
