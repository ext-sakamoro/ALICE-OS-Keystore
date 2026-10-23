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

use super::{by_generation_of, current_of, generation_of, rotate_of, GenerationItems};
use crate::{Key, KeyGeneration, KeyProvider, KeyProviderError};

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

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

    /// Add a fresh random key as the next generation (1 when the service holds none) and
    /// return it; the older items stay
    ///
    /// # Errors
    /// [`KeyProviderError::Unavailable`] when the keychain refuses, the entropy source
    /// fails, the generation counter would overflow, or other processes keep adding
    /// generations faster than this call can claim one
    pub fn rotate(&self) -> Result<KeyGeneration, KeyProviderError> {
        rotate_of(self)
    }
}

impl GenerationItems for MacosKeychainStore {
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
        Ok(items
            .iter()
            .filter_map(|item| generation_of(item.simplify_dict()?.get("acct")?, "gen-", ""))
            .collect())
    }

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

    fn create(&self, generation: KeyGeneration, key: &Key) -> Result<bool, KeyProviderError> {
        let mut item = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(key.as_bytes()),
        });
        item.set_service(&self.service)
            .set_account_name(account(generation))
            .set_label(format!("{} key generation {generation}", self.service));
        match item.add() {
            Ok(()) => Ok(true),
            Err(e) if e.code() == ERR_SEC_DUPLICATE_ITEM => Ok(false),
            Err(e) => Err(unavailable(e)),
        }
    }
}

impl KeyProvider for MacosKeychainStore {
    /// The highest generation, creating generation 1 when the service holds none
    fn current(&self) -> Result<(KeyGeneration, Key), KeyProviderError> {
        current_of(self)
    }

    fn by_generation(&self, generation: KeyGeneration) -> Result<Key, KeyProviderError> {
        by_generation_of(self, generation)
    }
}
