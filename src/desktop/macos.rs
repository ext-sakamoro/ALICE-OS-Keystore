//! macOS Keychain store
//!
//! Each generation is one generic password item in the login keychain: service = the
//! store's service name, account = `gen-<n>` (decimal, no leading zero), data = the 32
//! key bytes, created once and never rewritten; and a marker item `issued-<n>` for every
//! generation issued (see the generation model in `desktop`). Items are added with `SecItemAdd`, which
//! refuses an item that already exists, so two processes creating the same generation at
//! once cannot both win: the loser reads the item the winner wrote.
//!
//! The items live in the file-based login keychain, not the data protection keychain: the
//! latter needs a signed binary with an access group, which a command-line program does
//! not have. The keychain lets the program that created an item read it without asking;
//! another program (or a rebuilt one with a different signature) gets the system's
//! "allow access" dialog, and a refusal is [`KeyProviderError::Unavailable`].
//!
//! Every call into the Security framework, including the release of the objects it hands
//! back, runs under one lock for the whole process: the file-based keychain can deadlock
//! inside the framework when one thread adds an item while another searches or deletes
//! (seen on macOS 26, every thread waiting on the framework's own mutexes). Calls are
//! therefore serialised within a process, and another library in the same process that
//! calls the framework on its own is outside that guarantee. Processes are not serialised:
//! two processes agree on a generation through `SecItemAdd` refusing a duplicate.
//!
//! The key bytes the Security framework hands back are copied into the [`Key`] (zeroed on
//! drop) and the returned buffer is zeroed. Copies the framework makes on its own side
//! are outside this crate's reach.

use core_foundation::data::CFData;
use security_framework::base::Error as SecError;
use security_framework::item::{ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Limit};
use security_framework::passwords::get_generic_password;
use zeroize::Zeroize;

use super::{by_generation_of, current_of, generation_of, rotate_of, GenerationItems, Inventory};
use crate::{Key, KeyGeneration, KeyProvider, KeyProviderError};

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

const KEY_PREFIX: &str = "gen-";
const MARKER_PREFIX: &str = "issued-";

static KEYCHAIN: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run `f` holding the process-wide lock of the Security framework calls (see the module
/// doc); for tests that reach the keychain directly next to the store. `f` must not call
/// the store (the lock is not reentrant)
#[doc(hidden)]
pub fn keychain_serialized<T>(f: impl FnOnce() -> T) -> T {
    let _guard = KEYCHAIN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f()
}

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

    /// Add a fresh random key as the next generation (above every generation ever issued,
    /// 1 when the service holds none) and return it; the older items stay
    ///
    /// # Errors
    /// [`KeyProviderError::Unavailable`] when the keychain refuses, the entropy source
    /// fails, the generation counter would overflow, or other processes keep adding
    /// generations faster than this call can claim one
    pub fn rotate(&self) -> Result<KeyGeneration, KeyProviderError> {
        rotate_of(self)
    }

    /// Add a generic password item; `false` when the account already exists
    fn add(&self, account: &str, data: &[u8]) -> Result<bool, KeyProviderError> {
        let mut item = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(data),
        });
        item.set_service(&self.service)
            .set_account_name(account)
            .set_label(format!("{} {account}", self.service));
        keychain_serialized(|| match item.add() {
            Ok(()) => Ok(true),
            Err(e) if e.code() == ERR_SEC_DUPLICATE_ITEM => Ok(false),
            Err(e) => Err(unavailable(e)),
        })
    }
}

impl GenerationItems for MacosKeychainStore {
    fn inventory(&self) -> Result<Inventory, KeyProviderError> {
        // the search results are released inside the lock too
        keychain_serialized(|| self.inventory_unlocked())
    }

    fn read(&self, generation: KeyGeneration) -> Result<Option<Key>, KeyProviderError> {
        keychain_serialized(|| self.read_unlocked(generation))
    }

    fn create(&self, generation: KeyGeneration, key: &Key) -> Result<bool, KeyProviderError> {
        self.add(&format!("{KEY_PREFIX}{generation}"), key.as_bytes())
    }

    fn mark(&self, generation: KeyGeneration) -> Result<(), KeyProviderError> {
        // the marker holds no secret; its presence is the record
        self.add(&format!("{MARKER_PREFIX}{generation}"), b"issued")
            .map(|_| ())
    }
}

impl MacosKeychainStore {
    fn inventory_unlocked(&self) -> Result<Inventory, KeyProviderError> {
        let found = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(&self.service)
            .load_attributes(true)
            .limit(Limit::All)
            .search();
        let items = match found {
            Ok(items) => items,
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(Inventory::default()),
            Err(e) => return Err(unavailable(e)),
        };
        let mut inv = Inventory::default();
        for item in &items {
            let Some(account) = item.simplify_dict().and_then(|d| d.get("acct").cloned()) else {
                continue;
            };
            if let Some(g) = generation_of(&account, KEY_PREFIX, "") {
                inv.keys.insert(g);
            } else if let Some(g) = generation_of(&account, MARKER_PREFIX, "") {
                inv.issued.insert(g);
            }
        }
        Ok(inv)
    }

    fn read_unlocked(&self, generation: KeyGeneration) -> Result<Option<Key>, KeyProviderError> {
        match get_generic_password(&self.service, &format!("{KEY_PREFIX}{generation}")) {
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
}

impl KeyProvider for MacosKeychainStore {
    /// The newest generation, creating generation 1 when the service holds none
    fn current(&self) -> Result<(KeyGeneration, Key), KeyProviderError> {
        current_of(self)
    }

    fn by_generation(&self, generation: KeyGeneration) -> Result<Key, KeyProviderError> {
        by_generation_of(self, generation)
    }
}
