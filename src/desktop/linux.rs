//! Linux Secret Service store
//!
//! Each generation is one item in the default collection of the Secret Service
//! (gnome-keyring, `KWallet`) with the attributes `keystore-service` = the store's service
//! name and `keystore-generation` = the generation (decimal, no leading zero), holding the
//! 32 key bytes. The session with the service is encrypted (Diffie-Hellman, as the
//! specification offers).
//!
//! The Secret Service has no "create unless it exists": two processes creating the same
//! generation at once leave two items. Every reader therefore picks the same one, by what
//! the service alone sets: the earliest `Created` (a read-only property, set by the service
//! when the item is made), ties broken by the item's object path (assigned by the service).
//! A creator re-reads after creating and uses its own key only when its item is the one
//! chosen; otherwise it returns the chosen item's key. The other items are left in place,
//! logged (`log::warn!`, no key material) and counted by [`LinuxSecretServiceStore::duplicate_count`],
//! so a later explicit cleanup can remove them safely. For every generation issued a marker
//! item (attribute `keystore-issued`, no secret) follows the key item (see the generation
//! model in `desktop`); the store looks for a marker before making one, and a duplicate marker
//! from a race is harmless (only its presence counts).
//!
//! Without a reachable service (no D-Bus session bus, as on a headless machine), a locked
//! keyring that cannot be unlocked, or no default collection, every call is
//! [`KeyProviderError::Unavailable`], so the caller can fall back to a passphrase.

use std::collections::{BTreeSet, HashMap};

use secret_service::blocking::{Collection, Item, SecretService};
use secret_service::{EncryptionType, Error as SsError};
use zeroize::Zeroize;

use super::{by_generation_of, current_of, generation_of, rotate_of, GenerationItems, Inventory};
use crate::{Key, KeyGeneration, KeyProvider, KeyProviderError};

const SERVICE_ATTR: &str = "keystore-service";
const GENERATION_ATTR: &str = "keystore-generation";
const ISSUED_ATTR: &str = "keystore-issued";
const CONTENT_TYPE: &str = "application/octet-stream";

/// Keys kept in the Secret Service, one item per generation
pub struct LinuxSecretServiceStore {
    service: String,
}

// the service's own error text can name objects or paths; only the kind is passed on
fn unavailable(e: &SsError) -> KeyProviderError {
    KeyProviderError::Unavailable(match e {
        SsError::Locked | SsError::Prompt | SsError::PromptDisconnected => {
            "the keyring is locked or access was refused"
        }
        SsError::NoResult => "the Secret Service has no default keyring",
        SsError::Unavailable | SsError::Zbus(_) | SsError::ZbusFdo(_) => {
            "the Secret Service cannot be reached"
        }
        _ => "the Secret Service answered unexpectedly",
    })
}

/// The item every reader chooses among items of one generation: earliest `Created`, then
/// the lowest object path (both set by the service)
fn choose<'a, 'b>(items: &'b [Item<'a>]) -> Result<Option<&'b Item<'a>>, KeyProviderError> {
    let mut best: Option<((u64, String), &Item)> = None;
    for item in items {
        let rank = (
            item.get_created().map_err(|e| unavailable(&e))?,
            item.item_path.to_string(),
        );
        if best.as_ref().is_none_or(|(b, _)| rank < *b) {
            best = Some((rank, item));
        }
    }
    Ok(best.map(|(_, item)| item))
}

fn with_collection<T>(
    f: impl FnOnce(&Collection<'_>) -> Result<T, KeyProviderError>,
) -> Result<T, KeyProviderError> {
    let ss = SecretService::connect(EncryptionType::Dh).map_err(|e| unavailable(&e))?;
    let collection = ss.get_default_collection().map_err(|e| unavailable(&e))?;
    collection.ensure_unlocked().map_err(|e| unavailable(&e))?;
    f(&collection)
}

impl LinuxSecretServiceStore {
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
        assert!(!service.is_empty(), "the Secret Service name is empty");
        Self {
            service: service.to_owned(),
        }
    }

    /// Add a fresh random key as the next generation (1 when the service holds none) and
    /// return it; the older items stay
    ///
    /// # Errors
    /// [`KeyProviderError::Unavailable`] when the Secret Service cannot be reached or
    /// refuses, the entropy source fails, the generation counter would overflow, or other
    /// processes keep adding generations faster than this call can claim one
    pub fn rotate(&self) -> Result<KeyGeneration, KeyProviderError> {
        rotate_of(self)
    }

    /// How many stored items are duplicates (left by creators that lost a race), never used
    ///
    /// # Errors
    /// [`KeyProviderError::Unavailable`] when the Secret Service cannot be reached
    pub fn duplicate_count(&self) -> Result<usize, KeyProviderError> {
        with_collection(|c| {
            let items = self.service_items(c)?;
            let generations: BTreeSet<KeyGeneration> = items.iter().map(|(g, _)| *g).collect();
            Ok(items.len() - generations.len())
        })
    }

    /// The items of this service with a canonical generation attribute
    fn service_items<'a>(
        &self,
        c: &'a Collection<'_>,
    ) -> Result<Vec<(KeyGeneration, Item<'a>)>, KeyProviderError> {
        let items = c
            .search_items(HashMap::from([(SERVICE_ATTR, self.service.as_str())]))
            .map_err(|e| unavailable(&e))?;
        let mut out = Vec::new();
        for item in items {
            let attrs = item.get_attributes().map_err(|e| unavailable(&e))?;
            if let Some(g) = attrs
                .get(GENERATION_ATTR)
                .and_then(|v| generation_of(v, "", ""))
            {
                out.push((g, item));
            }
        }
        Ok(out)
    }

    fn generation_items<'a>(
        &self,
        c: &'a Collection<'_>,
        generation: KeyGeneration,
    ) -> Result<Vec<Item<'a>>, KeyProviderError> {
        let g = generation.to_string();
        c.search_items(HashMap::from([
            (SERVICE_ATTR, self.service.as_str()),
            (GENERATION_ATTR, g.as_str()),
        ]))
        .map_err(|e| unavailable(&e))
    }

    fn read_chosen(item: &Item<'_>) -> Result<Key, KeyProviderError> {
        let mut bytes = item.get_secret().map_err(|e| unavailable(&e))?;
        let key = Key::from_slice(&bytes).map_err(|_| {
            KeyProviderError::Irrecoverable("the Secret Service item is not a 32-byte key")
        });
        bytes.zeroize();
        key
    }
}

impl GenerationItems for LinuxSecretServiceStore {
    fn inventory(&self) -> Result<Inventory, KeyProviderError> {
        with_collection(|c| {
            let items = c
                .search_items(HashMap::from([(SERVICE_ATTR, self.service.as_str())]))
                .map_err(|e| unavailable(&e))?;
            let mut inv = Inventory::default();
            for item in items {
                let attrs = item.get_attributes().map_err(|e| unavailable(&e))?;
                if let Some(g) = attrs
                    .get(GENERATION_ATTR)
                    .and_then(|v| generation_of(v, "", ""))
                {
                    inv.keys.insert(g);
                } else if let Some(g) = attrs
                    .get(ISSUED_ATTR)
                    .and_then(|v| generation_of(v, "", ""))
                {
                    inv.issued.insert(g);
                }
            }
            Ok(inv)
        })
    }

    fn read(&self, generation: KeyGeneration) -> Result<Option<Key>, KeyProviderError> {
        with_collection(|c| {
            let items = self.generation_items(c, generation)?;
            if items.len() > 1 {
                log::warn!(
                    "alice-os-keystore: {} duplicate Secret Service items for generation {generation} (the earliest is used)",
                    items.len() - 1
                );
            }
            choose(&items)?.map(Self::read_chosen).transpose()
        })
    }

    /// Create an item for `generation`; `true` only when, re-read afterwards, the item
    /// chosen for that generation is the one just created
    fn create(&self, generation: KeyGeneration, key: &Key) -> Result<bool, KeyProviderError> {
        with_collection(|c| {
            let g = generation.to_string();
            let created = c
                .create_item(
                    &format!("{} key generation {generation}", self.service),
                    HashMap::from([
                        (SERVICE_ATTR, self.service.as_str()),
                        (GENERATION_ATTR, g.as_str()),
                    ]),
                    key.as_bytes(),
                    false,
                    CONTENT_TYPE,
                )
                .map_err(|e| unavailable(&e))?;
            let items = self.generation_items(c, generation)?;
            Ok(choose(&items)?.is_some_and(|chosen| chosen.item_path == created.item_path))
        })
    }

    fn mark(&self, generation: KeyGeneration) -> Result<(), KeyProviderError> {
        with_collection(|c| {
            let g = generation.to_string();
            let attrs = HashMap::from([
                (SERVICE_ATTR, self.service.as_str()),
                (ISSUED_ATTR, g.as_str()),
            ]);
            let existing = c.search_items(attrs.clone()).map_err(|e| unavailable(&e))?;
            if existing.is_empty() {
                c.create_item(
                    &format!("{} issued generation {generation}", self.service),
                    attrs,
                    b"issued",
                    false,
                    CONTENT_TYPE,
                )
                .map_err(|e| unavailable(&e))?;
            }
            Ok(())
        })
    }
}

impl KeyProvider for LinuxSecretServiceStore {
    /// The highest generation, creating generation 1 when the service holds none
    fn current(&self) -> Result<(KeyGeneration, Key), KeyProviderError> {
        current_of(self)
    }

    fn by_generation(&self, generation: KeyGeneration) -> Result<Key, KeyProviderError> {
        by_generation_of(self, generation)
    }
}
