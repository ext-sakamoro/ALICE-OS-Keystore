//! The browser key store: `WebCrypto` keys that never leave the browser.
//!
//! A browser cannot hand out a key's bytes and keep it safe at the same time, so this store
//! does not implement [`crate::KeyProvider`] (which returns bytes). Its keys are `WebCrypto`
//! `CryptoKey`s made with `extractable: false`: neither JavaScript nor this module can read
//! them, and they keep that property when stored. The store does the operations itself,
//! through [`AsyncKeyOps`] (seal, open, MAC by generation) and its own Ed25519 methods.
//!
//! Each generation holds three keys, created together by [`WebCryptoStore::rotate`]:
//!
//! | use | algorithm | operation |
//! |---|---|---|
//! | [`KeyUse::Seal`] | AES-256-GCM | [`AsyncKeyOps::seal`] / [`AsyncKeyOps::open`] |
//! | [`KeyUse::Mac`] | HMAC-SHA-256 | [`AsyncKeyOps::mac`] |
//! | [`KeyUse::Sign`] | Ed25519 | [`WebCryptoStore::sign`] / [`WebCryptoStore::verifying_key`] |
//!
//! A sealed value is `AMS2 ‖ generation (u32 BE) ‖ nonce (12 bytes) ‖ ciphertext ‖ tag
//! (16 bytes)`; the caller's associated data is passed to AES-GCM as is, so any AES-256-GCM
//! implementation with the same key opens it. The nonce is random, so a generation seals at
//! most a fixed number of values (2³² by default, the limit NIST SP 800-38D sets for random
//! 96-bit nonces): the count is kept with the keys, survives a reload, and a generation
//! that reached it is refused for sealing until the next [`WebCryptoStore::rotate`].
//!
//! The MAC is HMAC-SHA-256 over `len(context) (u64 LE) ‖ context ‖ message`, so that two
//! (context, message) pairs with the same concatenation get different tags.
//!
//! The keys live in `IndexedDB` (database `name`, object stores `keys` and `meta`), so they are
//! bound to the page's origin and survive a reload. Clearing the site's data removes them,
//! and with them every value they sealed. A browser may also evict the data of a site that
//! is rarely used unless persistence was granted: [`WebCryptoStore::persisted`] reports it.
//! Without `IndexedDB` (some private windows) [`WebCryptoStore::open`] is
//! [`KeyProviderError::Unavailable`].
//!
//! Errors use the kinds of [`KeyProviderError`]: generation 0 and a generation that never
//! existed are `UnknownGeneration`, a removed generation is `Irrecoverable`, and a store with
//! no current key (or whose current key reached its seal limit) is `Unavailable`.

use alice_crypto::{AsyncKeyOps, KeyGeneration, KeyOpsError, KeyProviderError};
use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Crypto, CryptoKey, SubtleCrypto};
use zeroize::Zeroize;

/// The magic that starts every sealed value.
pub const SEALED_MAGIC: &[u8; 4] = b"AMS2";
/// The number of values a generation seals before it is refused (NIST SP 800-38D, random
/// 96-bit nonces).
pub const DEFAULT_SEAL_LIMIT: u64 = 1 << 32;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 4 + NONCE_LEN;

#[wasm_bindgen(inline_js = r#"
export function ks_open(factory, name) {
  return new Promise((resolve, reject) => {
    const request = factory.open(name, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("keys")) db.createObjectStore("keys");
      if (!db.objectStoreNames.contains("meta")) db.createObjectStore("meta");
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
export function ks_get(db, store, key) {
  return new Promise((resolve, reject) => {
    const request = db.transaction(store, "readonly").objectStore(store).get(key);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
export function ks_put(db, store, key, value) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}
export function ks_keys(db, store) {
  return new Promise((resolve, reject) => {
    const request = db.transaction(store, "readonly").objectStore(store).getAllKeys();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
export function ks_close(db) { db.close(); }
export function ks_delete(factory, name) {
  return new Promise((resolve, reject) => {
    const request = factory.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}
"#)]
extern "C" {
    #[wasm_bindgen(catch)]
    fn ks_open(factory: &JsValue, name: &str) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(catch)]
    fn ks_get(db: &JsValue, store: &str, key: &JsValue) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(catch)]
    fn ks_put(
        db: &JsValue,
        store: &str,
        key: &JsValue,
        value: &JsValue,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(catch)]
    fn ks_keys(db: &JsValue, store: &str) -> Result<js_sys::Promise, JsValue>;
    fn ks_close(db: &JsValue);
    #[wasm_bindgen(catch)]
    fn ks_delete(factory: &JsValue, name: &str) -> Result<js_sys::Promise, JsValue>;
}

/// Which of a generation's keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUse {
    /// The AES-256-GCM key that seals and opens.
    Seal,
    /// The HMAC-SHA-256 key.
    Mac,
    /// The Ed25519 private key.
    Sign,
}

/// Keys whose bytes the caller already has (published test vectors, a migration), taken in
/// as non-extractable keys of one generation. The bytes are zeroed when this is dropped.
pub struct KnownKeys {
    /// The generation the keys become (and the current one).
    pub generation: KeyGeneration,
    /// The AES-256-GCM key.
    pub seal: [u8; 32],
    /// The HMAC-SHA-256 key.
    pub mac: [u8; 32],
    /// An Ed25519 private key in PKCS#8; `None` makes a new one.
    pub sign_pkcs8: Option<Vec<u8>>,
}

impl Drop for KnownKeys {
    fn drop(&mut self) {
        self.seal.zeroize();
        self.mac.zeroize();
        if let Some(p) = self.sign_pkcs8.as_mut() {
            p.zeroize();
        }
    }
}

/// The keys of one generation as read from `IndexedDB`.
struct Record {
    value: JsValue,
}

impl Record {
    fn key(&self, field: &str) -> Result<CryptoKey, KeyOpsError> {
        Reflect::get(&self.value, &field.into())
            .ok()
            .and_then(|k| k.dyn_into::<CryptoKey>().ok())
            .ok_or(KeyOpsError::Key(KeyProviderError::Irrecoverable(
                "a stored key is missing or corrupt",
            )))
    }

    fn sealed(&self) -> u64 {
        Reflect::get(&self.value, &"sealed".into())
            .ok()
            .and_then(|v| v.as_f64())
            .and_then(js_integer)
            // a count that is not a count this module wrote refuses sealing
            .unwrap_or(u64::MAX)
    }

    fn public(&self) -> Result<[u8; 32], KeyOpsError> {
        let bytes = Reflect::get(&self.value, &"sign_public".into())
            .ok()
            .and_then(|v| v.dyn_into::<Uint8Array>().ok())
            .map(|a| a.to_vec());
        bytes
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .ok_or(KeyOpsError::Key(KeyProviderError::Irrecoverable(
                "the stored public key is missing or corrupt",
            )))
    }
}

/// The browser key store over one `IndexedDB` database.
pub struct WebCryptoStore {
    name: String,
    factory: JsValue,
    db: JsValue,
    crypto: Crypto,
    subtle: SubtleCrypto,
    seal_limit: u64,
}

fn unavailable(why: &'static str) -> KeyOpsError {
    KeyOpsError::Key(KeyProviderError::Unavailable(why))
}

async fn wait(
    p: Result<js_sys::Promise, JsValue>,
    why: &'static str,
) -> Result<JsValue, KeyOpsError> {
    let p = p.map_err(|_| unavailable(why))?;
    JsFuture::from(p).await.map_err(|_| unavailable(why))
}

/// The largest integer a JavaScript number holds exactly (2^53).
const JS_EXACT: u64 = 1 << 53;

/// A JavaScript number this module wrote as a non-negative integer below 2^53, read back.
fn js_integer(v: f64) -> Option<u64> {
    // every value in this range is an exact integer of f64, so the cast is exact
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let n = v as u64;
    (v.fract() == 0.0 && (0.0..9_007_199_254_740_992.0).contains(&v)).then_some(n)
}

/// A generation read back from `IndexedDB`.
fn js_generation(v: f64) -> Option<KeyGeneration> {
    js_integer(v).and_then(|n| KeyGeneration::try_from(n).ok())
}

/// A count below 2^53 as a JavaScript number (exact).
fn js_number(n: u64) -> JsValue {
    debug_assert!(n < JS_EXACT);
    #[allow(clippy::cast_precision_loss)]
    JsValue::from(n.min(JS_EXACT - 1) as f64)
}

fn global_property(name: &str) -> Option<JsValue> {
    Reflect::get(&js_sys::global(), &name.into())
        .ok()
        .filter(|v| !v.is_undefined() && !v.is_null())
}

fn object(fields: &[(&str, JsValue)]) -> Object {
    let o = Object::new();
    for (k, v) in fields {
        // setting a property of a fresh plain object does not fail
        let _ = Reflect::set(&o, &(*k).into(), v);
    }
    o
}

fn usages(names: &[&str]) -> JsValue {
    names
        .iter()
        .map(|n| JsValue::from_str(n))
        .collect::<Array>()
        .into()
}

fn bytes(b: &[u8]) -> Uint8Array {
    Uint8Array::from(b)
}

fn to_bytes(v: &JsValue) -> Vec<u8> {
    Uint8Array::new(v).to_vec()
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits).to_le_bytes()[0]);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

impl WebCryptoStore {
    /// The store over database `name`, created if it does not exist.
    ///
    /// # Errors
    ///
    /// [`KeyProviderError::Unavailable`] when the page has no `IndexedDB` or no `WebCrypto`, or
    /// the database does not open.
    pub async fn open(name: &str) -> Result<Self, KeyOpsError> {
        Self::open_with_seal_limit(name, DEFAULT_SEAL_LIMIT).await
    }

    /// [`Self::open`] with a generation sealing at most `limit` values (tests use a small one).
    ///
    /// # Errors
    ///
    /// As [`Self::open`].
    pub async fn open_with_seal_limit(name: &str, limit: u64) -> Result<Self, KeyOpsError> {
        let factory =
            global_property("indexedDB").ok_or(unavailable("IndexedDB is not available"))?;
        let crypto = global_property("crypto")
            .and_then(|c| c.dyn_into::<Crypto>().ok())
            .ok_or(unavailable("WebCrypto is not available"))?;
        let subtle = crypto.subtle();
        let db = wait(ks_open(&factory, name), "IndexedDB did not open").await?;
        Ok(Self {
            name: name.to_owned(),
            factory,
            db,
            crypto,
            subtle,
            // counts are kept as JavaScript numbers, exact below 2^53
            seal_limit: limit.min(JS_EXACT - 1),
        })
    }

    /// A store over database `name` whose generation `keys.generation` holds the given keys
    /// (as non-extractable keys) and is the current one.
    ///
    /// # Errors
    ///
    /// As [`Self::open`], [`KeyProviderError::UnknownGeneration`] for generation 0, and
    /// [`KeyProviderError::Unavailable`] when the browser refuses a key.
    pub async fn import_known(name: &str, keys: KnownKeys) -> Result<Self, KeyOpsError> {
        if keys.generation == 0 {
            return Err(KeyOpsError::Key(KeyProviderError::UnknownGeneration(0)));
        }
        let store = Self::open(name).await?;
        let seal = store
            .import_raw(
                &keys.seal,
                &object(&[("name", "AES-GCM".into())]),
                &["encrypt", "decrypt"],
            )
            .await?;
        let mac = store
            .import_raw(
                &keys.mac,
                &object(&[("name", "HMAC".into()), ("hash", "SHA-256".into())]),
                &["sign", "verify"],
            )
            .await?;
        let (sign, public) = match &keys.sign_pkcs8 {
            Some(pkcs8) => store.import_ed25519(pkcs8).await?,
            None => store.generate_ed25519().await?,
        };
        store
            .put_generation(keys.generation, &seal, &mac, &sign, &public)
            .await?;
        store.set_current(keys.generation).await?;
        Ok(store)
    }

    /// Adds the next generation (new non-extractable keys) and makes it the current one.
    ///
    /// # Errors
    ///
    /// [`KeyProviderError::Unavailable`] when the browser cannot make or store the keys.
    pub async fn rotate(&self) -> Result<KeyGeneration, KeyOpsError> {
        let existing = wait(ks_keys(&self.db, "keys"), "IndexedDB read failed").await?;
        let last = Array::from(&existing)
            .iter()
            .filter_map(|k| k.as_f64().and_then(js_generation))
            .max()
            .unwrap_or(0);
        let next = last
            .checked_add(1)
            .ok_or(unavailable("no generation is left"))?;
        let seal = self
            .generate(
                &object(&[("name", "AES-GCM".into()), ("length", 256.into())]),
                &["encrypt", "decrypt"],
            )
            .await?;
        let mac = self
            .generate(
                &object(&[("name", "HMAC".into()), ("hash", "SHA-256".into())]),
                &["sign", "verify"],
            )
            .await?;
        let (sign, public) = self.generate_ed25519().await?;
        self.put_generation(next, &seal, &mac, &sign, &public)
            .await?;
        self.set_current(next).await?;
        Ok(next)
    }

    /// Removes the keys of generation `g`: what they sealed no longer opens, and the
    /// generation reports [`KeyProviderError::Irrecoverable`] from then on.
    ///
    /// # Errors
    ///
    /// [`KeyProviderError::Unavailable`] when `IndexedDB` fails.
    pub async fn remove(&self, g: KeyGeneration) -> Result<(), KeyOpsError> {
        let tombstone = object(&[("removed", true.into())]);
        wait(
            ks_put(&self.db, "keys", &JsValue::from(g), &tombstone),
            "IndexedDB write failed",
        )
        .await?;
        Ok(())
    }

    /// One key of generation `g` (it stays non-extractable).
    ///
    /// # Errors
    ///
    /// The generation errors of the module documentation.
    pub async fn crypto_key(
        &self,
        g: KeyGeneration,
        kind: KeyUse,
    ) -> Result<CryptoKey, KeyOpsError> {
        let record = self.record(g).await?;
        record.key(match kind {
            KeyUse::Seal => "seal",
            KeyUse::Mac => "mac",
            KeyUse::Sign => "sign",
        })
    }

    /// The Ed25519 signature of `message` with generation `g`'s key.
    ///
    /// # Errors
    ///
    /// The generation errors of the module documentation, [`KeyProviderError::Unavailable`]
    /// when the browser does not sign.
    pub async fn sign(&self, g: KeyGeneration, message: &[u8]) -> Result<[u8; 64], KeyOpsError> {
        let key = self.crypto_key(g, KeyUse::Sign).await?;
        let sig = wait(
            self.subtle.sign_with_object_and_js_u8_array(
                &object(&[("name", "Ed25519".into())]),
                &key,
                &bytes(message),
            ),
            "Ed25519 signing failed",
        )
        .await?;
        <[u8; 64]>::try_from(to_bytes(&sig).as_slice())
            .map_err(|_| unavailable("Ed25519 signing failed"))
    }

    /// The Ed25519 public key of generation `g`.
    ///
    /// # Errors
    ///
    /// The generation errors of the module documentation.
    pub async fn verifying_key(&self, g: KeyGeneration) -> Result<[u8; 32], KeyOpsError> {
        self.record(g).await?.public()
    }

    /// Whether `signature` is an Ed25519 signature of `message` under `public` (strict, as
    /// `WebCrypto` verifies).
    ///
    /// # Errors
    ///
    /// [`KeyProviderError::Unavailable`] when the page has no `WebCrypto` Ed25519.
    pub async fn verify(
        public: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<bool, KeyOpsError> {
        let subtle = global_property("crypto")
            .and_then(|c| c.dyn_into::<Crypto>().ok())
            .ok_or(unavailable("WebCrypto is not available"))?
            .subtle();
        let alg = object(&[("name", "Ed25519".into())]);
        let key = wait(
            subtle.import_key_with_object("raw", &bytes(public), &alg, true, &usages(&["verify"])),
            "the public key was refused",
        )
        .await?
        .unchecked_into::<CryptoKey>();
        let ok = wait(
            subtle.verify_with_object_and_js_u8_array_and_js_u8_array(
                &alg,
                &key,
                &bytes(signature),
                &bytes(message),
            ),
            "Ed25519 verification failed",
        )
        .await?;
        Ok(ok.as_bool() == Some(true))
    }

    /// Whether the browser granted this origin persistent storage (without it, the keys may
    /// be evicted when the device runs short of space). Asking for it is the page's choice
    /// (`navigator.storage.persist()`), as some browsers prompt.
    pub async fn persisted(&self) -> bool {
        let Some(storage) = global_property("navigator")
            .and_then(|n| Reflect::get(&n, &"storage".into()).ok())
            .filter(|s| !s.is_undefined())
        else {
            return false;
        };
        let Some(f) = Reflect::get(&storage, &"persisted".into())
            .ok()
            .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
        else {
            return false;
        };
        match f.call0(&storage).map(JsCast::dyn_into::<js_sys::Promise>) {
            Ok(Ok(p)) => {
                JsFuture::from(p)
                    .await
                    .ok()
                    .and_then(|v| JsValue::as_bool(&v))
                    == Some(true)
            }
            _ => false,
        }
    }

    /// Closes the database connection (the keys stay in `IndexedDB`).
    pub fn close(self) {
        ks_close(&self.db);
    }

    /// Closes the connection and deletes the database with every key in it.
    ///
    /// # Errors
    ///
    /// [`KeyProviderError::Unavailable`] when `IndexedDB` refuses.
    pub async fn delete_database(self) -> Result<(), KeyOpsError> {
        ks_close(&self.db);
        wait(
            ks_delete(&self.factory, &self.name),
            "IndexedDB did not delete the database",
        )
        .await?;
        Ok(())
    }

    async fn record(&self, g: KeyGeneration) -> Result<Record, KeyOpsError> {
        if g == 0 {
            return Err(KeyOpsError::Key(KeyProviderError::UnknownGeneration(0)));
        }
        let value = wait(
            ks_get(&self.db, "keys", &JsValue::from(g)),
            "IndexedDB read failed",
        )
        .await?;
        if value.is_undefined() || value.is_null() {
            return Err(KeyOpsError::Key(KeyProviderError::UnknownGeneration(g)));
        }
        if Reflect::get(&value, &"removed".into())
            .ok()
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Err(KeyOpsError::Key(KeyProviderError::Irrecoverable(
                "the generation was removed",
            )));
        }
        Ok(Record { value })
    }

    async fn set_current(&self, g: KeyGeneration) -> Result<(), KeyOpsError> {
        wait(
            ks_put(&self.db, "meta", &"current".into(), &JsValue::from(g)),
            "IndexedDB write failed",
        )
        .await?;
        Ok(())
    }

    async fn put_generation(
        &self,
        g: KeyGeneration,
        seal: &CryptoKey,
        mac: &CryptoKey,
        sign: &CryptoKey,
        public: &[u8; 32],
    ) -> Result<(), KeyOpsError> {
        let value = object(&[
            ("seal", seal.into()),
            ("mac", mac.into()),
            ("sign", sign.into()),
            ("sign_public", bytes(public).into()),
            ("sealed", JsValue::from(0)),
        ]);
        wait(
            ks_put(&self.db, "keys", &JsValue::from(g), &value),
            "IndexedDB write failed",
        )
        .await?;
        Ok(())
    }

    async fn generate(&self, alg: &Object, uses: &[&str]) -> Result<CryptoKey, KeyOpsError> {
        Ok(wait(
            self.subtle
                .generate_key_with_object(alg, false, &usages(uses)),
            "the browser did not make a key",
        )
        .await?
        .unchecked_into())
    }

    async fn import_raw(
        &self,
        raw: &[u8; 32],
        alg: &Object,
        uses: &[&str],
    ) -> Result<CryptoKey, KeyOpsError> {
        let data = bytes(raw);
        let key = wait(
            self.subtle
                .import_key_with_object("raw", &data, alg, false, &usages(uses)),
            "the browser refused the key",
        )
        .await;
        data.fill(0, 0, 32);
        Ok(key?.unchecked_into())
    }

    async fn generate_ed25519(&self) -> Result<(CryptoKey, [u8; 32]), KeyOpsError> {
        let pair = wait(
            self.subtle.generate_key_with_object(
                &object(&[("name", "Ed25519".into())]),
                false,
                &usages(&["sign", "verify"]),
            ),
            "the browser did not make an Ed25519 key",
        )
        .await?;
        let private = Reflect::get(&pair, &"privateKey".into())
            .ok()
            .and_then(|k| k.dyn_into::<CryptoKey>().ok())
            .ok_or(unavailable("the browser did not make an Ed25519 key"))?;
        let public = Reflect::get(&pair, &"publicKey".into())
            .ok()
            .and_then(|k| k.dyn_into::<CryptoKey>().ok())
            .ok_or(unavailable("the browser did not make an Ed25519 key"))?;
        // a public key is always extractable
        let raw = wait(
            self.subtle.export_key("raw", &public),
            "the public key did not export",
        )
        .await?;
        let raw = <[u8; 32]>::try_from(to_bytes(&raw).as_slice())
            .map_err(|_| unavailable("the public key did not export"))?;
        Ok((private, raw))
    }

    /// Takes a PKCS#8 Ed25519 key the caller already holds: once as extractable to read its
    /// public half (the bytes are the caller's already), then as the non-extractable key kept.
    async fn import_ed25519(&self, pkcs8: &[u8]) -> Result<(CryptoKey, [u8; 32]), KeyOpsError> {
        let alg = object(&[("name", "Ed25519".into())]);
        let data = bytes(pkcs8);
        let readable = wait(
            self.subtle
                .import_key_with_object("pkcs8", &data, &alg, true, &usages(&["sign"])),
            "the browser refused the Ed25519 key",
        )
        .await?
        .unchecked_into::<CryptoKey>();
        let jwk = wait(
            self.subtle.export_key("jwk", &readable),
            "the Ed25519 key did not export",
        )
        .await?;
        let x = Reflect::get(&jwk, &"x".into())
            .ok()
            .and_then(|x| x.as_string())
            .and_then(|x| base64url_decode(&x))
            .and_then(|x| <[u8; 32]>::try_from(x.as_slice()).ok())
            .ok_or(unavailable("the Ed25519 key did not export"))?;
        let kept = wait(
            self.subtle
                .import_key_with_object("pkcs8", &data, &alg, false, &usages(&["sign"])),
            "the browser refused the Ed25519 key",
        )
        .await;
        data.fill(0, 0, data.length());
        Ok((kept?.unchecked_into(), x))
    }

    async fn current(&self) -> Result<KeyGeneration, KeyOpsError> {
        let v = wait(
            ks_get(&self.db, "meta", &"current".into()),
            "IndexedDB read failed",
        )
        .await?;
        let g = v
            .as_f64()
            .and_then(js_generation)
            .ok_or(unavailable("no current key yet"))?;
        let record = self
            .record(g)
            .await
            .map_err(|_| unavailable("the current key is gone"))?;
        if record.sealed() >= self.seal_limit {
            return Err(unavailable("the current key reached its seal limit"));
        }
        Ok(g)
    }

    async fn seal_value(
        &self,
        g: KeyGeneration,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyOpsError> {
        let record = self.record(g).await?;
        let sealed = record.sealed();
        if sealed >= self.seal_limit {
            return Err(unavailable("the key reached its seal limit"));
        }
        // count before sealing: a crash after the count wastes one, it never reuses one
        let next = sealed + 1;
        Reflect::set(&record.value, &"sealed".into(), &js_number(next))
            .map_err(|_| KeyOpsError::Seal)?;
        wait(
            ks_put(&self.db, "keys", &JsValue::from(g), &record.value),
            "IndexedDB write failed",
        )
        .await?;
        let key = record.key("seal")?;
        let mut nonce = [0u8; NONCE_LEN];
        self.crypto
            .get_random_values_with_u8_array(&mut nonce)
            .map_err(|_| KeyOpsError::Seal)?;
        let alg = object(&[
            ("name", "AES-GCM".into()),
            ("iv", bytes(&nonce).into()),
            ("additionalData", bytes(aad).into()),
            ("tagLength", 128.into()),
        ]);
        let body = JsFuture::from(
            self.subtle
                .encrypt_with_object_and_js_u8_array(&alg, &key, &bytes(plaintext))
                .map_err(|_| KeyOpsError::Seal)?,
        )
        .await
        .map_err(|_| KeyOpsError::Seal)?;
        let body = to_bytes(&body);
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(SEALED_MAGIC);
        out.extend_from_slice(&g.to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        Ok(out)
    }

    async fn open_value(
        &self,
        g: KeyGeneration,
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, KeyOpsError> {
        let key = self.record(g).await?.key("seal")?;
        if sealed.len() < HEADER_LEN + TAG_LEN
            || &sealed[..4] != SEALED_MAGIC
            || sealed[4..8] != g.to_be_bytes()
        {
            return Err(KeyOpsError::Open);
        }
        let alg = object(&[
            ("name", "AES-GCM".into()),
            ("iv", bytes(&sealed[8..HEADER_LEN]).into()),
            ("additionalData", bytes(aad).into()),
            ("tagLength", 128.into()),
        ]);
        let plain = JsFuture::from(
            self.subtle
                .decrypt_with_object_and_js_u8_array(&alg, &key, &bytes(&sealed[HEADER_LEN..]))
                .map_err(|_| KeyOpsError::Open)?,
        )
        .await
        .map_err(|_| KeyOpsError::Open)?;
        Ok(to_bytes(&plain))
    }

    async fn mac_value(
        &self,
        g: KeyGeneration,
        context: &[u8],
        message: &[u8],
    ) -> Result<[u8; 32], KeyOpsError> {
        let key = self.record(g).await?.key("mac")?;
        let mut input = Vec::with_capacity(8 + context.len() + message.len());
        input.extend_from_slice(&(context.len() as u64).to_le_bytes());
        input.extend_from_slice(context);
        input.extend_from_slice(message);
        let tag = wait(
            self.subtle.sign_with_object_and_js_u8_array(
                &object(&[("name", "HMAC".into())]),
                &key,
                &bytes(&input),
            ),
            "HMAC failed",
        )
        .await?;
        <[u8; 32]>::try_from(to_bytes(&tag).as_slice()).map_err(|_| unavailable("HMAC failed"))
    }
}

impl AsyncKeyOps for WebCryptoStore {
    async fn current_generation(&self) -> Result<KeyGeneration, KeyOpsError> {
        self.current().await
    }

    async fn seal(
        &self,
        generation: KeyGeneration,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyOpsError> {
        self.seal_value(generation, aad, plaintext).await
    }

    async fn open(
        &self,
        generation: KeyGeneration,
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, KeyOpsError> {
        self.open_value(generation, aad, sealed).await
    }

    async fn mac(
        &self,
        generation: KeyGeneration,
        context: &[u8],
        message: &[u8],
    ) -> Result<[u8; 32], KeyOpsError> {
        self.mac_value(generation, context, message).await
    }
}
