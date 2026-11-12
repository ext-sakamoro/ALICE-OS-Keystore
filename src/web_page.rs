//! A page-facing face of [`crate::web::WebCryptoStore`] (feature `web-page`): JavaScript
//! functions over one store at a time, for a page that keeps its keys across reloads. The
//! browser reload test (`tests/web/reload.spec.mjs`) drives these from a real page.
//!
//! Text is sealed as UTF-8 under the current generation; [`open`] reads the generation from
//! the sealed value's header.

use std::cell::RefCell;
use std::rc::Rc;

use alice_crypto::{AsyncKeyOps, KeyOpsError};
use js_sys::{Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

use crate::web::{KeyUse, WebCryptoStore};

thread_local! {
    static STORE: RefCell<Option<Rc<WebCryptoStore>>> = const { RefCell::new(None) };
}

fn err(e: KeyOpsError) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn store() -> Result<Rc<WebCryptoStore>, JsValue> {
    STORE
        .with(|s| s.borrow().clone())
        .ok_or_else(|| JsValue::from_str("no store attached"))
}

fn replace(next: Option<Rc<WebCryptoStore>>) {
    let previous = STORE.with(|s| s.replace(next));
    if let Some(Ok(previous)) = previous.map(Rc::try_unwrap) {
        previous.close();
    }
}

/// Deletes database `name` with its keys and attaches an empty store over it.
///
/// # Errors
///
/// The store's error, as text.
#[wasm_bindgen]
pub async fn reset(name: String) -> Result<(), JsValue> {
    replace(None);
    WebCryptoStore::open(&name)
        .await
        .map_err(err)?
        .delete_database()
        .await
        .map_err(err)?;
    attach(name).await
}

/// Attaches the store over database `name` (created if missing).
///
/// # Errors
///
/// The store's error, as text.
#[wasm_bindgen]
pub async fn attach(name: String) -> Result<(), JsValue> {
    let opened = WebCryptoStore::open(&name).await.map_err(err)?;
    replace(Some(Rc::new(opened)));
    Ok(())
}

/// Adds a generation and returns it.
///
/// # Errors
///
/// The store's error, as text.
#[wasm_bindgen]
pub async fn rotate() -> Result<u32, JsValue> {
    store()?.rotate().await.map_err(err)
}

/// `text` sealed under the current generation, bound to `aad`.
///
/// # Errors
///
/// The store's error, as text.
#[wasm_bindgen]
pub async fn seal(aad: String, text: String) -> Result<Uint8Array, JsValue> {
    let s = store()?;
    let g = s.current_generation().await.map_err(err)?;
    let sealed = s
        .seal(g, aad.as_bytes(), text.as_bytes())
        .await
        .map_err(err)?;
    Ok(Uint8Array::from(sealed.as_slice()))
}

/// The text of a value [`seal`] made with `aad`.
///
/// # Errors
///
/// The store's error, as text, or a value too short to carry a generation, or text that
/// is not UTF-8.
#[wasm_bindgen]
pub async fn open(aad: String, sealed: Vec<u8>) -> Result<String, JsValue> {
    let g = sealed
        .get(4..8)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| JsValue::from_str("not a sealed value"))?;
    let plain = store()?
        .open(g, aad.as_bytes(), &sealed)
        .await
        .map_err(err)?;
    String::from_utf8(plain).map_err(|_| JsValue::from_str("the opened value is not UTF-8"))
}

/// Whether any key of the current generation is extractable (it never should be).
///
/// # Errors
///
/// The store's error, as text.
#[wasm_bindgen(js_name = anyKeyExtractable)]
pub async fn any_key_extractable() -> Result<bool, JsValue> {
    let s = store()?;
    let g = s.current_generation().await.map_err(err)?;
    let mut any = false;
    for kind in [KeyUse::Seal, KeyUse::Mac, KeyUse::Sign] {
        let key = s.crypto_key(g, kind).await.map_err(err)?;
        any |= Reflect::get(&key, &"extractable".into())
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
    }
    Ok(any)
}
