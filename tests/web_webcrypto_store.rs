//! The browser key store: WebCrypto keys that never leave the browser, kept across a
//! reload in IndexedDB, used by generation to seal, open, authenticate and sign.
//!
//! Red by design until `web::WebCryptoStore` exists (the store and the operation trait
//! it implements are not built yet): this file pins the contract first.
//!
//! Runs only in a browser (`wasm-pack test --headless --chrome --firefox -- --features web`);
//! the count of passed tests is checked by `scripts/web_test_count.py`, which fails on 0.
//!
//! Oracles (each against something outside the store):
//! 1. non-extractable: `extractable` is false and `exportKey` rejects, also for the key
//!    read back from IndexedDB;
//! 2. sealing: the independent `aes-gcm` crate opens what the store sealed under a known key,
//!    and the store opens what `aes-gcm` sealed;
//! 3. signing: RFC 8032 §7.1 test 1 (an empty message) gives the published signature,
//!    `ed25519-dalek` and `alice-sign` verify the store's signature on another message, and
//!    the store verifies `alice-sign`'s signature made from the same seed;
//! 4. tampering with the tag, the associated data or the generation makes `open` fail;
//! 5. generations: after a rotation the current generation is the new one and the old one
//!    still opens; generation 0 and an unknown one are `UnknownGeneration`, a removed one is
//!    `Irrecoverable`;
//! 6. a generation that reached its seal limit is not used for sealing any more;
//! 7. persistence: after closing the database and dropping every handle, a fresh `open`
//!    of the same database opens what was sealed before (the reload itself is
//!    `tests/web/reload.spec.mjs`);
//! 8. no IndexedDB, or a refused persistence request, is `Unavailable`, not a panic.

#![cfg(all(target_arch = "wasm32", feature = "web"))]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use alice_os_keystore::web::{KeyUse, KnownKeys, WebCryptoStore};
use alice_os_keystore::{AsyncKeyOps, KeyGeneration, KeyOpsError, KeyProviderError};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// A database name of its own for each test, so the tests do not see each other's keys.
fn db(name: &str) -> String {
    format!("alice-os-keystore-test-{name}")
}

/// Seal under the current generation, as a consumer does: ask for it, then seal under it.
async fn seal_now(
    store: &WebCryptoStore,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(KeyGeneration, Vec<u8>), KeyOpsError> {
    let g = store.current_generation().await?;
    Ok((g, store.seal(g, aad, plaintext).await?))
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// The AMS2 layout as the design fixes it: magic, generation (u32 BE), 96-bit nonce, then
/// the AES-256-GCM ciphertext with its 16-byte tag.
fn split_sealed(sealed: &[u8]) -> (u32, [u8; 12], &[u8]) {
    assert_eq!(
        &sealed[..4],
        b"AMS2",
        "the sealed value starts with the AMS2 magic"
    );
    let generation = u32::from_be_bytes(sealed[4..8].try_into().expect("4 bytes"));
    let nonce: [u8; 12] = sealed[8..20].try_into().expect("12 bytes");
    (generation, nonce, &sealed[20..])
}

// RFC 8032 §7.1, test 1
const RFC8032_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC8032_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RFC8032_SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

/// Oracle 1: no key of the store can be exported, before or after IndexedDB.
#[wasm_bindgen_test]
async fn the_keys_cannot_be_exported_before_or_after_indexeddb() {
    let store = WebCryptoStore::open(&db("export")).await.expect("open");
    let g = store.rotate().await.expect("rotate");
    for kind in [KeyUse::Seal, KeyUse::Mac, KeyUse::Sign] {
        let key = store.crypto_key(g, kind).await.expect("key");
        assert!(!key.extractable(), "{kind:?} is extractable");
        let subtle = web_sys::window()
            .expect("window")
            .crypto()
            .expect("crypto")
            .subtle();
        for format in ["raw", "jwk", "pkcs8"] {
            let refused = JsFuture::from(subtle.export_key(format, &key).expect("promise")).await;
            let err = refused.expect_err("exportKey must reject");
            let name = err
                .dyn_ref::<web_sys::DomException>()
                .map(web_sys::DomException::name);
            assert!(
                matches!(
                    name.as_deref(),
                    Some("InvalidAccessError" | "NotSupportedError")
                ),
                "{kind:?} {format}: {name:?}"
            );
        }
    }
    store.close();
    let reopened = WebCryptoStore::open(&db("export")).await.expect("reopen");
    for kind in [KeyUse::Seal, KeyUse::Mac, KeyUse::Sign] {
        let key = reopened.crypto_key(g, kind).await.expect("key read back");
        assert!(
            !key.extractable(),
            "{kind:?} became extractable in IndexedDB"
        );
    }
    reopened.delete_database().await.expect("cleanup");
}

/// Oracle 2: the store and the independent `aes-gcm` crate open each other's values.
#[wasm_bindgen_test]
async fn the_store_and_an_independent_aes_gcm_open_each_others_values() {
    let key = [0x42u8; 32];
    let store = WebCryptoStore::import_known(
        &db("aes"),
        KnownKeys {
            generation: 1,
            seal: key,
            mac: [0x24; 32],
            sign_pkcs8: None,
        },
    )
    .await
    .expect("import");
    let aad = b"the associated data";
    let message = b"a value the store seals";
    let (g, sealed) = seal_now(&store, aad, message).await.expect("seal");
    let (stored_g, nonce, body) = split_sealed(&sealed);
    assert_eq!((g, stored_g), (1, 1));
    let reference = Aes256Gcm::new_from_slice(&key).expect("key");
    let opened = reference
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: body, aad })
        .expect("aes-gcm opens the store's value");
    assert_eq!(opened, message);

    let theirs = reference
        .encrypt(
            Nonce::from_slice(&[7u8; 12]),
            Payload {
                msg: b"sealed elsewhere",
                aad,
            },
        )
        .expect("encrypt");
    let mut framed = b"AMS2".to_vec();
    framed.extend(1u32.to_be_bytes());
    framed.extend([7u8; 12]);
    framed.extend(&theirs);
    assert_eq!(
        store.open(1, aad, &framed).await.expect("open"),
        b"sealed elsewhere"
    );
    store.delete_database().await.expect("cleanup");
}

/// Oracle 3: RFC 8032 test 1, and an independent verifier.
#[wasm_bindgen_test]
async fn ed25519_signs_the_rfc8032_vector_and_dalek_verifies() {
    // PKCS#8 v1 for Ed25519: the fixed 16-byte prefix, then the 32-byte seed
    let mut pkcs8 = hex("302e020100300506032b657004220420");
    pkcs8.extend(hex(RFC8032_SECRET));
    let store = WebCryptoStore::import_known(
        &db("sign"),
        KnownKeys {
            generation: 1,
            seal: [1; 32],
            mac: [2; 32],
            sign_pkcs8: Some(pkcs8),
        },
    )
    .await
    .expect("import");
    assert_eq!(
        store.verifying_key(1).await.expect("public").to_vec(),
        hex(RFC8032_PUBLIC)
    );
    assert_eq!(
        store.sign(1, b"").await.expect("sign").to_vec(),
        hex(RFC8032_SIG)
    );

    let message = b"another message";
    let signature = store.sign(1, message).await.expect("sign");
    let public: [u8; 32] = hex(RFC8032_PUBLIC).try_into().expect("32");
    let verifier = ed25519_dalek::VerifyingKey::from_bytes(&public).expect("public key");
    verifier
        .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
        .expect("dalek verifies the store's signature");

    // the native identity stack: alice-sign from the same seed has the same public key, its
    // verifier accepts the store's signature, and the store accepts alice-sign's signature
    let seed: [u8; 32] = hex(RFC8032_SECRET).try_into().expect("32");
    let native = alice_sign::KeyPair::from_seed(seed);
    assert_eq!(native.public().0, public);
    assert!(
        native
            .public()
            .verify_strict(message, &alice_sign::Signature(signature)),
        "alice-sign rejects the store's signature"
    );
    let native_signature = native.sign(b"signed natively");
    assert!(
        WebCryptoStore::verify(&public, b"signed natively", &native_signature.0)
            .await
            .expect("verify"),
        "the store rejects alice-sign's signature"
    );
    assert!(
        !WebCryptoStore::verify(&public, b"signed nativelY", &native_signature.0)
            .await
            .expect("verify"),
        "the store accepts a signature over another message"
    );
    store.delete_database().await.expect("cleanup");
}

/// Oracle 4: a changed tag, associated data or generation does not open.
#[wasm_bindgen_test]
async fn tampered_values_do_not_open() {
    let store = WebCryptoStore::open(&db("tamper")).await.expect("open");
    let g1 = store.rotate().await.expect("rotate");
    let g2 = store.rotate().await.expect("rotate");
    let (g, sealed) = seal_now(&store, b"aad", b"secret").await.expect("seal");
    assert_eq!(g, g2);
    let mut tag = sealed.clone();
    *tag.last_mut().expect("tag") ^= 1;
    assert!(
        store.open(g, b"aad", &tag).await.is_err(),
        "a changed tag opened"
    );
    assert!(
        store.open(g, b"aaD", &sealed).await.is_err(),
        "other associated data opened"
    );
    assert!(
        store.open(g1, b"aad", &sealed).await.is_err(),
        "another generation opened"
    );
    let mut renamed = sealed.clone();
    renamed[4..8].copy_from_slice(&g1.to_be_bytes());
    assert!(
        store.open(g1, b"aad", &renamed).await.is_err(),
        "a relabelled value opened"
    );
    assert_eq!(
        store.open(g, b"aad", &sealed).await.expect("open"),
        b"secret"
    );
    store.delete_database().await.expect("cleanup");
}

/// Oracle 5: rotation keeps old generations readable, and the error kinds are those of
/// `KeyProvider`.
#[wasm_bindgen_test]
async fn generations_rotate_and_report_the_key_provider_errors() {
    let store = WebCryptoStore::open(&db("generations"))
        .await
        .expect("open");
    assert!(matches!(
        seal_now(&store, b"", b"x").await,
        Err(KeyOpsError::Key(KeyProviderError::Unavailable(_)))
    ));
    let g1 = store.rotate().await.expect("rotate");
    let (_, old) = seal_now(&store, b"", b"old").await.expect("seal");
    let g2 = store.rotate().await.expect("rotate");
    assert_eq!(g2, g1 + 1);
    let (current, _) = seal_now(&store, b"", b"new").await.expect("seal");
    assert_eq!(current, g2);
    assert_eq!(store.open(g1, b"", &old).await.expect("old opens"), b"old");
    assert_eq!(
        store.open(0, b"", &old).await,
        Err(KeyOpsError::Key(KeyProviderError::UnknownGeneration(0)))
    );
    assert_eq!(
        store.open(g2 + 5, b"", &old).await,
        Err(KeyOpsError::Key(KeyProviderError::UnknownGeneration(
            g2 + 5
        )))
    );
    store.remove(g1).await.expect("remove");
    assert!(matches!(
        store.open(g1, b"", &old).await,
        Err(KeyOpsError::Key(KeyProviderError::Irrecoverable(_)))
    ));
    store.delete_database().await.expect("cleanup");
}

/// Oracle 6: a generation that reached its seal limit is not sealed with again, and the
/// count survives reopening the database.
#[wasm_bindgen_test]
async fn a_generation_stops_sealing_at_its_limit_across_a_reopen() {
    let store = WebCryptoStore::open_with_seal_limit(&db("limit"), 3)
        .await
        .expect("open");
    let g1 = store.rotate().await.expect("rotate");
    for _ in 0..2 {
        assert_eq!(seal_now(&store, b"", b"x").await.expect("seal").0, g1);
    }
    store.close();
    let store = WebCryptoStore::open_with_seal_limit(&db("limit"), 3)
        .await
        .expect("reopen");
    assert_eq!(seal_now(&store, b"", b"x").await.expect("third seal").0, g1);
    assert!(
        matches!(
            seal_now(&store, b"", b"x").await,
            Err(KeyOpsError::Key(KeyProviderError::Unavailable(_)))
        ),
        "a fourth seal under the same generation"
    );
    let g2 = store.rotate().await.expect("rotate");
    assert_eq!(seal_now(&store, b"", b"x").await.expect("seal").0, g2);
    store.delete_database().await.expect("cleanup");
}

/// Oracle 7: a fresh store over the same database opens what an earlier one sealed, once
/// every handle of the earlier one is gone.
#[wasm_bindgen_test]
async fn a_reopened_database_opens_what_was_sealed_before() {
    let (g, sealed, tag) = {
        let store = WebCryptoStore::open(&db("reopen")).await.expect("open");
        store.rotate().await.expect("rotate");
        let (g, sealed) = seal_now(&store, b"aad", b"kept across a reload")
            .await
            .expect("seal");
        let tag = store.mac(g, b"ctx", b"name").await.expect("mac");
        store.close();
        (g, sealed, tag)
    };
    let store = WebCryptoStore::open(&db("reopen")).await.expect("reopen");
    assert_eq!(
        store.open(g, b"aad", &sealed).await.expect("open"),
        b"kept across a reload"
    );
    assert_eq!(
        store.mac(g, b"ctx", b"name").await.expect("mac"),
        tag,
        "the MAC key persisted"
    );
    store.delete_database().await.expect("cleanup");
}

/// Oracle 8: without IndexedDB the store is unavailable, and says so.
#[wasm_bindgen_test]
async fn no_indexeddb_is_unavailable_not_a_panic() {
    let global = js_sys::global();
    let saved = js_sys::Reflect::get(&global, &"indexedDB".into()).expect("read");
    // shadow the property for this test only (a private window may have none)
    js_sys::Reflect::define_property(
        &global.clone().unchecked_into(),
        &"indexedDB".into(),
        &js_sys::Object::from_entries(&js_sys::Array::of2(
            &js_sys::Array::of2(&"value".into(), &wasm_bindgen::JsValue::UNDEFINED),
            &js_sys::Array::of2(&"configurable".into(), &true.into()),
        ))
        .expect("descriptor"),
    );
    let result = WebCryptoStore::open(&db("none")).await;
    js_sys::Reflect::define_property(
        &global.clone().unchecked_into(),
        &"indexedDB".into(),
        &js_sys::Object::from_entries(&js_sys::Array::of2(
            &js_sys::Array::of2(&"value".into(), &saved),
            &js_sys::Array::of2(&"configurable".into(), &true.into()),
        ))
        .expect("descriptor"),
    );
    assert!(
        matches!(
            result,
            Err(KeyOpsError::Key(KeyProviderError::Unavailable(_)))
        ),
        "{:?}",
        result.err()
    );
}
