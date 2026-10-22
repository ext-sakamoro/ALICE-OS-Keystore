//! Oracle for the `KeyVault` contract and the in-memory vault.
//!
//! The contract: `current` returns the highest generation and its key; `by_id`
//! returns exactly the key stored for that generation and `UnknownKey` for any
//! other; a vault that cannot hand out keys right now returns `Unavailable`.

use alice_os_keystore::{DataKey, KeyVault, MemoryVault, VaultError};

#[test]
fn current_is_the_highest_generation() {
    let v = MemoryVault::new();
    v.insert(1, DataKey::from_bytes([1; 32]));
    v.insert(3, DataKey::from_bytes([3; 32]));
    v.insert(2, DataKey::from_bytes([2; 32]));
    let (g, k) = v.current().unwrap();
    assert_eq!(g, 3);
    assert_eq!(k.as_bytes(), &[3; 32]);
}

#[test]
fn by_id_returns_the_stored_key_and_rejects_others() {
    let v = MemoryVault::new();
    v.insert(7, DataKey::from_bytes([7; 32]));
    assert_eq!(v.by_id(7).unwrap().as_bytes(), &[7; 32]);
    assert_eq!(v.by_id(8).unwrap_err(), VaultError::UnknownKey(8));
    assert_eq!(v.by_id(0).unwrap_err(), VaultError::UnknownKey(0));
}

#[test]
fn an_empty_vault_has_no_current_key() {
    let v = MemoryVault::new();
    assert!(matches!(v.current(), Err(VaultError::Unavailable(_))));
}

#[test]
fn generate_adds_a_fresh_random_key_as_the_next_generation() {
    let v = MemoryVault::new();
    let g1 = v.generate().unwrap();
    let g2 = v.generate().unwrap();
    assert_eq!((g1, g2), (1, 2));
    let (cur, k2) = v.current().unwrap();
    assert_eq!(cur, 2);
    let k1 = v.by_id(1).unwrap();
    assert_ne!(k1.as_bytes(), k2.as_bytes());
    assert_ne!(k2.as_bytes(), &[0; 32]);
}

#[test]
fn retire_removes_a_generation() {
    let v = MemoryVault::new();
    v.insert(1, DataKey::from_bytes([1; 32]));
    v.insert(2, DataKey::from_bytes([2; 32]));
    v.retire(1);
    assert_eq!(v.by_id(1).unwrap_err(), VaultError::UnknownKey(1));
    assert_eq!(v.current().unwrap().0, 2);
}

#[test]
fn a_data_key_does_not_print_its_bytes() {
    let k = DataKey::from_bytes([0xAB; 32]);
    assert_eq!(format!("{k:?}"), "DataKey(..)");
}

#[test]
fn the_trait_is_object_safe_and_shareable() {
    let v: std::sync::Arc<dyn KeyVault> = std::sync::Arc::new(MemoryVault::new());
    let w = v.clone();
    std::thread::spawn(move || w.current().is_err())
        .join()
        .unwrap();
}

#[test]
fn errors_say_what_happened() {
    assert_eq!(
        VaultError::UnknownKey(3).to_string(),
        "no data key of generation 3"
    );
    assert_eq!(
        VaultError::Unavailable("locked".into()).to_string(),
        "key store unavailable: locked"
    );
    assert_eq!(
        VaultError::InvalidKeyLength(16).to_string(),
        "key store returned 16 bytes, expected 32"
    );
}

#[test]
fn an_irrecoverable_failure_is_its_own_kind() {
    // a key that is gone or a wrapped blob that no longer opens will not succeed on retry
    let e = VaultError::Irrecoverable("enclave key missing".into());
    assert_ne!(e, VaultError::Unavailable("enclave key missing".into()));
    assert_eq!(
        e.to_string(),
        "key store cannot recover this key: enclave key missing"
    );
}

#[test]
fn from_slice_takes_exactly_32_bytes() {
    // oracle: the length rule of the type (a data key is 32 bytes), not the implementation
    let bytes: Vec<u8> = (0u8..32).collect();
    let k = DataKey::from_slice(&bytes).expect("32 bytes is a key");
    assert_eq!(k.as_bytes().as_slice(), bytes.as_slice());
    for n in [0usize, 31, 33] {
        let short_or_long = vec![0x5Au8; n];
        let e = DataKey::from_slice(&short_or_long).expect_err("only 32 bytes is a key");
        assert_eq!(e, VaultError::InvalidKeyLength(n));
        // the error names the length only, never the bytes
        assert!(!format!("{e} {e:?}").contains("5A") && !format!("{e:?}").contains("90"));
    }
}
