//! Oracle for the key provider contract (`alice_crypto::KeyProvider`) and the in-memory store.
//!
//! The contract: generations start at 1; `current` returns the highest generation and its key;
//! `by_generation` returns exactly the key stored for that generation, `UnknownGeneration` for a
//! generation that never existed (and always for 0); a store that cannot hand out keys right now
//! returns `Unavailable`. `rotate` adds the next generation and keeps the older keys.

use alice_crypto::{Key, KeyProvider, KeyProviderError};
use alice_os_keystore::MemoryVault;

#[test]
fn current_is_the_highest_generation() {
    let v = MemoryVault::new();
    v.insert(1, Key::from_bytes([1; 32]));
    v.insert(3, Key::from_bytes([3; 32]));
    v.insert(2, Key::from_bytes([2; 32]));
    let (g, k) = v.current().unwrap();
    assert_eq!(g, 3);
    assert_eq!(k.as_bytes(), &[3; 32]);
}

#[test]
fn by_generation_returns_the_stored_key_and_rejects_others() {
    let v = MemoryVault::new();
    v.insert(7, Key::from_bytes([7; 32]));
    assert_eq!(v.by_generation(7).unwrap().as_bytes(), &[7; 32]);
    assert_eq!(
        v.by_generation(8).unwrap_err(),
        KeyProviderError::UnknownGeneration(8)
    );
}

#[test]
fn generation_zero_is_never_a_key() {
    let v = MemoryVault::new();
    v.insert(1, Key::from_bytes([1; 32]));
    assert_eq!(
        v.by_generation(0).unwrap_err(),
        KeyProviderError::UnknownGeneration(0)
    );
}

#[test]
fn an_empty_vault_has_no_current_key() {
    let v = MemoryVault::new();
    assert!(matches!(v.current(), Err(KeyProviderError::Unavailable(_))));
}

#[test]
fn rotate_adds_a_fresh_random_key_as_the_next_generation_and_keeps_the_old_one() {
    let v = MemoryVault::new();
    let g1 = v.rotate().unwrap();
    let k1 = v.by_generation(1).unwrap();
    let g2 = v.rotate().unwrap();
    assert_eq!((g1, g2), (1, 2));
    let (cur, k2) = v.current().unwrap();
    assert_eq!(cur, 2);
    assert_eq!(v.by_generation(1).unwrap().as_bytes(), k1.as_bytes());
    assert_ne!(k1.as_bytes(), k2.as_bytes());
    assert_ne!(k2.as_bytes(), &[0; 32]);
}

#[test]
fn rotate_continues_after_the_highest_inserted_generation() {
    let v = MemoryVault::new();
    v.insert(5, Key::from_bytes([5; 32]));
    assert_eq!(v.rotate().unwrap(), 6);
}

#[test]
fn rotate_refuses_to_overflow_the_generation() {
    let v = MemoryVault::new();
    v.insert(u32::MAX, Key::from_bytes([9; 32]));
    assert!(matches!(v.rotate(), Err(KeyProviderError::Unavailable(_))));
    assert_eq!(v.current().unwrap().0, u32::MAX);
}

#[test]
fn retire_removes_a_generation() {
    let v = MemoryVault::new();
    v.insert(1, Key::from_bytes([1; 32]));
    v.insert(2, Key::from_bytes([2; 32]));
    v.retire(1);
    assert_eq!(
        v.by_generation(1).unwrap_err(),
        KeyProviderError::UnknownGeneration(1)
    );
    assert_eq!(v.current().unwrap().0, 2);
}

#[test]
fn the_vault_is_a_shareable_key_provider_object() {
    let v: std::sync::Arc<dyn KeyProvider> = std::sync::Arc::new(MemoryVault::new());
    let w = v.clone();
    assert!(std::thread::spawn(move || w.current().is_err())
        .join()
        .unwrap());
}
