#![no_main]
//! Any sequence of insert / retire / generate keeps the vault consistent with a
//! plain model: `current` is the highest stored generation, `by_id` returns
//! exactly the stored key and `UnknownKey` otherwise.

use std::collections::BTreeMap;

use alice_os_keystore::{DataKey, KeyVault, MemoryVault, VaultError};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    Insert(u32, u8),
    Retire(u32),
    Generate,
    Lookup(u32),
}

fuzz_target!(|ops: Vec<Op>| {
    let vault = MemoryVault::new();
    let mut model: BTreeMap<u32, Option<[u8; 32]>> = BTreeMap::new();
    for op in ops.into_iter().take(256) {
        match op {
            Op::Insert(g, b) => {
                vault.insert(g, DataKey::from_bytes([b; 32]));
                model.insert(g, Some([b; 32]));
            }
            Op::Retire(g) => {
                vault.retire(g);
                model.remove(&g);
            }
            Op::Generate => match vault.generate() {
                Ok(g) => {
                    let expected = model.keys().next_back().map_or(1, |m| m + 1);
                    assert_eq!(g, expected);
                    model.insert(g, None); // random bytes: only the generation is modelled
                }
                Err(_) => assert_eq!(model.keys().next_back(), Some(&u32::MAX)),
            },
            Op::Lookup(g) => match (vault.by_id(g), model.get(&g)) {
                (Ok(k), Some(Some(bytes))) => assert_eq!(k.as_bytes(), bytes),
                (Ok(_), Some(None)) => {}
                (Err(VaultError::UnknownKey(e)), None) => assert_eq!(e, g),
                (got, want) => panic!("by_id({g}) = {got:?}, model {want:?}"),
            },
        }
        match (vault.current(), model.keys().next_back()) {
            (Ok((g, _)), Some(&m)) => assert_eq!(g, m),
            (Err(VaultError::Unavailable(_)), None) => {}
            (got, want) => panic!("current = {got:?}, model max {want:?}"),
        }
    }
});
