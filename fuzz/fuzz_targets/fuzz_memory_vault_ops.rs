#![no_main]
//! Any sequence of insert / retire / rotate keeps the vault consistent with a
//! plain model: `current` is the highest stored generation, `by_generation` returns
//! exactly the stored key and `UnknownGeneration` otherwise (always for 0).

use std::collections::BTreeMap;

use alice_os_keystore::{Key, KeyProvider, KeyProviderError, MemoryVault};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    Insert(u32, u8),
    Retire(u32),
    Rotate,
    Lookup(u32),
}

fuzz_target!(|ops: Vec<Op>| {
    let vault = MemoryVault::new();
    let mut model: BTreeMap<u32, Option<[u8; 32]>> = BTreeMap::new();
    for op in ops.into_iter().take(256) {
        match op {
            // generation 0 is never a key: insert refuses it (tested in tests/vault_oracle.rs)
            Op::Insert(0, _) => {}
            Op::Insert(g, b) => {
                vault.insert(g, Key::from_bytes([b; 32]));
                model.insert(g, Some([b; 32]));
            }
            Op::Retire(g) => {
                vault.retire(g);
                model.remove(&g);
            }
            Op::Rotate => match vault.rotate() {
                Ok(g) => {
                    let expected = model.keys().next_back().map_or(1, |m| m + 1);
                    assert_eq!(g, expected);
                    model.insert(g, None); // random bytes: only the generation is modelled
                }
                Err(_) => assert_eq!(model.keys().next_back(), Some(&u32::MAX)),
            },
            Op::Lookup(g) => match (vault.by_generation(g), model.get(&g)) {
                (Ok(k), Some(Some(bytes))) => assert_eq!(k.as_bytes(), bytes),
                (Ok(_), Some(None)) => {}
                (Err(KeyProviderError::UnknownGeneration(e)), None) => assert_eq!(e, g),
                (got, want) => panic!("by_generation({g}) = {:?}, model {want:?}", got.err()),
            },
        }
        match (vault.current(), model.keys().next_back()) {
            (Ok((g, _)), Some(&m)) => assert_eq!(g, m),
            (Err(KeyProviderError::Unavailable(_)), None) => {}
            (got, want) => panic!("current = {:?}, model max {want:?}", got.map(|(g, _)| g)),
        }
    }
});
