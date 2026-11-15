//! Oracle for the floor names and the in-memory floor (the reference behaviour; the laws are in
//! `floor_laws`, the same functions every persistent store runs).

mod floor_laws;

use alice_os_keystore::{FloorError, FloorName, MemoryFloor, MonotonicFloor, FLOOR_NAME_MAX};

#[test]
fn floor_names_are_1_to_64_bytes_of_a_z_0_9_and_dash() {
    for good in [
        "a",
        "0",
        "-",
        "relay-a",
        "ab12cd",
        &"z".repeat(64),
        "a-b-c-1-2-3",
    ] {
        assert_eq!(FloorName::new(good).unwrap().as_str(), good, "{good:?}");
    }
    assert_eq!(FLOOR_NAME_MAX, 64);
    for bad in [
        "",
        &"z".repeat(65),
        "A",
        "relay_a",
        "relay.a",
        "relay a",
        "é",
        "a/b",
        "a\\b",
        "a\0",
        "a\n",
        "floor:x",
    ] {
        assert_eq!(FloorName::new(bad), Err(FloorError::InvalidName), "{bad:?}");
    }
    assert_eq!(FloorName::try_from("ok-1").unwrap().to_string(), "ok-1");
}

#[test]
fn floor_errors_display_and_are_errors() {
    let errors: [Box<dyn std::error::Error>; 3] = [
        Box::new(FloorError::InvalidName),
        Box::new(FloorError::Unavailable("locked")),
        Box::new(FloorError::OutOfRange),
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
    assert!(FloorError::Unavailable("locked")
        .to_string()
        .contains("locked"));
}

#[test]
fn memory_floor_raise_then_read() {
    floor_laws::raise_then_read(&MemoryFloor::new());
}

#[test]
fn memory_floor_ignores_a_lower_raise() {
    floor_laws::lower_raise_is_ignored(&MemoryFloor::new());
}

#[test]
fn memory_floor_names_are_isolated() {
    floor_laws::names_are_isolated(&MemoryFloor::new());
}

#[test]
fn memory_floor_one_counter_as_n_0() {
    floor_laws::one_counter_as_n_0(&MemoryFloor::new());
}

#[test]
fn memory_floor_full_range() {
    floor_laws::full_range(&MemoryFloor::new());
}

#[test]
fn a_removed_memory_floor_reads_none_again() {
    let f = MemoryFloor::new();
    let n = floor_laws::name("gone");
    f.raise(&n, (4, 4)).unwrap();
    f.remove(&n);
    assert_eq!(f.read(&n).unwrap(), None);
    // the limit: after the removal a lower value is accepted
    assert_eq!(f.raise(&n, (1, 0)).unwrap(), (1, 0));
}

#[test]
fn a_floor_is_a_shareable_trait_object() {
    let f: std::sync::Arc<dyn MonotonicFloor + Send + Sync> =
        std::sync::Arc::new(MemoryFloor::new());
    let n = floor_laws::name("shared");
    let handles: Vec<_> = (1..=8u64)
        .map(|i| {
            let f = f.clone();
            let n = n.clone();
            std::thread::spawn(move || f.raise(&n, (i, 0)).unwrap())
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(f.read(&n).unwrap(), Some((8, 0)));
}
