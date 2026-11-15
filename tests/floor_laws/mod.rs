//! The laws of a named floor that only goes up, shared by every store's oracle.
//!
//! The reference is the definition, not an implementation: the floor of a name is the
//! lexicographic maximum of every value raised under that name (`None` before the first raise),
//! `raise` returns that maximum after the call, and names do not see each other's values. The
//! expected values below are written out by hand from that definition.
#![allow(dead_code)]

use alice_os_keystore::{FloorName, MonotonicFloor};

pub fn name(s: &str) -> FloorName {
    FloorName::new(s).unwrap()
}

/// raise then read: the first raise sets the value, a higher one replaces it (hi and lo both count)
pub fn raise_then_read(f: &dyn MonotonicFloor) {
    let n = name("relay-a");
    assert_eq!(f.read(&n).unwrap(), None);
    assert_eq!(f.raise(&n, (3, 7)).unwrap(), (3, 7));
    assert_eq!(f.read(&n).unwrap(), Some((3, 7)));
    assert_eq!(f.raise(&n, (3, 8)).unwrap(), (3, 8));
    assert_eq!(f.raise(&n, (4, 0)).unwrap(), (4, 0));
    assert_eq!(f.read(&n).unwrap(), Some((4, 0)));
}

/// a lower or equal raise changes nothing and returns the current value (not an error)
pub fn lower_raise_is_ignored(f: &dyn MonotonicFloor) {
    let n = name("relay-b");
    assert_eq!(f.raise(&n, (5, 5)).unwrap(), (5, 5));
    assert_eq!(f.raise(&n, (5, 4)).unwrap(), (5, 5));
    assert_eq!(f.raise(&n, (4, 9)).unwrap(), (5, 5));
    assert_eq!(f.raise(&n, (0, 0)).unwrap(), (5, 5));
    assert_eq!(f.raise(&n, (5, 5)).unwrap(), (5, 5));
    assert_eq!(f.read(&n).unwrap(), Some((5, 5)));
}

/// names are isolated, including a name that starts with another name and a value-like suffix
pub fn names_are_isolated(f: &dyn MonotonicFloor) {
    let a = name("x");
    let b = name("y");
    let tricky = name("x-00000000000000000009");
    assert_eq!(f.raise(&a, (9, 9)).unwrap(), (9, 9));
    assert_eq!(f.read(&b).unwrap(), None);
    assert_eq!(f.read(&tricky).unwrap(), None);
    assert_eq!(f.raise(&b, (1, 0)).unwrap(), (1, 0));
    assert_eq!(f.raise(&tricky, (2, 0)).unwrap(), (2, 0));
    assert_eq!(f.read(&a).unwrap(), Some((9, 9)));
    assert_eq!(f.read(&b).unwrap(), Some((1, 0)));
    assert_eq!(f.read(&tricky).unwrap(), Some((2, 0)));
}

/// the second consumer's shape: one counter per store, carried as (n, 0)
pub fn one_counter_as_n_0(f: &dyn MonotonicFloor) {
    let n = name("sealed-store-1");
    for i in 1..=5 {
        assert_eq!(f.raise(&n, (i, 0)).unwrap(), (i, 0));
    }
    assert_eq!(f.read(&n).unwrap(), Some((5, 0)));
    assert_eq!(f.raise(&n, (3, 0)).unwrap(), (5, 0));
    assert_eq!(f.read(&n).unwrap(), Some((5, 0)));
}

/// the full u64 range of both halves (native stores; the browser store stops below 2^53)
pub fn full_range(f: &dyn MonotonicFloor) {
    let n = name("wide");
    assert_eq!(
        f.raise(&n, (u64::MAX - 1, u64::MAX)).unwrap(),
        (u64::MAX - 1, u64::MAX)
    );
    assert_eq!(f.raise(&n, (u64::MAX, 0)).unwrap(), (u64::MAX, 0));
    assert_eq!(
        f.raise(&n, (u64::MAX - 1, u64::MAX)).unwrap(),
        (u64::MAX, 0)
    );
    assert_eq!(f.read(&n).unwrap(), Some((u64::MAX, 0)));
}
