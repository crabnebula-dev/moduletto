//! Fuzz target: constant-time primitive correctness
//!
//! Verifies ct_select, ct_swap, ct_eq, ct_lt against their specifications
//! for arbitrary fuzzed inputs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use moduletto::{ModN, ConstantTimeOps};

type K = ModN<3329>;

fuzz_target!(|data: [u8; 5]| {
    let a_raw = u16::from_le_bytes([data[0], data[1]]) as i64 % 3329;
    let b_raw = u16::from_le_bytes([data[2], data[3]]) as i64 % 3329;
    let choice = data[4];

    let a = K::new(a_raw);
    let b = K::new(b_raw);

    // ct_select: choice bit 0 selects between a and b
    let selected = K::ct_select(a, b, choice);
    if choice & 1 == 0 {
        assert_eq!(selected.value(), a.value(), "ct_select should return a when choice=0");
    } else {
        assert_eq!(selected.value(), b.value(), "ct_select should return b when choice=1");
    }

    // ct_select always returns one of {a, b}
    assert!(
        selected.value() == a.value() || selected.value() == b.value(),
        "ct_select returned neither a nor b"
    );

    // ct_swap with choice=0: no change
    {
        let mut x = a;
        let mut y = b;
        K::ct_swap(&mut x, &mut y, 0);
        assert_eq!(x.value(), a.value(), "ct_swap(0) changed x");
        assert_eq!(y.value(), b.value(), "ct_swap(0) changed y");
    }

    // ct_swap with choice=1: swapped
    {
        let mut x = a;
        let mut y = b;
        K::ct_swap(&mut x, &mut y, 1);
        assert_eq!(x.value(), b.value(), "ct_swap(1) didn't swap x");
        assert_eq!(y.value(), a.value(), "ct_swap(1) didn't swap y");
    }

    // ct_swap roundtrip: swap twice == identity
    {
        let mut x = a;
        let mut y = b;
        K::ct_swap(&mut x, &mut y, choice);
        K::ct_swap(&mut x, &mut y, choice);
        assert_eq!(x.value(), a.value(), "double ct_swap not identity (x)");
        assert_eq!(y.value(), b.value(), "double ct_swap not identity (y)");
    }

    // ct_eq: reflexive and correct
    assert_eq!(a.ct_eq(a), 1, "ct_eq not reflexive");
    assert_eq!(b.ct_eq(b), 1, "ct_eq not reflexive");
    if a.value() == b.value() {
        assert_eq!(a.ct_eq(b), 1, "ct_eq false negative");
    } else {
        assert_eq!(a.ct_eq(b), 0, "ct_eq false positive");
    }

    // ct_lt: consistent with actual ordering
    if a.value() < b.value() {
        assert_eq!(a.ct_lt(b), 1, "ct_lt false negative");
        assert_eq!(b.ct_lt(a), 0, "ct_lt reverse false positive");
    } else if a.value() > b.value() {
        assert_eq!(a.ct_lt(b), 0, "ct_lt false positive");
        assert_eq!(b.ct_lt(a), 1, "ct_lt reverse false negative");
    } else {
        assert_eq!(a.ct_lt(b), 0, "ct_lt should be 0 for equal values");
        assert_eq!(b.ct_lt(a), 0, "ct_lt should be 0 for equal values");
    }

    // ct_lt: irreflexive
    assert_eq!(a.ct_lt(a), 0, "ct_lt not irreflexive");
});
