//! Fuzz target: constant-time vs variable-time arithmetic equivalence
//!
//! Verifies that ct_add, ct_sub, ct_mul, ct_neg produce identical results
//! to their variable-time counterparts for all fuzzed inputs over the
//! Kyber modulus (q = 3329).

#![no_main]

use libfuzzer_sys::fuzz_target;
use moduletto::{ModN, ConstantTimeOps};

type K = ModN<3329>;

fuzz_target!(|data: [u8; 4]| {
    let a_raw = u16::from_le_bytes([data[0], data[1]]) as i64 % 3329;
    let b_raw = u16::from_le_bytes([data[2], data[3]]) as i64 % 3329;

    let a = K::new(a_raw);
    let b = K::new(b_raw);

    // ct_add == vt_add
    assert_eq!(a.ct_add(b).value(), (a + b).value(), "ct_add mismatch");

    // ct_sub == vt_sub
    assert_eq!(a.ct_sub(b).value(), (a - b).value(), "ct_sub mismatch");

    // ct_mul == vt_mul
    assert_eq!(a.ct_mul(b).value(), (a * b).value(), "ct_mul mismatch");

    // ct_neg == vt_neg
    assert_eq!(a.ct_neg().value(), (-a).value(), "ct_neg mismatch");
    assert_eq!(b.ct_neg().value(), (-b).value(), "ct_neg mismatch");

    // Range invariant: all results in [0, q)
    assert!(a.ct_add(b).value() >= 0 && a.ct_add(b).value() < 3329);
    assert!(a.ct_sub(b).value() >= 0 && a.ct_sub(b).value() < 3329);
    assert!(a.ct_mul(b).value() >= 0 && a.ct_mul(b).value() < 3329);
    assert!(a.ct_neg().value() >= 0 && a.ct_neg().value() < 3329);

    // Algebraic: a + (-a) == 0
    assert_eq!(a.ct_add(a.ct_neg()).value(), 0, "additive inverse broken");

    // Algebraic: (a + b) - b == a
    assert_eq!(a.ct_add(b).ct_sub(b).value(), a.value(), "add-sub roundtrip");

    // Algebraic: a * 1 == a
    let one = K::new(1);
    assert_eq!(a.ct_mul(one).value(), a.value(), "multiplicative identity");

    // Algebraic: a * 0 == 0
    let zero = K::new(0);
    assert_eq!(a.ct_mul(zero).value(), 0, "multiplicative zero");
});
