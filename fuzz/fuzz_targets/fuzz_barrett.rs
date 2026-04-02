//! Fuzz target: Barrett reduction correctness
//!
//! Verifies that ct_mul (which uses Barrett reduction internally) produces
//! the same result as the variable-time modular multiplication for all
//! fuzzed coefficient pairs. Also tests with several different moduli
//! to exercise different Barrett parameter combinations.

#![no_main]

use libfuzzer_sys::fuzz_target;
use moduletto::{ModN, ConstantTimeOps};

fuzz_target!(|data: [u8; 8]| {
    let a_raw = u16::from_le_bytes([data[0], data[1]]);
    let b_raw = u16::from_le_bytes([data[2], data[3]]);
    let c_raw = u16::from_le_bytes([data[4], data[5]]);
    let d_raw = u16::from_le_bytes([data[6], data[7]]);

    // Kyber modulus: q = 3329
    {
        type K = ModN<3329>;
        let a = K::new(a_raw as i64);
        let b = K::new(b_raw as i64);
        let ct = a.ct_mul(b);
        let vt = a * b;
        assert_eq!(ct.value(), vt.value(), "Barrett 3329: {} * {}", a.value(), b.value());
    }

    // Small prime: q = 7
    {
        type M = ModN<7>;
        let a = M::new(a_raw as i64);
        let b = M::new(b_raw as i64);
        assert_eq!(a.ct_mul(b).value(), (a * b).value(), "Barrett 7");
    }

    // Medium prime: q = 251
    {
        type M = ModN<251>;
        let a = M::new(c_raw as i64);
        let b = M::new(d_raw as i64);
        assert_eq!(a.ct_mul(b).value(), (a * b).value(), "Barrett 251");
    }

    // Larger prime: q = 65537
    {
        type M = ModN<65537>;
        let a = M::new(a_raw as i64);
        let b = M::new(b_raw as i64);
        assert_eq!(a.ct_mul(b).value(), (a * b).value(), "Barrett 65537");
    }

    // Power-of-two-adjacent: q = 257
    {
        type M = ModN<257>;
        let a = M::new(c_raw as i64);
        let b = M::new(d_raw as i64);
        assert_eq!(a.ct_mul(b).value(), (a * b).value(), "Barrett 257");
    }

    // Mersenne prime: q = 127
    {
        type M = ModN<127>;
        let a = M::new(a_raw as i64);
        let b = M::new(b_raw as i64);
        assert_eq!(a.ct_mul(b).value(), (a * b).value(), "Barrett 127");
    }
});
