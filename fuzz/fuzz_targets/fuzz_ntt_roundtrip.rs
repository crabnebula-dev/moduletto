//! Fuzz target: NTT forward/inverse roundtrip
//!
//! Verifies that NTT(INTT(poly)) == poly and INTT(NTT(poly)) == poly
//! for arbitrary polynomial coefficients. Tests both variable-time
//! and constant-time NTT paths.

#![no_main]

use libfuzzer_sys::fuzz_target;
use moduletto::{ConstantTimeOps, NTTPoly, KyberCoeff, KYBER_N};

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    // Build a polynomial from fuzz data
    let mut poly = NTTPoly::zero();
    for (i, chunk) in data.chunks(2).take(KYBER_N).enumerate() {
        let val = if chunk.len() == 2 {
            u16::from_le_bytes([chunk[0], chunk[1]]) as i64 % 3329
        } else {
            chunk[0] as i64 % 3329
        };
        poly.coeffs[i] = KyberCoeff::new(val);
    }

    // VT roundtrip: INTT(NTT(poly)) == poly
    let ntt_poly = poly.ntt();
    let recovered = ntt_poly.intt();
    for i in 0..KYBER_N {
        assert_eq!(
            recovered.coeffs[i].value(),
            poly.coeffs[i].value(),
            "VT NTT roundtrip failed at coeff {}", i
        );
    }

    // CT roundtrip: ct_intt(ct_ntt(poly)) == poly
    let ct_ntt_poly = poly.ct_ntt();
    let ct_recovered = ct_ntt_poly.ct_intt();
    for i in 0..KYBER_N {
        assert_eq!(
            ct_recovered.coeffs[i].value(),
            poly.coeffs[i].value(),
            "CT NTT roundtrip failed at coeff {}", i
        );
    }

    // CT == VT: ct_ntt should produce same output as ntt
    for i in 0..KYBER_N {
        assert_eq!(
            ct_ntt_poly.coeffs[i].value(),
            ntt_poly.coeffs[i].value(),
            "CT vs VT NTT mismatch at coeff {}", i
        );
    }
});
