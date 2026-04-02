//! Fuzz target: NTT polynomial multiplication vs schoolbook
//!
//! Verifies that NTT-based polynomial multiplication produces the same
//! result as naive schoolbook multiplication for arbitrary polynomials.
//! Tests both variable-time and constant-time paths.

#![no_main]

use libfuzzer_sys::fuzz_target;
use moduletto::{NTTPoly, KyberCoeff, KYBER_N};

fuzz_target!(|data: &[u8]| {
    // Need enough data for two small polynomials
    if data.len() < 8 {
        return;
    }

    let half = data.len() / 2;
    let data_a = &data[..half];
    let data_b = &data[half..];

    // Build two polynomials (sparse — only populate from fuzz data)
    let mut poly_a = NTTPoly::zero();
    let mut poly_b = NTTPoly::zero();

    for (i, chunk) in data_a.chunks(2).take(KYBER_N).enumerate() {
        let val = if chunk.len() == 2 {
            u16::from_le_bytes([chunk[0], chunk[1]]) as i64 % 3329
        } else {
            chunk[0] as i64 % 3329
        };
        poly_a.coeffs[i] = KyberCoeff::new(val);
    }

    for (i, chunk) in data_b.chunks(2).take(KYBER_N).enumerate() {
        let val = if chunk.len() == 2 {
            u16::from_le_bytes([chunk[0], chunk[1]]) as i64 % 3329
        } else {
            chunk[0] as i64 % 3329
        };
        poly_b.coeffs[i] = KyberCoeff::new(val);
    }

    // NTT multiplication
    let ntt_result = poly_a.mul_ntt(&poly_b);

    // Schoolbook multiplication (ground truth)
    let schoolbook_result = poly_a.mul_schoolbook(&poly_b);

    // They must agree
    for i in 0..KYBER_N {
        assert_eq!(
            ntt_result.coeffs[i].value(),
            schoolbook_result.coeffs[i].value(),
            "NTT vs schoolbook mismatch at coeff {}", i
        );
    }

    // CT NTT multiplication must also agree
    let ct_result = poly_a.ct_mul_ntt(&poly_b);
    for i in 0..KYBER_N {
        assert_eq!(
            ct_result.coeffs[i].value(),
            schoolbook_result.coeffs[i].value(),
            "CT NTT vs schoolbook mismatch at coeff {}", i
        );
    }
});
