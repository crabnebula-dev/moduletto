//! Fuzz target: ML-KEM decapsulation over attacker-controlled bytes
//! (FIPS 203 Algorithms 18 and 21)
//!
//! Ciphertexts: the whole input, and the input spliced into a valid
//! ciphertext at an offset it chooses. A ciphertext of the right length is
//! never an error; unless it is the valid one, the result must be the
//! implicit-rejection key J(z ‖ c) = SHAKE256(z ‖ c, 32), computed here with
//! an independent SHA-3, and never the real shared secret. Any other length
//! is refused.
//!
//! Decapsulation keys: the input spliced into the secret parts of a valid
//! key (ŝ, where every 12-bit value up to 4095 can appear, and z). The hash
//! check still passes, so decapsulation runs on out-of-range coefficients;
//! it must not panic (the fuzz build has overflow checks on) and must stay
//! deterministic. A change to ek or H(ek) inside dk must be refused.

#![no_main]

use libfuzzer_sys::fuzz_target;
use moduletto::kem::{ml_kem_512, ml_kem_768, KemError};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::sync::OnceLock;

fn j(z: &[u8], c: &[u8]) -> [u8; 32] {
    let mut h = sha3::Shake256::default();
    h.update(z);
    h.update(c);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

/// `base` with the input after its first two bytes written at the offset
/// those two bytes name, kept inside `range`.
fn splice(base: &[u8], range: core::ops::Range<usize>, data: &[u8]) -> Vec<u8> {
    let mut out = base.to_vec();
    if data.len() >= 2 {
        let at = range.start + u16::from_le_bytes([data[0], data[1]]) as usize % range.len();
        let patch = &data[2..data.len().min(2 + range.end - at)];
        out[at..at + patch.len()].copy_from_slice(patch);
    }
    out
}

macro_rules! target {
    ($set:ident, $k:literal, $data:expr) => {{
        use $set::{CT_BYTES, DK_BYTES};
        struct Fixture {
            dk: [u8; DK_BYTES],
            c: [u8; CT_BYTES],
            ss: [u8; 32],
        }
        static F: OnceLock<Fixture> = OnceLock::new();
        let f = F.get_or_init(|| {
            let (ek, dk) = $set::keygen_derand(&[0x11; 32], &[0x22; 32]);
            let (c, ss) = $set::encaps_derand(&ek, &[0x33; 32]).unwrap();
            Fixture { dk, c, ss }
        });
        let data: &[u8] = $data;
        let z = &f.dk[DK_BYTES - 32..];

        // The whole input as a ciphertext.
        let got = $set::decaps(&f.dk, data);
        if data.len() != CT_BYTES {
            assert_eq!(got, Err(KemError::Length));
        } else if data != f.c.as_slice() {
            assert_eq!(got, Ok(j(z, data)), "not the implicit-rejection key");
        }

        // The input spliced into the valid ciphertext.
        let c = splice(&f.c, 0..CT_BYTES, data);
        let got = $set::decaps(&f.dk, &c).expect("a full-length ciphertext decapsulates");
        if c == f.c.as_slice() {
            assert_eq!(got, f.ss);
        } else {
            assert_eq!(got, j(z, &c), "not the implicit-rejection key");
            assert_ne!(got, f.ss, "a modified ciphertext gave the real key");
        }

        // The input spliced into ŝ: unreduced coefficients, same public part.
        let dk = splice(&f.dk, 0..384 * $k, data);
        let a = $set::decaps(&dk, &f.c).expect("the hash check still passes");
        assert_eq!(
            $set::decaps(&dk, &f.c),
            Ok(a),
            "decapsulation is not deterministic"
        );
        if dk == f.dk.as_slice() {
            assert_eq!(a, f.ss);
        }

        // The input spliced into ek ‖ H(ek): refused unless nothing changed.
        let dk = splice(&f.dk, 384 * $k..DK_BYTES - 32, data);
        let got = $set::decaps(&dk, &f.c);
        if dk == f.dk.as_slice() {
            assert_eq!(got, Ok(f.ss));
        } else {
            assert_eq!(got, Err(KemError::InvalidKey));
        }
        assert_eq!(
            $set::check_decapsulation_key(&dk).is_ok(),
            dk == f.dk.as_slice()
        );

        // The whole input as a decapsulation key.
        if data.len() != DK_BYTES {
            assert_eq!($set::decaps(data, &f.c), Err(KemError::Length));
            assert_eq!($set::check_decapsulation_key(data), Err(KemError::Length));
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    target!(ml_kem_512, 2, data);
    target!(ml_kem_768, 3, data);
});
