//! Fuzz target: ML-KEM encapsulation keys and round trips
//! (FIPS 203 Algorithms 16, 17 and 20, and the section 7.2 key check)
//!
//! Encapsulation keys: the whole input, and the input spliced into a valid
//! key. The library's check must agree with a reference written here (right
//! length, every 12-bit coefficient below q), encapsulation must succeed
//! exactly when the check passes, and it must not panic on any accepted
//! key (the fuzz build has overflow checks on).
//!
//! Round trips: d, z and m are taken from the input. Key generation is
//! deterministic and produces keys that pass both checks; decapsulation
//! returns the encapsulated secret; encapsulating twice gives the same
//! result.

#![no_main]

use libfuzzer_sys::fuzz_target;
use moduletto::kem::{ml_kem_512, ml_kem_768, KemError};
use std::sync::OnceLock;

const Q: u16 = 3329;

/// FIPS 203 section 7.2, independently of the library.
fn reference_check(ek: &[u8], k: usize) -> Result<(), KemError> {
    if ek.len() != 384 * k + 32 {
        return Err(KemError::Length);
    }
    for t in ek[..384 * k].chunks_exact(3) {
        let c0 = t[0] as u16 | ((t[1] as u16 & 0x0f) << 8);
        let c1 = (t[1] as u16 >> 4) | ((t[2] as u16) << 4);
        if c0 >= Q || c1 >= Q {
            return Err(KemError::InvalidKey);
        }
    }
    Ok(())
}

macro_rules! target {
    ($set:ident, $k:literal, $data:expr) => {{
        use $set::EK_BYTES;
        static EK: OnceLock<[u8; EK_BYTES]> = OnceLock::new();
        let valid = EK.get_or_init(|| $set::keygen_derand(&[0x11; 32], &[0x22; 32]).0);
        let data: &[u8] = $data;
        let m = [0x33u8; 32];

        // The whole input as an encapsulation key.
        let want = reference_check(data, $k);
        assert_eq!($set::check_encapsulation_key(data), want);
        assert_eq!($set::encaps_derand(data, &m).map(|_| ()), want);

        // The input spliced into a valid key.
        let mut ek = *valid;
        if data.len() >= 2 {
            let at = u16::from_le_bytes([data[0], data[1]]) as usize % EK_BYTES;
            let patch = &data[2..data.len().min(2 + EK_BYTES - at)];
            ek[at..at + patch.len()].copy_from_slice(patch);
        }
        let want = reference_check(&ek, $k);
        assert_eq!($set::check_encapsulation_key(&ek), want);
        let got = $set::encaps_derand(&ek, &m);
        assert_eq!(got.map(|_| ()), want);
        assert_eq!(
            got,
            $set::encaps_derand(&ek, &m),
            "encapsulation is not deterministic"
        );

        // Round trip with seeds from the input.
        if data.len() >= 96 {
            let d: [u8; 32] = data[..32].try_into().unwrap();
            let z: [u8; 32] = data[32..64].try_into().unwrap();
            let m: [u8; 32] = data[64..96].try_into().unwrap();
            let (ek, dk) = $set::keygen_derand(&d, &z);
            assert_eq!($set::keygen_derand(&d, &z), (ek, dk));
            assert_eq!(reference_check(&ek, $k), Ok(()));
            assert_eq!($set::check_decapsulation_key(&dk), Ok(()));
            assert_eq!(&dk[dk.len() - 32..], &z);
            let (c, ss) = $set::encaps_derand(&ek, &m).unwrap();
            assert_eq!($set::decaps(&dk, &c), Ok(ss));
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    target!(ml_kem_512, 2, data);
    target!(ml_kem_768, 3, data);
});
