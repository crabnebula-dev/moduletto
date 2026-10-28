//! Fuzz target: ML-DSA-65 key decoding (FIPS 204 Algorithms 23 and 25)
//!
//! Public keys: arbitrary bytes, whole or spliced into a valid key at an
//! offset the input chooses, are used to verify a fixed valid signature.
//! pkDecode is a bijection and the key is hashed into μ, so only the
//! original key may verify. Private keys: the input spliced into a valid
//! private key is used to sign. skDecode accepts any bytes, and FIPS 204
//! notes that a malformed key can decode out of range; signing must still
//! terminate, be deterministic and never panic. The whole input as a private
//! key must be refused unless it has the right length.

#![no_main]

use libfuzzer_sys::fuzz_target;
use moduletto::dsa::ml_dsa_65::{self, PK_BYTES, SIG_BYTES, SK_BYTES};
use moduletto::dsa::DsaError;
use std::sync::OnceLock;

const MSG: &[u8] = b"moduletto fuzz message";

struct Fixture {
    pk: [u8; PK_BYTES],
    sk: [u8; SK_BYTES],
    sig: [u8; SIG_BYTES],
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let (pk, sk) = ml_dsa_65::keygen_internal(&[0x22; 32]);
        let sig = ml_dsa_65::sign(&sk, MSG, b"", &[0; 32]).unwrap();
        Fixture { pk, sk, sig }
    })
}

/// `base` with the input after its first two bytes written at the offset
/// those two bytes name.
fn splice<const N: usize>(base: &[u8; N], data: &[u8]) -> [u8; N] {
    let mut out = *base;
    if data.len() >= 2 {
        let at = u16::from_le_bytes([data[0], data[1]]) as usize % N;
        let patch = &data[2..data.len().min(2 + N - at)];
        out[at..at + patch.len()].copy_from_slice(patch);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();

    // The whole input as a public key.
    let ok = ml_dsa_65::verify(data, MSG, b"", &f.sig);
    assert_eq!(
        ok,
        data == f.pk.as_slice(),
        "a different public key verified"
    );
    assert_eq!(
        ml_dsa_65::external_mu(data, MSG, b"").is_ok(),
        data.len() == PK_BYTES
    );

    // The input spliced into the valid public key.
    let pk = splice(&f.pk, data);
    let ok = ml_dsa_65::verify(&pk, MSG, b"", &f.sig);
    assert_eq!(ok, pk == f.pk, "a spliced public key verified");

    // The whole input as a private key.
    if data.len() != SK_BYTES {
        assert_eq!(
            ml_dsa_65::sign(data, MSG, b"", &[0; 32]),
            Err(DsaError::Length)
        );
    }

    // The input spliced into the valid private key.
    let sk = splice(&f.sk, data);
    let sig = ml_dsa_65::sign(&sk, MSG, b"", &[0; 32]).expect("a full-length private key signs");
    let again = ml_dsa_65::sign(&sk, MSG, b"", &[0; 32]).unwrap();
    assert_eq!(sig, again, "deterministic signing is not reproducible");
    if sk == f.sk {
        assert_eq!(sig, f.sig);
    }
});
