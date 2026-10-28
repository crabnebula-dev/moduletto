//! Fuzz target: ML-DSA-65 signature decoding (FIPS 204 Algorithms 27 and 21)
//!
//! Feeds arbitrary bytes to verification as a signature over a fixed key
//! and message, in two ways: the whole input as the signature, and the input
//! spliced into a valid signature at an offset it chooses (so the fuzzer can
//! reach the hint encoding at the end). The signature encoding is injective
//! (z is a bijective 20-bit packing and HintBitUnpack rejects every
//! non-canonical hint), so verification must accept exactly the original
//! signature and nothing else. It must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use moduletto::dsa::ml_dsa_65::{self, PK_BYTES, SIG_BYTES};
use std::sync::OnceLock;

const MSG: &[u8] = b"moduletto fuzz message";
const CTX: &[u8] = b"fuzz";

fn fixture() -> &'static ([u8; PK_BYTES], [u8; SIG_BYTES]) {
    static F: OnceLock<([u8; PK_BYTES], [u8; SIG_BYTES])> = OnceLock::new();
    F.get_or_init(|| {
        let (pk, sk) = ml_dsa_65::keygen_internal(&[0x11; 32]);
        let sig = ml_dsa_65::sign(&sk, MSG, CTX, &[0; 32]).unwrap();
        (pk, sig)
    })
}

fuzz_target!(|data: &[u8]| {
    let (pk, sig) = fixture();

    // The whole input as a signature, of any length.
    let ok = ml_dsa_65::verify(pk, MSG, CTX, data);
    assert_eq!(
        ok,
        data == sig.as_slice(),
        "verify accepted a different signature"
    );

    // The input spliced into the valid signature.
    if data.len() < 2 {
        return;
    }
    let at = u16::from_le_bytes([data[0], data[1]]) as usize % SIG_BYTES;
    let patch = &data[2..data.len().min(2 + SIG_BYTES - at)];
    let mut spliced = *sig;
    spliced[at..at + patch.len()].copy_from_slice(patch);
    let ok = ml_dsa_65::verify(pk, MSG, CTX, &spliced);
    assert_eq!(ok, spliced == *sig, "verify accepted a spliced signature");
});
