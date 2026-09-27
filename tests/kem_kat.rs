//! The library `kem` module against the NIST ACVP ML-KEM-512 vectors
//! (FIPS 203): 25 keyGen, 25 encapsulation and 10 decapsulation cases.

use moduletto::kem::{self, KemError};

const KATS: &str = include_str!("kat/ml_kem_512_fips203.txt");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn acvp_ml_kem_512() {
    let (mut kg, mut en, mut de) = (0, 0, 0);
    for line in KATS.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f[0] {
            "keygen" => {
                let d: [u8; 32] = unhex(f[2]).try_into().unwrap();
                let z: [u8; 32] = unhex(f[3]).try_into().unwrap();
                let (ek, dk) = kem::keygen_derand(&d, &z);
                assert_eq!(ek.as_slice(), unhex(f[4]), "keygen tc{} ek", f[1]);
                assert_eq!(dk.as_slice(), unhex(f[5]), "keygen tc{} dk", f[1]);
                kg += 1;
            }
            "encaps" => {
                let m: [u8; 32] = unhex(f[3]).try_into().unwrap();
                let (c, k) = kem::encaps_derand(&unhex(f[2]), &m).unwrap();
                assert_eq!(c.as_slice(), unhex(f[4]), "encaps tc{} c", f[1]);
                assert_eq!(k.as_slice(), unhex(f[5]), "encaps tc{} k", f[1]);
                en += 1;
            }
            "decaps" => {
                let k = kem::decaps(&unhex(f[2]), &unhex(f[3])).unwrap();
                assert_eq!(k.as_slice(), unhex(f[4]), "decaps tc{} k", f[1]);
                de += 1;
            }
            other => panic!("unknown record {other}"),
        }
    }
    assert_eq!((kg, en, de), (25, 25, 10));
}

#[test]
fn input_checks() {
    let (ek, dk) = kem::keygen_derand(&[1; 32], &[2; 32]);
    assert_eq!(kem::encaps_derand(&ek[..799], &[0; 32]), Err(KemError::Length));
    // A coefficient of 0xfff (>= q) must fail the modulus check.
    let mut bad = ek;
    bad[0] = 0xff;
    bad[1] |= 0x0f;
    assert_eq!(kem::encaps_derand(&bad, &[0; 32]), Err(KemError::InvalidKey));
    let (c, k) = kem::encaps_derand(&ek, &[3; 32]).unwrap();
    assert_eq!(kem::decaps(&dk, &c).unwrap(), k);
    // Tampered ciphertext: implicit rejection gives a different key, not an error.
    let mut c2 = c;
    c2[0] ^= 1;
    assert_ne!(kem::decaps(&dk, &c2).unwrap(), k);
    // Tampered H(ek) inside dk is rejected.
    let mut dk2 = dk;
    dk2[1570] ^= 1;
    assert_eq!(kem::decaps(&dk2, &c), Err(KemError::InvalidKey));
}
