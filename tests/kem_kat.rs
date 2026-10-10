//! The library `kem` module against the NIST ACVP ML-KEM vectors (FIPS 203):
//! for ML-KEM-512 and ML-KEM-768, 25 keyGen, 25 encapsulation and 10
//! decapsulation cases each, plus 10 encapsulation-key and 10
//! decapsulation-key checks each. `tests/kat/extract.mjs` regenerates the
//! files from an ACVP-Server checkout.

use moduletto::kem::{self, ml_kem_512, ml_kem_768, KemError};

type Keygen = fn(&[u8; 32], &[u8; 32]) -> (Vec<u8>, Vec<u8>);
type Encaps = fn(&[u8], &[u8; 32]) -> Result<(Vec<u8>, [u8; 32]), KemError>;
type Decaps = fn(&[u8], &[u8]) -> Result<[u8; 32], KemError>;

struct Set {
    kats: &'static str,
    keygen: Keygen,
    encaps: Encaps,
    decaps: Decaps,
}

const ML_KEM_512: Set = Set {
    kats: include_str!("kat/ml_kem_512_fips203.txt"),
    keygen: |d, z| {
        let (ek, dk) = ml_kem_512::keygen_derand(d, z);
        (ek.to_vec(), dk.to_vec())
    },
    encaps: |ek, m| ml_kem_512::encaps_derand(ek, m).map(|(c, k)| (c.to_vec(), k)),
    decaps: ml_kem_512::decaps,
};

const ML_KEM_768: Set = Set {
    kats: include_str!("kat/ml_kem_768_fips203.txt"),
    keygen: |d, z| {
        let (ek, dk) = ml_kem_768::keygen_derand(d, z);
        (ek.to_vec(), dk.to_vec())
    },
    encaps: |ek, m| ml_kem_768::encaps_derand(ek, m).map(|(c, k)| (c.to_vec(), k)),
    decaps: ml_kem_768::decaps,
};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn records(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().collect())
}

fn run(set: &Set) {
    let (mut kg, mut en, mut de) = (0, 0, 0);
    for f in records(set.kats) {
        match f[0] {
            "keygen" => {
                let d: [u8; 32] = unhex(f[2]).try_into().unwrap();
                let z: [u8; 32] = unhex(f[3]).try_into().unwrap();
                let (ek, dk) = (set.keygen)(&d, &z);
                assert_eq!(ek, unhex(f[4]), "keygen tc{} ek", f[1]);
                assert_eq!(dk, unhex(f[5]), "keygen tc{} dk", f[1]);
                kg += 1;
            }
            "encaps" => {
                let m: [u8; 32] = unhex(f[3]).try_into().unwrap();
                let (c, k) = (set.encaps)(&unhex(f[2]), &m).unwrap();
                assert_eq!(c, unhex(f[4]), "encaps tc{} c", f[1]);
                assert_eq!(k.as_slice(), unhex(f[5]), "encaps tc{} k", f[1]);
                en += 1;
            }
            "decaps" => {
                let k = (set.decaps)(&unhex(f[2]), &unhex(f[3])).unwrap();
                assert_eq!(k.as_slice(), unhex(f[4]), "decaps tc{} k", f[1]);
                de += 1;
            }
            other => panic!("unknown record {other}"),
        }
    }
    assert_eq!((kg, en, de), (25, 25, 10));
}

#[test]
fn acvp_ml_kem_512() {
    run(&ML_KEM_512);
}

#[test]
fn acvp_ml_kem_768() {
    run(&ML_KEM_768);
}

/// ACVP encapsulationKeyCheck and decapsulationKeyCheck groups.
#[test]
fn acvp_key_checks() {
    let mut n = 0;
    for f in records(include_str!("kat/ml_kem_keycheck_fips203.txt")) {
        let key = unhex(f[4]);
        let got = match (f[0], f[1]) {
            ("ekcheck", "ML-KEM-512") => ml_kem_512::check_encapsulation_key(&key),
            ("dkcheck", "ML-KEM-512") => ml_kem_512::check_decapsulation_key(&key),
            ("ekcheck", "ML-KEM-768") => ml_kem_768::check_encapsulation_key(&key),
            ("dkcheck", "ML-KEM-768") => ml_kem_768::check_decapsulation_key(&key),
            other => panic!("unknown record {other:?}"),
        };
        assert_eq!(got.is_ok(), f[3] == "pass", "{} {} tc{}: {got:?}", f[0], f[1], f[2]);
        n += 1;
    }
    assert_eq!(n, 40);
}

#[test]
fn input_checks() {
    assert_eq!(kem::SS_BYTES, 32);
    let (ek, dk) = ml_kem_768::keygen_derand(&[1; 32], &[2; 32]);
    assert_eq!(ml_kem_768::encaps_derand(&ek[..1183], &[0; 32]), Err(KemError::Length));
    // A coefficient of 0xfff (>= q) must fail the modulus check.
    let mut bad = ek;
    bad[0] = 0xff;
    bad[1] |= 0x0f;
    assert_eq!(ml_kem_768::encaps_derand(&bad, &[0; 32]), Err(KemError::InvalidKey));
    let (c, k) = ml_kem_768::encaps_derand(&ek, &[3; 32]).unwrap();
    assert_eq!(ml_kem_768::decaps(&dk, &c).unwrap(), k);
    // Tampered ciphertext: implicit rejection gives a different key, not an error.
    let mut c2 = c;
    c2[0] ^= 1;
    assert_ne!(ml_kem_768::decaps(&dk, &c2).unwrap(), k);
    #[cfg(feature = "getrandom")]
    {
        let (ek, dk) = ml_kem_768::keygen().unwrap();
        let (c, k) = ml_kem_768::encaps(&ek).unwrap();
        assert_eq!(ml_kem_768::decaps(&dk, &c).unwrap(), k);
    }
    assert_eq!(ml_kem_768::decaps(&dk, &c[..1087]), Err(KemError::Length));
    // Tampered H(ek) inside dk is rejected.
    let mut dk2 = dk;
    dk2[768 * 3 + 40] ^= 1;
    assert_eq!(ml_kem_768::decaps(&dk2, &c), Err(KemError::InvalidKey));
    // A 512 key is not a 768 key.
    let (ek512, _) = ml_kem_512::keygen_derand(&[1; 32], &[2; 32]);
    assert_eq!(ml_kem_768::encaps_derand(&ek512, &[0; 32]), Err(KemError::Length));
}

/// FIPS 203 implicit rejection, checked through the public API against an
/// independent SHAKE256: for every single-bit change to a ciphertext the
/// result is exactly J(z ‖ c'), never the real key and never a mix of the two.
///
/// Regression test for the audit finding in `audits/`: the previous mask
/// derivation leaked bits of K' whenever the changed bit was not bit 0.
#[test]
fn implicit_rejection_matches_shake256_for_every_bit() {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    fn j(z: &[u8], c: &[u8]) -> [u8; 32] {
        let mut h = sha3::Shake256::default();
        h.update(z);
        h.update(c);
        let mut out = [0u8; 32];
        h.finalize_xof().read(&mut out);
        out
    }

    fn check(set: &Set, dk_len: usize, ct_len: usize) {
        let d = [0x11u8; 32];
        let z = [0x22u8; 32];
        let (ek, dk) = (set.keygen)(&d, &z);
        assert_eq!(dk.len(), dk_len);
        assert_eq!(&dk[dk_len - 32..], &z);
        let (c, k) = (set.encaps)(&ek, &[0x33u8; 32]).unwrap();
        assert_eq!(c.len(), ct_len);
        assert_eq!((set.decaps)(&dk, &c).unwrap(), k);
        for pos in [0usize, 1, 2, 159, ct_len - 129, ct_len - 128, ct_len - 1] {
            for bit in 0..8 {
                let mut c2 = c.clone();
                c2[pos] ^= 1 << bit;
                let got = (set.decaps)(&dk, &c2).unwrap();
                assert_eq!(got, j(&z, &c2), "byte {pos} bit {bit}: not J(z || c')");
                assert_ne!(got, k);
            }
        }
    }

    check(&ML_KEM_512, ml_kem_512::DK_BYTES, ml_kem_512::CT_BYTES);
    check(&ML_KEM_768, ml_kem_768::DK_BYTES, ml_kem_768::CT_BYTES);
}
