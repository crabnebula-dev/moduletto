//! ctgrind-style check: secrets are marked undefined for Valgrind memcheck,
//! which then reports any conditional jump or memory address that depends on
//! them. Run on x86-64 Linux:
//!
//!   cargo build --release --features valgrind-ct --example valgrind_ct
//!   valgrind --tool=memcheck --error-exitcode=1 -q target/release/examples/valgrind_ct
//!
//! A clean run prints `ok` and valgrind exits 0. Any secret-dependent branch
//! or lookup appears as "Conditional jump or move depends on uninitialised
//! value(s)" / "Use of uninitialised value" with a stack trace.
//!
//! The library declassifies the values that are derived from secrets but
//! public by design (ρ, ek, H(ek), the ciphertext), so the variable-time code
//! that consumes them (rejection sampling, the ek and dk input checks) does
//! not report. Shared secrets are declassified *here*, only to compare them.
//!
//! Off x86-64 Linux, or outside valgrind, this runs as a plain smoke test.

use moduletto::kem::{ml_kem_512, ml_kem_768, KemError};
use moduletto::modn_ct::ConstantTimeOps;
use moduletto::valgrind::{declassify, poison, running};
use moduletto::{KyberCoeff, ModN, NTTPoly, KYBER_N};
use std::hint::black_box;

struct Set {
    name: &'static str,
    keygen: fn(&[u8; 32], &[u8; 32]) -> (Vec<u8>, Vec<u8>),
    encaps: fn(&[u8], &[u8; 32]) -> Result<(Vec<u8>, [u8; 32]), KemError>,
    decaps: fn(&[u8], &[u8]) -> Result<[u8; 32], KemError>,
    k: usize,
}

const SETS: [Set; 2] = [
    Set {
        name: "ML-KEM-512",
        keygen: |d, z| { let (ek, dk) = ml_kem_512::keygen_derand(d, z); (ek.to_vec(), dk.to_vec()) },
        encaps: |ek, m| ml_kem_512::encaps_derand(ek, m).map(|(c, k)| (c.to_vec(), k)),
        decaps: ml_kem_512::decaps,
        k: 2,
    },
    Set {
        name: "ML-KEM-768",
        keygen: |d, z| { let (ek, dk) = ml_kem_768::keygen_derand(d, z); (ek.to_vec(), dk.to_vec()) },
        encaps: |ek, m| ml_kem_768::encaps_derand(ek, m).map(|(c, k)| (c.to_vec(), k)),
        decaps: ml_kem_768::decaps,
        k: 3,
    },
];

fn kem(set: &Set) {
    // Key generation with secret seeds. Everything derived from them stays
    // undefined except what the library declassifies (ρ, ek, ek ‖ H(ek) in dk).
    let mut d = [0x11u8; 32];
    let mut z = [0x22u8; 32];
    poison(&mut d);
    poison(&mut z);
    let (ek, mut dk) = (set.keygen)(&d, &z);

    // Belt and braces: the secret parts of dk are undefined already, but a dk
    // loaded from storage would not be, so mark them explicitly as well.
    let k = set.k;
    poison(&mut dk[..384 * k]);
    poison(&mut dk[768 * k + 64..]);

    // Encapsulation with a secret message.
    let mut m = [0x33u8; 32];
    poison(&mut m);
    let (c, ss_sender) = (set.encaps)(&ek, &m).expect("encaps");

    // Decapsulation of the valid ciphertext and of a tampered one.
    let ss_receiver = (set.decaps)(&dk, &c).expect("decaps");
    let mut c2 = c.clone();
    c2[5] ^= 0x10;
    let ss_rejected = (set.decaps)(&dk, &c2).expect("decaps");

    // Only now, for the comparison, make the shared secrets public.
    declassify(&ss_sender);
    declassify(&ss_receiver);
    declassify(&ss_rejected);
    assert_eq!(ss_sender, ss_receiver, "{}: shared secrets differ", set.name);
    assert_ne!(ss_sender, ss_rejected, "{}: tampered ciphertext accepted", set.name);
}

fn field_ops() {
    type F = ModN<3329>;
    let mut a: [F; 256] = core::array::from_fn(|i| F::new((i * 37 + 11) as i64));
    let mut b: [F; 256] = core::array::from_fn(|i| F::new((i * 91 + 5) as i64));
    poison(&mut a);
    poison(&mut b);
    let mut acc = F::zero();
    for i in 0..256 {
        let p = a[i].ct_mul(b[i]);
        let s = a[i].ct_add(b[i]).ct_sub(p).ct_neg();
        let sel = F::ct_select(p, s, a[i].ct_lt(b[i]));
        let (mut x, mut y) = (p, s);
        F::ct_swap(&mut x, &mut y, a[i].ct_eq(b[i]));
        acc = acc.ct_add(sel).ct_add(x);
    }
    black_box(acc);
}

fn ntt_ops() {
    let mut a = NTTPoly::new(core::array::from_fn(|i| KyberCoeff::new((i * 13) as i64)));
    let mut b = NTTPoly::new(core::array::from_fn(|i| KyberCoeff::new((i * 7 + 1) as i64)));
    poison(&mut a.coeffs);
    poison(&mut b.coeffs);
    let p = a.ct_mul_ntt(&b);
    let q = a.ct_ntt().ct_add(&b.ct_ntt()).ct_intt().ct_sub(&p);
    black_box(q);
    let _ = KYBER_N;
}

fn main() {
    if !running() {
        eprintln!("valgrind_ct: not running under valgrind (or not x86-64 Linux); smoke test only");
    }
    for set in &SETS {
        kem(set);
    }
    field_ops();
    ntt_ops();
    println!("ok");
}
