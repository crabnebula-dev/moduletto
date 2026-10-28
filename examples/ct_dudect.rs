//! dudect statistical timing test for the secret-dependent paths.
//!
//! Each benchmark times one operation many times on inputs drawn from two
//! classes, interleaved at random, and runs Welch's t-test on the two timing
//! distributions (with the percentile cropping of the dudect paper). A
//! |t| above 4.5 is the paper's "timing leak detected" threshold; a
//! constant-time implementation stays within a few units however many
//! samples are added. Timing comes from `Instant::now()`, so the resolution
//! is ~40 ns on Apple Silicon and ~20 ns on x86-64; every operation measured
//! here takes microseconds, far above that.
//!
//! What is compared (fixed vs. random, or valid vs. tampered):
//!
//! - `decaps_valid_vs_tampered_{512,768}`: same key, a valid ciphertext against
//!   one with a random bit flipped. Exercises the implicit-rejection path.
//! - `decaps_fixed_vs_random_message_{512,768}`: same key, ciphertexts of a fixed
//!   message against ciphertexts of random messages. The decrypted message and
//!   the re-encryption randomness are the secrets here.
//! - `encaps_fixed_vs_random_message_768`: same ek, fixed m against random m.
//! - `ntt_ct_mul_fixed_vs_random`: `NTTPoly::ct_mul_ntt` on zero polynomials
//!   against random ones.
//! - `modn_ct_ops_fixed_vs_random`: 256 `ct_mul`/`ct_add`/`ct_sub`/`ct_select`
//!   on a fixed input against random ones.
//! - `dsa_sign_key_a_vs_key_b`: ML-DSA-65 hedged signing of one message under
//!   two fixed private keys, at the same rejection-loop count. The loop
//!   count is public by design (FIPS 204 lets it vary) and dominates the
//!   timing. Its distribution depends on the key through c·s1, c·s2 and
//!   c·t0, so two keys differ in mean count. An earlier version of this
//!   bench drew a fresh `rnd` per sample and let the count vary. On CI
//!   (x86-64) it reported max t = −10.94 and +10.44 from that difference
//!   alone. Now each sample's `rnd` is drawn, before timing, until signing
//!   under that sample's key takes exactly one iteration. The count comes
//!   from `ml_dsa_65::sign_iterations`, a hidden function behind the
//!   `ct-bench` feature. Only the production `ml_dsa_65::sign` is timed.
//!   The timed call still runs the whole secret-dependent path once:
//!   decoding and NTT of the key, ρ″, ExpandMask, the matrix product,
//!   Decompose, SampleInBall, the four checks, the hint and the encoding.
//!   A difference between the classes would come from secret-dependent work
//!   at a fixed loop count. Rejected iterations run the same loop body, and
//!   `examples/valgrind_ct.rs` checks signings with several iterations. The
//!   two keys share ρ and tr and differ in K, s1, s2 and t0. ρ and tr are
//!   public. ExpandA over ρ is variable-time by design, so a different ρ
//!   would separate the classes by public data alone. With two unrelated
//!   keys an earlier version reported |t| up to 6.7 on Apple M5. At one
//!   iteration per sample, three runs on Apple M5 gave max t = +1.95,
//!   −2.98 and −2.34.
//! - `hw_mul64_zero_vs_random` and `hw_mul64_zero_vs_random_dit`: not this
//!   crate's code but the CPU's: a dependent chain of 64-bit multiplies on
//!   all-zero against random operands, with `PSTATE.DIT` clear and set. On
//!   Apple M5 the first reports |t| in the tens and the second ~1: the
//!   multiplier's latency depends on its operands unless DIT is set, which is
//!   why the KEM entry points run under [`moduletto::dit::with_dit`]. The
//!   arithmetic benches above are wrapped in it here for the same reason.
//!
//! Key generation is not measured: `SampleNTT` over the public seed ρ is
//! variable-time by design (FIPS 203), and ρ changes with every key. The same
//! holds for ML-DSA key generation (`ExpandA` over ρ, and the public
//! rejection pattern of `ExpandS`).
//!
//! Environment: `DUDECT_SAMPLES` (default 50 000) sets the samples per bench;
//! `DUDECT_FIXED=zero` uses all-zero inputs for the fixed class of the
//! arithmetic benches instead of one fixed random input (with DIT clear, zero
//! operands alone move the multiplier's timing; see `hw_mul64_*`).
//!
//! Run everything once:   cargo run --release --features ct-bench --example ct_dudect
//! Run one for longer:    cargo run --release --features ct-bench --example ct_dudect -- \
//!                          --continuous decaps_valid_vs_tampered_768

use dudect_bencher::{ctbench_main, rand::RngExt, BenchRng, Class, CtRunner};
use moduletto::dit::with_dit;
use moduletto::dsa::ml_dsa_65;
use moduletto::kem::{ml_kem_512, ml_kem_768};
use moduletto::modn_ct::ConstantTimeOps;
use moduletto::{KyberCoeff, ModN, NTTPoly, KYBER_N};

/// Samples per benchmark across both classes (`DUDECT_SAMPLES` overrides).
fn samples() -> usize {
    std::env::var("DUDECT_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000)
}

/// `DUDECT_FIXED=zero` uses all-zero inputs for the fixed class of the
/// arithmetic benches (the dudect paper's choice); the default is one fixed
/// random input.
fn fixed_is_zero() -> bool {
    std::env::var("DUDECT_FIXED")
        .map(|v| v == "zero")
        .unwrap_or(false)
}

fn bytes32(rng: &mut BenchRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill(&mut b[..]);
    b
}

fn class(rng: &mut BenchRng) -> Class {
    if rng.random::<bool>() {
        Class::Left
    } else {
        Class::Right
    }
}

macro_rules! kem_benches {
    ($set:ident, $tampered:ident, $message:ident, $encaps:ident) => {
        fn $tampered(runner: &mut CtRunner, rng: &mut BenchRng) {
            let (ek, dk) = $set::keygen_derand(&bytes32(rng), &bytes32(rng));
            let (c, _) = $set::encaps_derand(&ek, &bytes32(rng)).unwrap();
            let inputs: Vec<(Class, [u8; $set::CT_BYTES])> = (0..samples())
                .map(|_| match class(rng) {
                    Class::Left => (Class::Left, c),
                    Class::Right => {
                        let mut t = c;
                        let bit = rng.random_range(0..8 * $set::CT_BYTES);
                        t[bit / 8] ^= 1 << (bit % 8);
                        (Class::Right, t)
                    }
                })
                .collect();
            for (cls, c) in &inputs {
                runner.run_one(*cls, || $set::decaps(&dk, c).unwrap());
            }
        }

        fn $message(runner: &mut CtRunner, rng: &mut BenchRng) {
            let (ek, dk) = $set::keygen_derand(&bytes32(rng), &bytes32(rng));
            let fixed = bytes32(rng);
            let inputs: Vec<(Class, [u8; $set::CT_BYTES])> = (0..samples())
                .map(|_| {
                    let cls = class(rng);
                    let m = match cls {
                        Class::Left => fixed,
                        Class::Right => bytes32(rng),
                    };
                    (cls, $set::encaps_derand(&ek, &m).unwrap().0)
                })
                .collect();
            for (cls, c) in &inputs {
                runner.run_one(*cls, || $set::decaps(&dk, c).unwrap());
            }
        }

        fn $encaps(runner: &mut CtRunner, rng: &mut BenchRng) {
            let (ek, _) = $set::keygen_derand(&bytes32(rng), &bytes32(rng));
            let fixed = bytes32(rng);
            let inputs: Vec<(Class, [u8; 32])> = (0..samples())
                .map(|_| {
                    let cls = class(rng);
                    (
                        cls,
                        match cls {
                            Class::Left => fixed,
                            Class::Right => bytes32(rng),
                        },
                    )
                })
                .collect();
            for (cls, m) in &inputs {
                runner.run_one(*cls, || $set::encaps_derand(&ek, m).unwrap());
            }
        }
    };
}

kem_benches!(
    ml_kem_512,
    decaps_valid_vs_tampered_512,
    decaps_fixed_vs_random_message_512,
    encaps_fixed_vs_random_message_512
);
kem_benches!(
    ml_kem_768,
    decaps_valid_vs_tampered_768,
    decaps_fixed_vs_random_message_768,
    encaps_fixed_vs_random_message_768
);

/// Rejection-loop iterations of every timed ML-DSA signing, in both classes.
const DSA_ITERATIONS: u32 = 1;

fn dsa_sign_key_a_vs_key_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (_, sk_a) = ml_dsa_65::keygen_internal(&bytes32(rng));
    let (_, other) = ml_dsa_65::keygen_internal(&bytes32(rng));
    // Key B keeps A's public parts (ρ and tr) and takes the secret parts
    // (K, s1, s2, t0) of another key. ExpandA over ρ is variable-time by
    // design, so a different ρ alone would separate the classes.
    let mut sk_b = sk_a;
    sk_b[32..64].copy_from_slice(&other[32..64]);
    sk_b[128..].copy_from_slice(&other[128..]);
    let m = bytes32(rng);
    // The loop count is public and its mean differs between keys, so every
    // timed signing runs exactly DSA_ITERATIONS iterations. For each sample,
    // draw rnd until signing under that sample's key takes that many.
    let rnd_for = |sk: &[u8], rng: &mut BenchRng| loop {
        let rnd = bytes32(rng);
        let (_, n) = ml_dsa_65::sign_iterations(sk, &m, b"", &rnd).unwrap();
        if n == DSA_ITERATIONS {
            break rnd;
        }
    };
    let inputs: Vec<(Class, [u8; 32])> = (0..samples())
        .map(|_| {
            let cls = class(rng);
            let sk = match cls {
                Class::Left => &sk_a,
                Class::Right => &sk_b,
            };
            (cls, rnd_for(sk, rng))
        })
        .collect();
    for (cls, rnd) in &inputs {
        let sk = match cls {
            Class::Left => &sk_a,
            Class::Right => &sk_b,
        };
        // The production entry point, not the counting one.
        runner.run_one(*cls, || ml_dsa_65::sign(sk, &m, b"", rnd).unwrap());
    }
}

fn random_poly(rng: &mut BenchRng) -> NTTPoly {
    let mut coeffs = [KyberCoeff::zero(); KYBER_N];
    for c in coeffs.iter_mut() {
        *c = KyberCoeff::new(rng.random_range(0..3329));
    }
    NTTPoly::new(coeffs)
}

fn ntt_ct_mul_fixed_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (fa, fb) = if fixed_is_zero() {
        (NTTPoly::zero(), NTTPoly::zero())
    } else {
        (random_poly(rng), random_poly(rng))
    };
    let inputs: Vec<(Class, NTTPoly, NTTPoly)> = (0..samples())
        .map(|_| match class(rng) {
            Class::Left => (Class::Left, fa.clone(), fb.clone()),
            Class::Right => (Class::Right, random_poly(rng), random_poly(rng)),
        })
        .collect();
    for (cls, a, b) in &inputs {
        runner.run_one(*cls, || with_dit(|| a.ct_mul_ntt(b)));
    }
}

type F = ModN<3329>;

fn random_field(rng: &mut BenchRng) -> [F; 256] {
    core::array::from_fn(|_| F::new(rng.random_range(0..3329)))
}

fn modn_ct_ops_fixed_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (fa, fb) = if fixed_is_zero() {
        ([F::zero(); 256], [F::zero(); 256])
    } else {
        (random_field(rng), random_field(rng))
    };
    let inputs: Vec<(Class, [F; 256], [F; 256])> = (0..samples())
        .map(|_| match class(rng) {
            Class::Left => (Class::Left, fa, fb),
            Class::Right => (
                Class::Right,
                core::array::from_fn(|_| F::new(rng.random_range(0..3329))),
                core::array::from_fn(|_| F::new(rng.random_range(0..3329))),
            ),
        })
        .collect();
    for (cls, a, b) in &inputs {
        runner.run_one(*cls, || {
            with_dit(|| {
                let mut acc = F::zero();
                for i in 0..256 {
                    let p = a[i].ct_mul(b[i]);
                    let s = a[i].ct_add(b[i]).ct_sub(p);
                    acc = acc.ct_add(F::ct_select(p, s, a[i].ct_lt(b[i])));
                }
                acc
            })
        });
    }
}

/// 32 passes of a dependent chain of 256 64-bit multiplies (~8 µs): measures
/// the CPU, not the crate. The effect is a steady-state one, so one sample
/// covers several thousand dependent multiplies.
#[inline(never)]
fn mul_chain(a: &[u64; 256]) -> u64 {
    let mut acc = 1u64;
    for _ in 0..32 {
        for &x in a.iter() {
            acc = acc.wrapping_mul(x).wrapping_add(x) | 1;
        }
        acc = std::hint::black_box(acc);
    }
    acc
}

fn mul64_inputs(rng: &mut BenchRng) -> Vec<(Class, [u64; 256])> {
    (0..samples())
        .map(|_| match class(rng) {
            Class::Left => (Class::Left, [0u64; 256]),
            Class::Right => (Class::Right, core::array::from_fn(|_| rng.random::<u64>())),
        })
        .collect()
}

fn hw_mul64_zero_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let inputs = mul64_inputs(rng);
    for (cls, a) in &inputs {
        runner.run_one(*cls, || mul_chain(a));
    }
}

fn hw_mul64_zero_vs_random_dit(runner: &mut CtRunner, rng: &mut BenchRng) {
    let inputs = mul64_inputs(rng);
    for (cls, a) in &inputs {
        runner.run_one(*cls, || with_dit(|| mul_chain(a)));
    }
}

ctbench_main!(
    decaps_valid_vs_tampered_512,
    decaps_valid_vs_tampered_768,
    decaps_fixed_vs_random_message_512,
    decaps_fixed_vs_random_message_768,
    encaps_fixed_vs_random_message_512,
    encaps_fixed_vs_random_message_768,
    ntt_ct_mul_fixed_vs_random,
    modn_ct_ops_fixed_vs_random,
    dsa_sign_key_a_vs_key_b,
    hw_mul64_zero_vs_random,
    hw_mul64_zero_vs_random_dit
);
