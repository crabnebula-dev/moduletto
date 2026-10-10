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
//! - `hw_mul64_zero_vs_random` and `hw_mul64_zero_vs_random_dit`: not this
//!   crate's code but the CPU's: a dependent chain of 64-bit multiplies on
//!   all-zero against random operands, with `PSTATE.DIT` clear and set. On
//!   Apple M5 the first reports |t| in the tens and the second ~1: the
//!   multiplier's latency depends on its operands unless DIT is set, which is
//!   why the KEM entry points run under [`moduletto::dit::with_dit`]. The
//!   arithmetic benches above are wrapped in it here for the same reason.
//!
//! Key generation is not measured: `SampleNTT` over the public seed ρ is
//! variable-time by design (FIPS 203), and ρ changes with every key.
//!
//! Environment: `DUDECT_SAMPLES` (default 50 000) sets the samples per bench;
//! `DUDECT_FIXED=zero` uses all-zero inputs for the fixed class of the
//! arithmetic benches instead of one fixed random input (with DIT clear, zero
//! operands alone move the multiplier's timing; see `hw_mul64_*`).
//!
//! Run everything once:   cargo run --release --example ct_dudect
//! Run one for longer:    cargo run --release --example ct_dudect -- --continuous decaps_valid_vs_tampered_768

use dudect_bencher::{
    ctbench_main,
    rand::RngExt,
    BenchRng, Class, CtRunner,
};
use moduletto::dit::with_dit;
use moduletto::kem::{ml_kem_512, ml_kem_768};
use moduletto::modn_ct::ConstantTimeOps;
use moduletto::{KyberCoeff, ModN, NTTPoly, KYBER_N};

/// Samples per benchmark across both classes (`DUDECT_SAMPLES` overrides).
fn samples() -> usize {
    std::env::var("DUDECT_SAMPLES").ok().and_then(|v| v.parse().ok()).unwrap_or(50_000)
}

/// `DUDECT_FIXED=zero` uses all-zero inputs for the fixed class of the
/// arithmetic benches (the dudect paper's choice); the default is one fixed
/// random input.
fn fixed_is_zero() -> bool {
    std::env::var("DUDECT_FIXED").map(|v| v == "zero").unwrap_or(false)
}

fn bytes32(rng: &mut BenchRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill(&mut b[..]);
    b
}

fn class(rng: &mut BenchRng) -> Class {
    if rng.random::<bool>() { Class::Left } else { Class::Right }
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
                    (cls, match cls {
                        Class::Left => fixed,
                        Class::Right => bytes32(rng),
                    })
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
    hw_mul64_zero_vs_random,
    hw_mul64_zero_vs_random_dit
);
