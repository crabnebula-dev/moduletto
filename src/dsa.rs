//! ML-DSA (FIPS 204) as a library API: ML-DSA-65.
//!
//! The API mirrors [`crate::kem`]: one module per parameter set, fixed-size
//! arrays for outputs and seeds, slices for keys and signatures, and the
//! randomness taken explicitly unless the `getrandom` feature is enabled.
//!
//! | | [`ml_dsa_65`] |
//! |---|---:|
//! | NIST security category | 3 |
//! | (k, ℓ), η, τ, λ | (6, 5), 4, 49, 192 |
//! | γ₁, γ₂, ω, d | 2¹⁹, (q − 1)/32, 55, 13 |
//! | public key `pk` | 1952 |
//! | private key `sk` | 4032 |
//! | signature `sig` | 3309 |
//!
//! Parameters are from FIPS 204 Table 1 and sizes from Table 2. The NIST ACVP
//! vectors in `tests/kat/` validate the parameter set (see
//! `tests/dsa_kat.rs`).
//!
//! # Interfaces
//!
//! * `keygen_internal(ξ)` is `ML-DSA.KeyGen_internal` (Algorithm 6).
//!   `keygen_internal_into` is the same, writing into caller-owned arrays.
//!   With the `getrandom` feature, `keygen()` and `keygen_into` are
//!   `ML-DSA.KeyGen` (Algorithm 1) in the same two forms.
//! * `sign` and `verify` are pure `ML-DSA.Sign` and `ML-DSA.Verify`
//!   (Algorithms 2 and 3). They take a context string of at most 255 bytes
//!   and form `M' = 0 ‖ |ctx| ‖ ctx ‖ M`.
//! * `sign_internal` and `verify_internal` are `ML-DSA.Sign_internal` and
//!   `ML-DSA.Verify_internal` (Algorithms 7 and 8). They take `M'` as given.
//! * `sign_mu` and `verify_mu` take the 64-byte message representative μ
//!   computed elsewhere (Algorithm 7 line 6, Algorithm 8 line 7).
//!   [`ml_dsa_65::external_mu`] computes μ for the pure interface.
//!
//! Signing takes `rnd` from the caller. Pass 32 zero bytes for the
//! deterministic variant (Algorithm 2 line 5) or 32 bytes from a CSPRNG for
//! the default hedged variant. With the `getrandom` feature, `keygen()` and
//! `sign_hedged()` draw `ξ` and `rnd` from the operating system instead.
//!
//! HashML-DSA (Algorithms 4 and 5, the pre-hash variant) is out of scope and
//! not provided.
//!
//! # Arithmetic
//!
//! Coefficients are `i32` modulo q = 8380417. The NTT is FIPS 204
//! Algorithms 41 and 42 with the zetas of Appendix B, held in Montgomery form
//! (R = 2³²) and reduced with the signed form of Algorithm 49
//! (`MontgomeryReduce`), as in the pq-crystals reference code. Every
//! reduction is branch-free shifts, multiplies and masks. The Rocq proofs in
//! `proofs/` cover the ML-KEM arithmetic only; they do not cover this NTT or
//! its reductions. Exhaustive and randomised unit tests check the reductions,
//! `Power2Round`, `Decompose` and the NTT against direct definitions.
//!
//! # Handling of secrets
//!
//! Key generation and signing derive secret data from the caller's ξ, `sk`
//! and `rnd`: ρ′, K, s₁, s₂, t₀, μ, ρ″, the mask y, w, c·s₁, c·s₂, c·t₀, the
//! rejected candidate signatures and the Keccak states. All of it is wiped
//! with [`zeroize`] before it goes out of scope, and the decoded private key
//! wipes itself on drop. The inputs themselves belong to the caller.
//!
//! After each key generation and signing, `scrub_stack` overwrites the
//! stack region the operation used, as in [`crate::kem`]. The cores run out
//! of line, below the frame that calls the scrub, so the scrub covers their
//! frames in every build profile (`tests/stack_scrub.rs`). That is a
//! best-effort measure, not a guarantee. `keygen_internal` and `keygen()`
//! return the private key by value as a plain array. The compiler may leave
//! copies of it in the entry point's own frames, above the scrubbed region,
//! where nothing can wipe them. `keygen_internal_into` and `keygen_into`
//! avoid those copies by encoding into storage you own. Either way, wrap the key in
//! [`zeroize::Zeroizing`] or wipe it yourself when you are done.
//!
//! No computation on secret data branches on it, indexes memory with it or
//! divides by it. `Decompose` and `Power2Round` use shifts and fixed-point
//! multiplies. `SampleInBall` places each ±1 with a masked pass over the whole
//! polynomial, through [`subtle`]. The four checks of the rejection loop
//! (Algorithm 7 lines 23 and 28) run over every coefficient on every
//! iteration and fold into one bit, so a rejection does not reveal which
//! check or which coefficient failed. Three decisions are made public by
//! design and are branched on:
//!
//! * whether a signing iteration is rejected, which sets the loop count
//!   (FIPS 204 allows the count to vary);
//! * whether a candidate nibble in `RejBoundedPoly` (Algorithm 31) is
//!   rejected;
//! * whether a candidate byte in `SampleInBall` (Algorithm 29) is rejected.
//!
//! Rejected candidates are independent of the accepted ones, so the last two
//! reveal nothing about s₁, s₂ or c. The accepted values are never branched
//! on.
//!
//! `ExpandA` samples the public matrix from the public seed ρ and is
//! variable-time, as `SampleNTT` is in ML-KEM.
//!
//! Verification treats its inputs as public and is not constant-time. FIPS
//! 204 section 3.6.3 notes that its intermediates can still be sensitive,
//! for example when the message is confidential. So verification wipes its
//! buffers for tr, μ, w′, the w₁′ encoding and the recomputed c̃ before it
//! returns, and computes μ in place rather than returning it by value. It
//! does not scrub the stack. Copies in callee frames, such as the Keccak
//! permutation's locals, or in compiler spill slots can therefore remain on
//! the stack after it returns.
//!
//! On AArch64 every key generation, signing and verification entry point
//! runs under [`crate::dit::with_dit`], as the ML-KEM entry points do.
//! [`ml_dsa_65::external_mu`] hashes only public inputs and does not.

#![allow(clippy::needless_range_loop)]

extern crate std;
use std::boxed::Box;

use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

#[cfg(target_arch = "aarch64")]
use crate::keccak::keccak_x2;
use crate::keccak::{shake256, ShakeStream};

/// Size of the key generation seed ξ.
pub const SEED_BYTES: usize = 32;
/// Size of the per-signature randomness `rnd`.
pub const RND_BYTES: usize = 32;
/// Size of the message representative μ.
pub const MU_BYTES: usize = 64;
/// Longest context string that Algorithms 2 and 3 accept.
pub const MAX_CONTEXT_BYTES: usize = 255;

/// Why an input was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsaError {
    /// A key had the wrong length.
    Length,
    /// The context string is longer than [`MAX_CONTEXT_BYTES`]
    /// (FIPS 204 Algorithm 2 line 1).
    Context,
    /// The operating system's random source failed (`getrandom` feature).
    Randomness,
}

impl core::fmt::Display for DsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DsaError::Length => f.write_str("ML-DSA: wrong input length"),
            DsaError::Context => f.write_str("ML-DSA: context string longer than 255 bytes"),
            DsaError::Randomness => f.write_str("ML-DSA: OS random source failed"),
        }
    }
}

impl std::error::Error for DsaError {}

/// FIPS 204 Algorithm 1 output size of `pk`: 32 + 32k(bitlen(q − 1) − d).
const fn pk_len(k: usize) -> usize {
    32 + 32 * k * (23 - 13)
}
/// FIPS 204 Algorithm 1 output size of `sk`:
/// 32 + 32 + 64 + 32((ℓ + k) bitlen(2η) + dk).
const fn sk_len(k: usize, l: usize, eta_bits: usize) -> usize {
    128 + 32 * ((l + k) * eta_bits + 13 * k)
}
/// FIPS 204 Algorithm 2 output size of `sig`:
/// λ/4 + 32ℓ(1 + bitlen(γ₁ − 1)) + ω + k.
const fn sig_len(k: usize, l: usize, lambda: usize, gamma1_bits: usize, omega: usize) -> usize {
    lambda / 4 + 32 * l * (1 + gamma1_bits) + omega + k
}

/// ML-DSA-65 (FIPS 204).
pub mod ml_dsa_65 {
    use super::{DsaError, MAX_CONTEXT_BYTES, MU_BYTES, RND_BYTES, SEED_BYTES};

    /// Size of a public key (FIPS 204 Table 2).
    pub const PK_BYTES: usize = super::pk_len(6);
    /// Size of a private key (FIPS 204 Table 2).
    pub const SK_BYTES: usize = super::sk_len(6, 5, 4);
    /// Size of a signature (FIPS 204 Table 2).
    pub const SIG_BYTES: usize = super::sig_len(6, 5, 192, 19, 55);

    /// FIPS 204 `ML-DSA.KeyGen_internal(ξ)` (Algorithm 6): returns `(pk, sk)`.
    ///
    /// `xi` must be 32 bytes from a CSPRNG. The returned `sk` is secret:
    /// wipe it when you are done with it.
    ///
    /// The arrays are returned by value, so the compiler may leave copies of
    /// `sk` in the entry point's own frames, where the stack scrub does not
    /// reach. Use [`keygen_internal_into`] to write `sk` straight into
    /// storage you own, such as a [`zeroize::Zeroizing`] box.
    pub fn keygen_internal(xi: &[u8; SEED_BYTES]) -> ([u8; PK_BYTES], [u8; SK_BYTES]) {
        let mut pk = [0u8; PK_BYTES];
        let mut sk = [0u8; SK_BYTES];
        keygen_internal_into(xi, &mut pk, &mut sk);
        (pk, sk)
    }

    /// FIPS 204 `ML-DSA.KeyGen_internal(ξ)` (Algorithm 6) into caller-owned
    /// `pk` and `sk`.
    ///
    /// The key is encoded in place, so no copy of `sk` is left on the stack
    /// above the scrubbed region. Both arrays are overwritten in full.
    pub fn keygen_internal_into(
        xi: &[u8; SEED_BYTES],
        pk: &mut [u8; PK_BYTES],
        sk: &mut [u8; SK_BYTES],
    ) {
        crate::dit::with_dit(|| {
            super::keygen(xi, pk, sk);
            super::scrub_stack();
            // pk, and the copies of ρ and tr inside sk, are public.
            super::declassify(&pk[..]);
            super::declassify(&sk[..32]);
            super::declassify(&sk[64..128]);
        })
    }

    /// FIPS 204 `ML-DSA.KeyGen()` (Algorithm 1): draws ξ from the operating
    /// system's CSPRNG and returns `(pk, sk)`. Requires the `getrandom`
    /// feature.
    ///
    /// As with [`keygen_internal`], the arrays are returned by value. The
    /// compiler may leave copies of `sk` in the entry point's own frames,
    /// where the stack scrub does not reach. Use [`keygen_into`] to write
    /// `sk` straight into storage you own, such as a
    /// [`zeroize::Zeroizing`] box.
    #[cfg(feature = "getrandom")]
    pub fn keygen() -> Result<([u8; PK_BYTES], [u8; SK_BYTES]), DsaError> {
        let mut pk = [0u8; PK_BYTES];
        let mut sk = [0u8; SK_BYTES];
        keygen_into(&mut pk, &mut sk)?;
        Ok((pk, sk))
    }

    /// FIPS 204 `ML-DSA.KeyGen()` (Algorithm 1) into caller-owned `pk` and
    /// `sk`, with ξ drawn from the operating system's CSPRNG. Requires the
    /// `getrandom` feature.
    ///
    /// This calls [`keygen_internal_into`], so no copy of `sk` is left on
    /// the stack above the scrubbed region. On success both arrays are
    /// overwritten in full. If the CSPRNG fails, neither array is touched.
    #[cfg(feature = "getrandom")]
    pub fn keygen_into(pk: &mut [u8; PK_BYTES], sk: &mut [u8; SK_BYTES]) -> Result<(), DsaError> {
        let mut xi = zeroize::Zeroizing::new([0u8; SEED_BYTES]);
        super::os_random(&mut *xi)?;
        keygen_internal_into(&xi, pk, sk);
        Ok(())
    }

    /// FIPS 204 `ML-DSA.Sign(sk, M, ctx)` (Algorithm 2) with `rnd` supplied
    /// by the caller.
    ///
    /// Pass `rnd` = 32 zero bytes for the deterministic variant, or 32 bytes
    /// from a CSPRNG for the hedged variant. Fails with
    /// [`DsaError::Context`] if `ctx` is longer than 255 bytes and with
    /// [`DsaError::Length`] if `sk` is not [`SK_BYTES`] long.
    pub fn sign(
        sk: &[u8],
        m: &[u8],
        ctx: &[u8],
        rnd: &[u8; RND_BYTES],
    ) -> Result<[u8; SIG_BYTES], DsaError> {
        if ctx.len() > MAX_CONTEXT_BYTES {
            return Err(DsaError::Context);
        }
        // Algorithm 2 line 10: M' = 0 ‖ |ctx| ‖ ctx ‖ M, absorbed in parts.
        let prefix = [0u8, ctx.len() as u8];
        super::sign_entry(sk, &[&prefix, ctx, m], None, rnd)
    }

    /// FIPS 204 `ML-DSA.Sign(sk, M, ctx)` (Algorithm 2), hedged, with `rnd`
    /// drawn from the operating system's CSPRNG. Requires the `getrandom`
    /// feature.
    #[cfg(feature = "getrandom")]
    pub fn sign_hedged(sk: &[u8], m: &[u8], ctx: &[u8]) -> Result<[u8; SIG_BYTES], DsaError> {
        if ctx.len() > MAX_CONTEXT_BYTES {
            return Err(DsaError::Context);
        }
        if sk.len() != SK_BYTES {
            return Err(DsaError::Length);
        }
        let mut rnd = zeroize::Zeroizing::new([0u8; RND_BYTES]);
        super::os_random(&mut *rnd)?;
        sign(sk, m, ctx, &rnd)
    }

    /// FIPS 204 `ML-DSA.Sign_internal(sk, M', rnd)` (Algorithm 7).
    ///
    /// `m_prime` is the formatted message M'; no context string is added.
    /// Fails with [`DsaError::Length`] if `sk` is not [`SK_BYTES`] long.
    pub fn sign_internal(
        sk: &[u8],
        m_prime: &[u8],
        rnd: &[u8; RND_BYTES],
    ) -> Result<[u8; SIG_BYTES], DsaError> {
        super::sign_entry(sk, &[m_prime], None, rnd)
    }

    /// FIPS 204 `ML-DSA.Sign_internal` (Algorithm 7) with the message
    /// representative μ computed elsewhere, so line 6 is skipped.
    /// Fails with [`DsaError::Length`] if `sk` is not [`SK_BYTES`] long.
    pub fn sign_mu(
        sk: &[u8],
        mu: &[u8; MU_BYTES],
        rnd: &[u8; RND_BYTES],
    ) -> Result<[u8; SIG_BYTES], DsaError> {
        super::sign_entry(sk, &[], Some(mu), rnd)
    }

    /// The message representative μ = H(H(pk, 64) ‖ M', 64) of the pure
    /// interface, with M' = 0 ‖ |ctx| ‖ ctx ‖ M (Algorithm 2 line 10,
    /// Algorithm 7 line 6). Feed the result to [`sign_mu`] or [`verify_mu`].
    ///
    /// Fails with [`DsaError::Context`] if `ctx` is longer than 255 bytes and
    /// with [`DsaError::Length`] if `pk` is not [`PK_BYTES`] long. It hashes
    /// only public inputs and does not run under [`crate::dit::with_dit`].
    pub fn external_mu(pk: &[u8], m: &[u8], ctx: &[u8]) -> Result<[u8; MU_BYTES], DsaError> {
        if ctx.len() > MAX_CONTEXT_BYTES {
            return Err(DsaError::Context);
        }
        if pk.len() != PK_BYTES {
            return Err(DsaError::Length);
        }
        let mut tr = [0u8; 64];
        super::shake256(&[pk], &mut tr);
        let prefix = [0u8, ctx.len() as u8];
        let mut mu = [0u8; MU_BYTES];
        super::message_representative(&tr, &[&prefix, ctx, m], &mut mu);
        Ok(mu)
    }

    /// FIPS 204 `ML-DSA.Verify(pk, M, σ, ctx)` (Algorithm 3).
    ///
    /// The arguments come in the order `(pk, m, ctx, sig)`, the same as
    /// [`sign`] takes `(sk, m, ctx, …)`. That differs from the order in
    /// FIPS 204, where σ comes before ctx.
    ///
    /// Returns `false` for a wrong-length `pk` or `sig` (FIPS 204 section
    /// 3.6.2) and for a context string longer than 255 bytes.
    pub fn verify(pk: &[u8], m: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        if ctx.len() > MAX_CONTEXT_BYTES {
            return false;
        }
        let prefix = [0u8, ctx.len() as u8];
        super::verify_entry(pk, &[&prefix, ctx, m], None, sig)
    }

    /// FIPS 204 `ML-DSA.Verify_internal(pk, M', σ)` (Algorithm 8).
    /// Returns `false` for a wrong-length `pk` or `sig`.
    pub fn verify_internal(pk: &[u8], m_prime: &[u8], sig: &[u8]) -> bool {
        super::verify_entry(pk, &[m_prime], None, sig)
    }

    /// FIPS 204 `ML-DSA.Verify_internal` (Algorithm 8) with the message
    /// representative μ computed elsewhere, so lines 6 and 7 are skipped.
    /// Returns `false` for a wrong-length `pk` or `sig`.
    pub fn verify_mu(pk: &[u8], mu: &[u8; MU_BYTES], sig: &[u8]) -> bool {
        super::verify_entry(pk, &[], Some(mu), sig)
    }
}

use ml_dsa_65::{PK_BYTES, SIG_BYTES, SK_BYTES};

// ── Parameters (FIPS 204 Table 1, ML-DSA-65) ─────────────────────────────────

const Q: i32 = 8_380_417;
const N: usize = 256;
/// Dropped bits of t.
const D: u32 = 13;
const K: usize = 6;
const L: usize = 5;
const ETA: i32 = 4;
const TAU: usize = 49;
/// Length of the commitment hash c̃: λ/4 bytes with λ = 192.
const CTILDE_BYTES: usize = 192 / 4;
const GAMMA1: i32 = 1 << 19;
const GAMMA2: i32 = (Q - 1) / 32;
/// β = τ·η.
const BETA: i32 = TAU as i32 * ETA;
const OMEGA: usize = 55;

/// Bit widths of the encodings: t₁ (bitlen(q − 1) − d), s₁ and s₂
/// (bitlen 2η), t₀ (d), z (1 + bitlen(γ₁ − 1)) and w₁
/// (bitlen((q − 1)/(2γ₂) − 1)).
const T1_BITS: u32 = 10;
const ETA_BITS: u32 = 4;
const T0_BITS: u32 = D;
const Z_BITS: u32 = 20;
const W1_BITS: u32 = 4;

const T1_POLY_BYTES: usize = 32 * T1_BITS as usize;
const ETA_POLY_BYTES: usize = 32 * ETA_BITS as usize;
const T0_POLY_BYTES: usize = 32 * T0_BITS as usize;
const Z_POLY_BYTES: usize = 32 * Z_BITS as usize;
const W1_POLY_BYTES: usize = 32 * W1_BITS as usize;

// Offsets inside sk (Algorithm 24) and σ (Algorithm 26).
const SK_S1: usize = 128;
const SK_S2: usize = SK_S1 + L * ETA_POLY_BYTES;
const SK_T0: usize = SK_S2 + K * ETA_POLY_BYTES;
const SIG_Z: usize = CTILDE_BYTES;
const SIG_H: usize = SIG_Z + L * Z_POLY_BYTES;

const _: () = assert!(32 + K * T1_POLY_BYTES == PK_BYTES);
const _: () = assert!(SK_T0 + K * T0_POLY_BYTES == SK_BYTES);
const _: () = assert!(SIG_H + OMEGA + K == SIG_BYTES);

type Poly = [i32; N];
type Matrix = [[Poly; L]; K];

#[cfg(feature = "getrandom")]
fn os_random(buf: &mut [u8]) -> Result<(), DsaError> {
    getrandom::fill(buf).map_err(|_| DsaError::Randomness)
}

/// Overwrite the stack region below the caller's frame.
///
/// The same measure as `kem::scrub_stack` (libsodium's `sodium_stackzero`),
/// sized for ML-DSA. Signing keeps the decoded private key, the mask y and
/// its NTT, w, z, the hint and the c·s products on the stack. The compiler
/// adds copies and spills. The cores [`keygen`] and [`sign`] are kept out
/// of line, so their frames lie below the frame that calls this function.
///
/// The sizes were measured on Apple M5 by painting the stack and finding the
/// deepest overwritten byte, counted from the stack pointer of the frame
/// that calls this function. Key generation reached about 41 KiB in the
/// release profile and 97 KiB in the debug profile. Signing reached about
/// 71 KiB and 133 KiB. 192 KiB covers the debug figures with margin.
/// `tests/stack_scrub.rs` checks the coverage in both profiles.
/// The public matrix Â lives on the heap and is not scrubbed.
///
/// This shares the limits of the ML-KEM scrub: it reaches only the stack of
/// this thread, below this frame, and only memory, not registers that the OS
/// or a signal handler may have saved elsewhere.
#[inline(never)]
fn scrub_stack() {
    const BYTES: usize = SCRUB_BYTES;
    let mut buf = core::mem::MaybeUninit::<[u8; BYTES]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;
    // SAFETY: `p` points to `BYTES` writable bytes owned by this frame.
    unsafe { core::ptr::write_bytes(p, 0, BYTES) };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::hint::black_box(p);
}

/// Bytes overwritten by [`scrub_stack`].
const SCRUB_BYTES: usize = 192 * 1024;

/// Mark derived-but-public data as defined for the ctgrind-style check.
/// A no-op unless the `valgrind-ct` feature is enabled.
#[inline(always)]
fn declassify<T: ?Sized>(_x: &T) {
    #[cfg(feature = "valgrind-ct")]
    crate::valgrind::declassify(_x);
}

/// A secret-derived decision that the algorithm makes public by design (see
/// the module documentation). The value is returned unchanged. With the
/// `valgrind-ct` feature it passes through memory and is declassified there,
/// so that memcheck accepts the branch that follows.
#[inline(always)]
fn public_bool(b: bool) -> bool {
    #[cfg(feature = "valgrind-ct")]
    let b = {
        let mut v = 0u8;
        // SAFETY: `v` is a live local; volatile keeps the round trip through
        // memory, which is where memcheck's definedness is reset.
        unsafe { core::ptr::write_volatile(&mut v, b as u8) };
        crate::valgrind::declassify(&v);
        // SAFETY: as above.
        unsafe { core::ptr::read_volatile(&v) != 0 }
    };
    b
}

// ── Modular arithmetic ──────────────────────────────────────────────────────

/// q⁻¹ mod 2³² (FIPS 204 Algorithm 49 line 1).
const QINV: i32 = 58_728_449;

/// a·2⁻³² mod q: the signed-remainder variant of FIPS 204 Algorithm 49
/// (`MontgomeryReduce`), as in the pq-crystals reference code.
///
/// Algorithm 49 takes t = (a mod 2³²)·QINV mod 2³² as an unsigned value and
/// bounds its result only by 2q in absolute value. Here t is the centred
/// representative, a signed i32, and the result lies in (−q, q) for
/// |a| < 2³¹·q. The bounds in [`ntt`], [`invntt_tomont`],
/// [`matrix_row_times`] and [`verify`] rely on (−q, q). Switching to the
/// unsigned form would break them. `tests::montgomery_constants` checks the
/// range. Every caller stays far below the input bound.
#[inline(always)]
fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV);
    ((a - t as i64 * Q as i64) >> 32) as i32
}

/// A representative of a mod q in [−6283009, 6283008], for
/// a ≤ 2³¹ − 2²² − 1. Branch-free: the quotient is a rounding shift by 23,
/// since 2²³ − q = 8191 is small.
#[inline(always)]
fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * Q
}

/// Adds q if a is negative.
#[inline(always)]
fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & Q)
}

/// The representative of a mod q in [0, q).
#[inline(always)]
fn freeze(a: i32) -> i32 {
    caddq(reduce32(a))
}

/// a mod± q: the representative in [−(q − 1)/2, (q − 1)/2].
#[inline(always)]
fn center(a: i32) -> i32 {
    let a = freeze(a);
    a - ((((Q - 1) / 2 - a) >> 31) & Q)
}

/// 1 if |a| ≥ bound, else 0, for a centred a, without a branch.
#[inline(always)]
fn exceeds(a: i32, bound: i32) -> u32 {
    let m = a >> 31;
    let abs = (a ^ m) - m;
    ((bound - 1 - abs) >> 31) as u32 & 1
}

// ── NTT (FIPS 204 Algorithms 41 and 42) ─────────────────────────────────────

/// FIPS 204 Appendix B: zetas[k] = ζ^BitRev8(k) mod q with ζ = 1753.
/// `tests::zetas_are_powers_of_1753` recomputes every entry.
#[rustfmt::skip]
const ZETAS: [i32; N] = [
          0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
    7778734, 3542485, 2682288, 2129892, 3764867, 7375178,  557458, 7159240,
    5010068, 4317364, 2663378, 6705802, 4855975, 7946292,  676590, 7044481,
    5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
    3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
     394148,  928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
    3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
    5483103, 3192354,  556856, 3870317, 2917338, 1853806, 3345963, 1858416,
    3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
    2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
    1528066,  482649, 1148858, 5418153, 7814814,  169688, 2462444, 5046034,
    4213992, 4892034, 1987814, 5183169, 1736313,  235407, 5130263, 3258457,
    5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
    7062739, 2461387, 3035980,  621164, 3901472, 7153756, 2925816, 3374250,
    1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
     348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
       1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
    1182243,   87208,  636927, 4415111, 4423672, 6084020, 5095502, 4663471,
    8352605,  822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
    6695264, 4969849, 2678278, 4611469, 4829411,  635956, 8129971, 5925040,
    4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
    3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
    2998219,  141835, 8291116, 2513018, 7025525,  613238, 7070156, 6161950,
    7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
    6757063, 2105286, 6006015, 6346610,  586241, 7200804,  527981, 5637006,
    6903432, 1994046, 2491325, 6987258,  507927, 7192532, 7655613, 6545891,
    5346675, 8041997, 2647994, 3009748, 5767564, 4148469,  749577, 4357667,
    3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
    3994671, 8368538, 7009900, 3020393, 3363542,  214880,  545376, 7609976,
    3105558, 7277073,  508145, 7826699,  860144, 3430436,  140244, 6866265,
    6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
    8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
];

/// The zetas in Montgomery form, zetas[k]·2³² mod q, computed at compile time.
const ZETAS_MONT: [i32; N] = {
    let mut out = [0i32; N];
    let mut k = 0;
    while k < N {
        out[k] = ((ZETAS[k] as i64 * (1i64 << 32)) % Q as i64) as i32;
        k += 1;
    }
    out
};

/// 2⁶⁴/256 mod q: Algorithm 42's f = 256⁻¹ times R² for Montgomery form.
const INV256_MONT2: i64 = {
    // 256⁻¹ mod q = 8347681 (Algorithm 42 line 21); R² mod q by doubling.
    let r = (1i64 << 32) % Q as i64;
    let r2 = r * r % Q as i64;
    r2 * 8_347_681 % Q as i64
};

/// FIPS 204 Algorithm 41, in place. The output is in bit-reversed order and
/// not reduced: each layer adds less than q in absolute value, so an input
/// below q in absolute value leaves an output below 9q.
fn ntt(w: &mut Poly) {
    let mut m = 0;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            m += 1;
            let z = ZETAS_MONT[m] as i64;
            for j in start..start + len {
                let t = montgomery_reduce(z * w[j + len] as i64);
                w[j + len] = w[j] - t;
                w[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// FIPS 204 Algorithm 42, in place, with the result multiplied by the
/// Montgomery factor 2³² mod q. Applied to a product of two NTTs formed with
/// [`montgomery_reduce`], the two factors cancel. The input must be below q
/// in absolute value; the output is in (−q, q).
fn invntt_tomont(w: &mut Poly) {
    let mut m = 256;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            m -= 1;
            let z = -(ZETAS_MONT[m] as i64);
            for j in start..start + len {
                let t = w[j];
                w[j] = t + w[j + len];
                w[j + len] = montgomery_reduce(z * (t - w[j + len]) as i64);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in w.iter_mut() {
        *c = montgomery_reduce(INV256_MONT2 * *c as i64);
    }
}

/// a ∘ b / 2³² (FIPS 204 Algorithm 45 in Montgomery form), accumulated into
/// `acc`.
#[inline(always)]
fn pointwise_acc(acc: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        acc[i] += montgomery_reduce(a[i] as i64 * b[i] as i64);
    }
}

/// a ∘ b / 2³² into `out`.
#[inline(always)]
fn pointwise(out: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        out[i] = montgomery_reduce(a[i] as i64 * b[i] as i64);
    }
}

/// Row i of Â ∘ v̂ followed by NTT⁻¹, reduced to [0, q). With Â from
/// [`expand_a`] (coefficients in [0, q)) and v̂ from [`ntt`] (below 9q), each
/// product is below q, the five-term sum below 5q, and [`reduce32`] brings it
/// below q for [`invntt_tomont`].
fn matrix_row_times(out: &mut Poly, row: &[Poly; L], v_hat: &[Poly; L]) {
    *out = [0; N];
    for j in 0..L {
        pointwise_acc(out, &row[j], &v_hat[j]);
    }
    for c in out.iter_mut() {
        *c = reduce32(*c);
    }
    invntt_tomont(out);
    for c in out.iter_mut() {
        *c = caddq(*c);
    }
}

// ── Rounding (FIPS 204 Algorithms 35 to 40) ─────────────────────────────────

/// FIPS 204 Algorithm 35 for r in [0, q): (r₁, r₀) with r = r₁·2^d + r₀ and
/// r₀ in (−2^(d−1), 2^(d−1)]. Branch-free.
#[inline(always)]
fn power2round(r: i32) -> (i32, i32) {
    let r1 = (r + (1 << (D - 1)) - 1) >> D;
    (r1, r - (r1 << D))
}

/// FIPS 204 Algorithm 36 for r in [0, q) and γ₂ = (q − 1)/32. Branch-free and
/// division-free: r₁ = round(r / 2γ₂) is a fixed-point multiply (the
/// pq-crystals formula), the wrap from (q − 1)/2γ₂ = 16 to 0 is a mask, and
/// the matching r₀ − 1 of line 5 is a masked subtraction of q.
/// `tests::decompose_matches_algorithm_36` checks every r in [0, q).
#[inline(always)]
fn decompose(r: i32) -> (i32, i32) {
    let mut r1 = (r + 127) >> 7;
    r1 = (r1 * 1025 + (1 << 21)) >> 22;
    r1 &= 15;
    let mut r0 = r - r1 * 2 * GAMMA2;
    r0 -= (((Q - 1) / 2 - r0) >> 31) & Q;
    (r1, r0)
}

/// FIPS 204 Algorithm 40 for r in [0, q). Used by verification only, on
/// public data, so it branches.
#[inline(always)]
fn use_hint(h: bool, r: i32) -> i32 {
    let (r1, r0) = decompose(r);
    match (h, r0 > 0) {
        (false, _) => r1,
        // mod m with m = (q − 1)/2γ₂ = 16.
        (true, true) => (r1 + 1) & 15,
        (true, false) => (r1 - 1) & 15,
    }
}

// ── Bit packing (FIPS 204 Algorithms 16 to 19) ──────────────────────────────

/// SimpleBitPack (Algorithm 16) for coefficients in [0, 2^bits): each one
/// contributes `bits` bits, least significant first (IntegerToBits), and the
/// bit string becomes bytes least significant bit first (BitsToBytes). The
/// loop shape depends only on `bits`.
fn pack(w: &Poly, bits: u32, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * bits as usize);
    let mask = (1u64 << bits) - 1;
    let mut acc = 0u64;
    let mut have = 0u32;
    let mut o = 0;
    for &c in w.iter() {
        acc |= (c as u32 as u64 & mask) << have;
        have += bits;
        while have >= 8 {
            out[o] = acc as u8;
            o += 1;
            acc >>= 8;
            have -= 8;
        }
    }
    acc.zeroize();
}

/// SimpleBitUnpack (Algorithm 18): the inverse of [`pack`]. Every output is
/// in [0, 2^bits).
fn unpack(v: &[u8], bits: u32, w: &mut Poly) {
    debug_assert_eq!(v.len(), 32 * bits as usize);
    let mask = (1u64 << bits) - 1;
    let mut acc = 0u64;
    let mut have = 0u32;
    let mut i = 0;
    for c in w.iter_mut() {
        while have < bits {
            acc |= (v[i] as u64) << have;
            i += 1;
            have += 8;
        }
        *c = (acc & mask) as i32;
        acc >>= bits;
        have -= bits;
    }
    acc.zeroize();
}

/// BitPack(w, a, b) (Algorithm 17): SimpleBitPack of b − w.
fn bit_pack(w: &Poly, b: i32, bits: u32, out: &mut [u8]) {
    let mut t: Poly = core::array::from_fn(|i| b - w[i]);
    pack(&t, bits, out);
    t.zeroize();
}

/// BitUnpack(v, a, b) (Algorithm 19): b minus SimpleBitUnpack.
fn bit_unpack(v: &[u8], b: i32, bits: u32, w: &mut Poly) {
    unpack(v, bits, w);
    for c in w.iter_mut() {
        *c = b - *c;
    }
}

/// FIPS 204 Algorithm 20. The hint is public once the signature is accepted.
fn hint_bit_pack(h: &[Poly; K], y: &mut [u8]) {
    debug_assert_eq!(y.len(), OMEGA + K);
    y.fill(0);
    let mut index = 0;
    for i in 0..K {
        for j in 0..N {
            if h[i][j] != 0 {
                y[index] = j as u8;
                index += 1;
            }
        }
        y[OMEGA + i] = index as u8;
    }
}

/// FIPS 204 Algorithm 21, rejecting every malformed encoding it names:
/// a count that decreases or exceeds ω (line 4), indices that do not
/// strictly increase within a polynomial (line 9), and nonzero padding
/// (line 17). `None` is ⊥.
fn hint_bit_unpack(y: &[u8]) -> Option<[Poly; K]> {
    debug_assert_eq!(y.len(), OMEGA + K);
    let mut h = [[0i32; N]; K];
    let mut index = 0usize;
    for i in 0..K {
        let end = y[OMEGA + i] as usize;
        if end < index || end > OMEGA {
            return None;
        }
        let first = index;
        while index < end {
            if index > first && y[index - 1] >= y[index] {
                return None;
            }
            h[i][y[index] as usize] = 1;
            index += 1;
        }
    }
    if y[index..OMEGA].iter().any(|&b| b != 0) {
        return None;
    }
    Some(h)
}

// ── Sampling (FIPS 204 Algorithms 29 to 34) ─────────────────────────────────

/// Consume 3-byte groups of a SHAKE128 block as CoeffFromThreeBytes
/// (Algorithm 14) candidates, keeping those below q. Returns the new count.
/// The rate (168) is a multiple of 3, so consuming the stream block by block
/// yields the coefficients of Algorithm 30 exactly. Public data only.
#[inline(always)]
fn rej_ntt_candidates(buf: &[u8], a: &mut Poly, mut j: usize) -> usize {
    let mut pos = 0;
    while pos + 3 <= buf.len() && j < N {
        let z = (buf[pos] as u32)
            | ((buf[pos + 1] as u32) << 8)
            | (((buf[pos + 2] & 0x7f) as u32) << 16);
        pos += 3;
        if z < Q as u32 {
            a[j] = z as i32;
            j += 1;
        }
    }
    j
}

/// FIPS 204 Algorithm 30 (RejNTTPoly) on ρ ‖ s ‖ r, the seed of Â[r, s]
/// (Algorithm 32 line 3).
fn rej_ntt_poly(rho: &[u8; 32], r: usize, s: usize, a: &mut Poly) {
    let mut xof = ShakeStream::new(168, &[rho.as_slice(), &[s as u8, r as u8]], 0x1f);
    let mut block = [0u8; 168];
    let mut j = 0;
    while j < N {
        xof.squeeze_block(&mut block);
        j = rej_ntt_candidates(&block, a, j);
    }
}

/// Two matrix entries at once through the two-lane SHA3 sponge, falling
/// back to [`rej_ntt_poly`] without FEAT_SHA3.
#[cfg(target_arch = "aarch64")]
fn rej_ntt_poly_pair(
    rho: &[u8; 32],
    e0: (usize, usize),
    e1: (usize, usize),
    a0: &mut Poly,
    a1: &mut Poly,
) {
    if !keccak_x2::available() {
        rej_ntt_poly(rho, e0.0, e0.1, a0);
        rej_ntt_poly(rho, e1.0, e1.1, a1);
        return;
    }
    let mut m0 = [0u8; 34];
    let mut m1 = [0u8; 34];
    m0[..32].copy_from_slice(rho);
    m1[..32].copy_from_slice(rho);
    (m0[32], m0[33]) = (e0.1 as u8, e0.0 as u8);
    (m1[32], m1[33]) = (e1.1 as u8, e1.0 as u8);
    let (mut b0, mut b1) = ([0u8; 168], [0u8; 168]);
    let (mut j0, mut j1) = (0, 0);
    // SAFETY: FEAT_SHA3 confirmed above; the messages are 34 < 168 bytes.
    unsafe {
        let mut xof = keccak_x2::ShakeX2::new(168, &m0, &m1, 0x1f);
        while j0 < N || j1 < N {
            xof.squeeze_block(&mut b0, &mut b1);
            j0 = rej_ntt_candidates(&b0, a0, j0);
            j1 = rej_ntt_candidates(&b1, a1, j1);
        }
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn rej_ntt_poly_pair(
    rho: &[u8; 32],
    e0: (usize, usize),
    e1: (usize, usize),
    a0: &mut Poly,
    a1: &mut Poly,
) {
    rej_ntt_poly(rho, e0.0, e0.1, a0);
    rej_ntt_poly(rho, e1.0, e1.1, a1);
}

/// FIPS 204 Algorithm 32 (ExpandA). Â is public and large (30 KiB), so it
/// lives on the heap. Entries are sampled two at a time in row-major order.
fn expand_a(rho: &[u8; 32]) -> Box<Matrix> {
    const _: () = assert!((K * L).is_multiple_of(2));
    let mut a: Box<Matrix> = Box::new([[[0; N]; L]; K]);
    let (mut p0, mut p1) = ([0; N], [0; N]);
    for idx in (0..K * L).step_by(2) {
        let (e0, e1) = ((idx / L, idx % L), ((idx + 1) / L, (idx + 1) % L));
        rej_ntt_poly_pair(rho, e0, e1, &mut p0, &mut p1);
        a[e0.0][e0.1] = p0;
        a[e1.0][e1.1] = p1;
    }
    a
}

/// One SHAKE256 block of RejBoundedPoly (Algorithm 31) candidates with
/// η = 4: CoeffFromHalfByte (Algorithm 15) accepts b < 9 as 4 − b.
///
/// The bytes are secret. The value 4 − b is computed without a branch; only
/// the accept decision is branched on, through [`public_bool`]. A rejected
/// nibble is independent of the accepted ones, so the decision reveals
/// nothing about the coefficients.
#[inline(always)]
fn rej_eta_candidates(buf: &[u8], a: &mut Poly, mut j: usize) -> usize {
    for &z in buf {
        if j >= N {
            break;
        }
        let (z0, z1) = ((z & 15) as i32, (z >> 4) as i32);
        if public_bool(z0 < 9) {
            a[j] = ETA - z0;
            j += 1;
        }
        if public_bool(z1 < 9) && j < N {
            a[j] = ETA - z1;
            j += 1;
        }
    }
    j
}

/// FIPS 204 Algorithm 31 (RejBoundedPoly) on ρ′ ‖ IntegerToBytes(r, 2).
fn rej_bounded_poly(rho_prime: &[u8; 64], r: u16, a: &mut Poly) {
    let mut xof = ShakeStream::new(136, &[rho_prime.as_slice(), &r.to_le_bytes()], 0x1f);
    let mut block = [0u8; 136];
    let mut j = 0;
    while j < N {
        xof.squeeze_block(&mut block);
        j = rej_eta_candidates(&block, a, j);
    }
    block.zeroize();
}

/// FIPS 204 Algorithm 33 (ExpandS).
fn expand_s(rho_prime: &[u8; 64], s1: &mut [Poly; L], s2: &mut [Poly; K]) {
    for r in 0..L {
        rej_bounded_poly(rho_prime, r as u16, &mut s1[r]);
    }
    for r in 0..K {
        rej_bounded_poly(rho_prime, (r + L) as u16, &mut s2[r]);
    }
}

/// FIPS 204 Algorithm 34 (ExpandMask): y[r] = BitUnpack(H(ρ″ ‖ κ + r, 640),
/// γ₁ − 1, γ₁). A fixed-length squeeze and an unpack: no rejection.
fn expand_mask(rho2: &[u8; 64], kappa: u16, y: &mut [Poly; L]) {
    let mut v = [0u8; Z_POLY_BYTES];
    for r in 0..L {
        // Line 3: IntegerToBytes(κ + r, 2) (Algorithm 11) encodes
        // κ + r mod 2¹⁶, so the counter wraps exactly as the standard says.
        // Reaching 2¹⁶ takes 13 107 rejections in a row.
        let nonce = kappa.wrapping_add(r as u16);
        shake256(&[rho2.as_slice(), &nonce.to_le_bytes()], &mut v);
        bit_unpack(&v, GAMMA1, Z_BITS, &mut y[r]);
    }
    v.zeroize();
}

/// FIPS 204 Algorithm 29 (SampleInBall) with τ = 49.
///
/// In signing, c̃ is secret until its iteration is accepted. The byte j at
/// line 7 is secret, so the swap of lines 11 and 12 is a masked pass over
/// c[0..=i] through [`subtle`] instead of two indexed accesses. The
/// rejection of line 8 (j > i) is a public decision, as in
/// [`rej_eta_candidates`]: rejected bytes are independent of the accepted j.
fn sample_in_ball(ctilde: &[u8; CTILDE_BYTES]) -> Poly {
    let mut xof = ShakeStream::new(136, &[ctilde.as_slice()], 0x1f);
    let mut block = [0u8; 136];
    xof.squeeze_block(&mut block);
    let mut signs = u64::from_le_bytes(block[..8].try_into().unwrap());
    let mut pos = 8;
    let mut c = [0i32; N];
    for i in N - TAU..N {
        let j = loop {
            if pos == block.len() {
                xof.squeeze_block(&mut block);
                pos = 0;
            }
            let b = block[pos];
            pos += 1;
            if public_bool(b as usize <= i) {
                break b as u32;
            }
        };
        // c_i ← c_j, then c_j ← (−1)^h[i + τ − 256].
        let sign = 1 - 2 * ((signs >> (i + TAU - N)) & 1) as i32;
        let mut cj = 0i32;
        for t in 0..=i {
            cj.conditional_assign(&c[t], (t as u32).ct_eq(&j));
        }
        c[i] = cj;
        for t in 0..=i {
            c[t].conditional_assign(&sign, (t as u32).ct_eq(&j));
        }
    }
    signs.zeroize();
    block.zeroize();
    c
}

// ── Keys ────────────────────────────────────────────────────────────────────

/// The decoded private key (FIPS 204 Algorithm 25). Wipes K, s₁, s₂ and t₀
/// on drop.
struct SecretKey {
    rho: [u8; 32],
    key: [u8; 32],
    tr: [u8; 64],
    s1: [Poly; L],
    s2: [Poly; K],
    t0: [Poly; K],
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.s1.zeroize();
        self.s2.zeroize();
        self.t0.zeroize();
    }
}

/// FIPS 204 Algorithm 25 (skDecode). The caller has checked the length. A
/// malformed key can give s₁ and s₂ coefficients outside [−η, η], as the
/// standard notes. Signing still terminates. It produces a signature that
/// the matching public key, if any, does not verify.
fn sk_decode(sk: &[u8]) -> SecretKey {
    debug_assert_eq!(sk.len(), SK_BYTES);
    let mut key = SecretKey {
        rho: [0; 32],
        key: [0; 32],
        tr: [0; 64],
        s1: [[0; N]; L],
        s2: [[0; N]; K],
        t0: [[0; N]; K],
    };
    key.rho.copy_from_slice(&sk[..32]);
    key.key.copy_from_slice(&sk[32..64]);
    key.tr.copy_from_slice(&sk[64..128]);
    for i in 0..L {
        let at = SK_S1 + i * ETA_POLY_BYTES;
        bit_unpack(&sk[at..at + ETA_POLY_BYTES], ETA, ETA_BITS, &mut key.s1[i]);
    }
    for i in 0..K {
        let at = SK_S2 + i * ETA_POLY_BYTES;
        bit_unpack(&sk[at..at + ETA_POLY_BYTES], ETA, ETA_BITS, &mut key.s2[i]);
    }
    for i in 0..K {
        let at = SK_T0 + i * T0_POLY_BYTES;
        bit_unpack(
            &sk[at..at + T0_POLY_BYTES],
            1 << (D - 1),
            T0_BITS,
            &mut key.t0[i],
        );
    }
    // ρ seeds the public matrix; tr is the hash of the public key.
    declassify(&key.rho);
    declassify(&key.tr);
    key
}

/// FIPS 204 Algorithm 6 (ML-DSA.KeyGen_internal), with pkEncode
/// (Algorithm 22) and skEncode (Algorithm 24) into caller-owned arrays.
///
/// Kept out of line so that its frame lies below the frame that calls
/// [`scrub_stack`] (see [`sign`]).
#[inline(never)]
fn keygen(xi: &[u8; 32], pk: &mut [u8; PK_BYTES], sk: &mut [u8; SK_BYTES]) {
    // Line 1: (ρ, ρ′, K) ← H(ξ ‖ k ‖ ℓ, 128).
    let mut seeds = [0u8; 128];
    shake256(&[xi.as_slice(), &[K as u8, L as u8]], &mut seeds);
    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut key = [0u8; 32];
    rho.copy_from_slice(&seeds[..32]);
    rho_prime.copy_from_slice(&seeds[32..96]);
    key.copy_from_slice(&seeds[96..]);
    seeds.zeroize();
    // ρ is published in pk; ExpandA's rejection sampling over it is
    // variable-time by design.
    declassify(&rho);

    // Lines 3 to 5: t = NTT⁻¹(Â ∘ NTT(s₁)) + s₂.
    let a_hat = expand_a(&rho);
    let mut s1 = [[0; N]; L];
    let mut s2 = [[0; N]; K];
    expand_s(&rho_prime, &mut s1, &mut s2);
    rho_prime.zeroize();
    let mut s1_hat = s1;
    for p in s1_hat.iter_mut() {
        ntt(p);
    }
    let mut t = [[0; N]; K];
    for i in 0..K {
        matrix_row_times(&mut t[i], &a_hat[i], &s1_hat);
        for j in 0..N {
            t[i][j] = freeze(t[i][j] + s2[i][j]);
        }
    }
    s1_hat.zeroize();

    // Line 6: (t₁, t₀) ← Power2Round(t).
    let mut t1 = [[0; N]; K];
    let mut t0 = [[0; N]; K];
    for i in 0..K {
        for j in 0..N {
            (t1[i][j], t0[i][j]) = power2round(t[i][j]);
        }
    }
    t.zeroize();
    declassify(&t1);

    // Lines 8 and 9: pk ← pkEncode(ρ, t₁), tr ← H(pk, 64).
    pk[..32].copy_from_slice(&rho);
    for i in 0..K {
        let at = 32 + i * T1_POLY_BYTES;
        pack(&t1[i], T1_BITS, &mut pk[at..at + T1_POLY_BYTES]);
    }
    let mut tr = [0u8; 64];
    shake256(&[pk.as_slice()], &mut tr);

    // Line 10: sk ← skEncode(ρ, K, tr, s₁, s₂, t₀).
    sk[..32].copy_from_slice(&rho);
    sk[32..64].copy_from_slice(&key);
    sk[64..128].copy_from_slice(&tr);
    for i in 0..L {
        let at = SK_S1 + i * ETA_POLY_BYTES;
        bit_pack(&s1[i], ETA, ETA_BITS, &mut sk[at..at + ETA_POLY_BYTES]);
    }
    for i in 0..K {
        let at = SK_S2 + i * ETA_POLY_BYTES;
        bit_pack(&s2[i], ETA, ETA_BITS, &mut sk[at..at + ETA_POLY_BYTES]);
    }
    for i in 0..K {
        let at = SK_T0 + i * T0_POLY_BYTES;
        bit_pack(
            &t0[i],
            1 << (D - 1),
            T0_BITS,
            &mut sk[at..at + T0_POLY_BYTES],
        );
    }
    key.zeroize();
    s1.zeroize();
    s2.zeroize();
    t0.zeroize();
}

// ── Signing (FIPS 204 Algorithm 7) ──────────────────────────────────────────

/// μ = H(tr ‖ M′, 64) (Algorithm 7 line 6, Algorithm 8 line 7) into `mu`,
/// with M′ given in parts so that Algorithm 2's prefix needs no copy of M.
/// It writes into the caller's buffer, so no by-value copy of μ is made.
fn message_representative(tr: &[u8; 64], m_prime: &[&[u8]], mu: &mut [u8; 64]) {
    let mut parts: [&[u8]; 4] = [tr, &[], &[], &[]];
    debug_assert!(m_prime.len() <= 3);
    parts[1..1 + m_prime.len()].copy_from_slice(m_prime);
    shake256(&parts[..1 + m_prime.len()], mu);
}

/// Length check, DIT, the signing core and the stack scrub. `mu` replaces
/// the hash of `m_prime` when given.
fn sign_entry(
    sk: &[u8],
    m_prime: &[&[u8]],
    mu: Option<&[u8; 64]>,
    rnd: &[u8; 32],
) -> Result<[u8; SIG_BYTES], DsaError> {
    if sk.len() != SK_BYTES {
        return Err(DsaError::Length);
    }
    Ok(crate::dit::with_dit(|| {
        let mut sig = [0u8; SIG_BYTES];
        sign(sk, m_prime, mu, rnd, &mut sig);
        scrub_stack();
        declassify(&sig);
        sig
    }))
}

/// FIPS 204 Algorithm 7 (ML-DSA.Sign_internal) into `sig`.
///
/// Kept out of line, as [`keygen`] is, so that its frame lies below the
/// frame that calls [`scrub_stack`]. With LTO it would otherwise be inlined
/// into that frame, above the scrubbed region, and a stale copy of the
/// decoded key (K included) would survive the scrub.
#[inline(never)]
fn sign(
    sk: &[u8],
    m_prime: &[&[u8]],
    mu: Option<&[u8; 64]>,
    rnd: &[u8; 32],
    sig: &mut [u8; SIG_BYTES],
) {
    // Lines 1 to 4: decode, and move s₁, s₂ and t₀ to the NTT domain in
    // place.
    let mut key = sk_decode(sk);
    for p in key
        .s1
        .iter_mut()
        .chain(key.s2.iter_mut())
        .chain(key.t0.iter_mut())
    {
        ntt(p);
    }
    // Line 5.
    let a_hat = expand_a(&key.rho);
    // Line 6 (skipped for an external μ), computed in place.
    let external_mu = mu;
    let mut mu = [0u8; 64];
    match external_mu {
        Some(m) => mu.copy_from_slice(m),
        None => message_representative(&key.tr, m_prime, &mut mu),
    }
    // Line 7: ρ″ ← H(K ‖ rnd ‖ μ, 64).
    let mut rho2 = [0u8; 64];
    shake256(&[key.key.as_slice(), rnd, &mu], &mut rho2);

    // Every buffer of the loop is reused across iterations and wiped once
    // after it, so a rejected candidate is overwritten by the next one.
    let mut y = [[0; N]; L];
    let mut y_hat;
    let mut w = [[0; N]; K];
    let mut w1 = [0; N];
    let mut w1_enc = [0u8; K * W1_POLY_BYTES];
    let mut ctilde = [0u8; CTILDE_BYTES];
    let mut c_hat;
    let mut cs = [0; N];
    let mut ct0 = [0; N];
    let mut z = [[0; N]; L];
    let mut h = [[0; N]; K];
    let mut kappa: u16 = 0;
    loop {
        // Lines 11 to 13.
        expand_mask(&rho2, kappa, &mut y);
        y_hat = y;
        for p in y_hat.iter_mut() {
            ntt(p);
        }
        for i in 0..K {
            matrix_row_times(&mut w[i], &a_hat[i], &y_hat);
        }
        // Line 15: c̃ ← H(μ ‖ w1Encode(HighBits(w)), λ/4) (Algorithm 28).
        for i in 0..K {
            for j in 0..N {
                w1[j] = decompose(w[i][j]).0;
            }
            pack(
                &w1,
                W1_BITS,
                &mut w1_enc[i * W1_POLY_BYTES..(i + 1) * W1_POLY_BYTES],
            );
        }
        shake256(&[mu.as_slice(), &w1_enc], &mut ctilde);
        // Lines 16 and 17.
        c_hat = sample_in_ball(&ctilde);
        ntt(&mut c_hat);

        // Lines 18 to 28, every check over every coefficient, folded into
        // `reject` without an early exit.
        let mut reject = 0u32;
        for l in 0..L {
            // Lines 18 and 20: z = y + ⟨⟨c·s₁⟩⟩, then ‖z‖∞ ≥ γ₁ − β.
            pointwise(&mut cs, &c_hat, &key.s1[l]);
            invntt_tomont(&mut cs);
            for j in 0..N {
                z[l][j] = center(y[l][j] + cs[j]);
                reject |= exceeds(z[l][j], GAMMA1 - BETA);
            }
        }
        let mut ones = 0i32;
        for i in 0..K {
            // Line 19: ⟨⟨c·s₂⟩⟩, and line 25: ⟨⟨c·t₀⟩⟩.
            pointwise(&mut cs, &c_hat, &key.s2[i]);
            invntt_tomont(&mut cs);
            pointwise(&mut ct0, &c_hat, &key.t0[i]);
            invntt_tomont(&mut ct0);
            for j in 0..N {
                // r = w − ⟨⟨c·s₂⟩⟩ in [0, q); (HighBits(r), LowBits(r)).
                let r = freeze(w[i][j] - cs[j]);
                let (r_high, r0) = decompose(r);
                // Line 23: ‖r₀‖∞ ≥ γ₂ − β.
                reject |= exceeds(r0, GAMMA2 - BETA);
                // Line 28: ‖⟨⟨c·t₀⟩⟩‖∞ ≥ γ₂.
                let ct0_j = center(ct0[j]);
                reject |= exceeds(ct0_j, GAMMA2);
                // Line 26 with Algorithm 39: MakeHint(−ct₀, r + ct₀) is
                // [[HighBits(r + ct₀) ≠ HighBits(r)]].
                let d = decompose(freeze(r + ct0_j)).0 ^ r_high;
                let bit = ((d | d.wrapping_neg()) as u32 >> 31) as i32;
                h[i][j] = bit;
                ones += bit;
            }
        }
        // Line 28: more than ω ones in h.
        reject |= ((OMEGA as i32 - ones) >> 31) as u32 & 1;
        if !public_bool(reject != 0) {
            break;
        }
        // Line 31, modulo 2¹⁶ as ExpandMask encodes κ.
        kappa = kappa.wrapping_add(L as u16);
    }

    // Line 33: σ ← sigEncode(c̃, z mod± q, h) (Algorithm 26). The accepted
    // candidate is the signature, so it is public from here on.
    declassify(&ctilde);
    declassify(&z);
    declassify(&h);
    sig[..CTILDE_BYTES].copy_from_slice(&ctilde);
    for l in 0..L {
        let at = SIG_Z + l * Z_POLY_BYTES;
        bit_pack(&z[l], GAMMA1, Z_BITS, &mut sig[at..at + Z_POLY_BYTES]);
    }
    hint_bit_pack(&h, &mut sig[SIG_H..]);

    mu.zeroize();
    rho2.zeroize();
    y.zeroize();
    y_hat.zeroize();
    w.zeroize();
    w1.zeroize();
    w1_enc.zeroize();
    ctilde.zeroize();
    c_hat.zeroize();
    cs.zeroize();
    ct0.zeroize();
    z.zeroize();
    h.zeroize();
    drop(key);
}

// ── Verification (FIPS 204 Algorithm 8) ─────────────────────────────────────

/// Length checks and DIT around [`verify`].
fn verify_entry(pk: &[u8], m_prime: &[&[u8]], mu: Option<&[u8; 64]>, sig: &[u8]) -> bool {
    // FIPS 204 section 3.6.2.
    if pk.len() != PK_BYTES || sig.len() != SIG_BYTES {
        return false;
    }
    crate::dit::with_dit(|| verify(pk, m_prime, mu, sig))
}

/// FIPS 204 Algorithm 8 (ML-DSA.Verify_internal) on correctly sized inputs.
/// The inputs are treated as public, and this returns early on the first
/// failed check. FIPS 204 section 3.6.3 notes that verification
/// intermediates can be sensitive, for example for a confidential message.
/// So the named buffers tr, μ, w′, the w₁′ encoding and the recomputed c̃
/// are wiped before returning. μ is computed in place, not returned by
/// value. No stack scrub follows, so copies in callee frames, such as the
/// Keccak permutation's locals, or in compiler spill slots can remain.
fn verify(pk: &[u8], m_prime: &[&[u8]], mu: Option<&[u8; 64]>, sig: &[u8]) -> bool {
    // Line 2 and 3: sigDecode (Algorithm 27); ⊥ for a malformed hint. The
    // z check of line 13 is done here, before the expensive part.
    let mut z = [[0; N]; L];
    for l in 0..L {
        let at = SIG_Z + l * Z_POLY_BYTES;
        bit_unpack(&sig[at..at + Z_POLY_BYTES], GAMMA1, Z_BITS, &mut z[l]);
        if z[l].iter().any(|&c| exceeds(c, GAMMA1 - BETA) != 0) {
            return false;
        }
    }
    let Some(h) = hint_bit_unpack(&sig[SIG_H..]) else {
        return false;
    };
    let ctilde: &[u8; CTILDE_BYTES] = sig[..CTILDE_BYTES].try_into().unwrap();

    // Line 1: pkDecode (Algorithm 23).
    let rho: &[u8; 32] = pk[..32].try_into().unwrap();
    let mut t1_hat = [[0; N]; K];
    for i in 0..K {
        let at = 32 + i * T1_POLY_BYTES;
        unpack(&pk[at..at + T1_POLY_BYTES], T1_BITS, &mut t1_hat[i]);
        // t₁ ≤ 2¹⁰ − 1, so t₁·2^d ≤ 1023·2¹³ = q − 1 < q, as the NTT
        // requires.
        for c in t1_hat[i].iter_mut() {
            *c <<= D;
        }
        ntt(&mut t1_hat[i]);
    }

    // Lines 5 to 8.
    let a_hat = expand_a(rho);
    // μ is computed in place, so no by-value copy of it is made.
    let external_mu = mu;
    let mut mu = [0u8; 64];
    match external_mu {
        Some(m) => mu.copy_from_slice(m),
        None => {
            let mut tr = [0u8; 64];
            shake256(&[pk], &mut tr);
            message_representative(&tr, m_prime, &mut mu);
            tr.zeroize();
        }
    }
    let mut c_hat = sample_in_ball(ctilde);
    ntt(&mut c_hat);

    // Line 9: w′ = NTT⁻¹(Â ∘ NTT(z) − NTT(c) ∘ NTT(t₁·2^d)). Line 10:
    // w₁′ = UseHint(h, w′), encoded for line 12.
    for p in z.iter_mut() {
        ntt(p);
    }
    let mut w1_enc = [0u8; K * W1_POLY_BYTES];
    let mut ct1 = [0; N];
    let mut w = [0; N];
    for i in 0..K {
        w.fill(0);
        for j in 0..L {
            pointwise_acc(&mut w, &a_hat[i][j], &z[j]);
        }
        pointwise(&mut ct1, &c_hat, &t1_hat[i]);
        for j in 0..N {
            w[j] = reduce32(w[j] - ct1[j]);
        }
        invntt_tomont(&mut w);
        for j in 0..N {
            w[j] = use_hint(h[i][j] != 0, caddq(w[j]));
        }
        pack(
            &w,
            W1_BITS,
            &mut w1_enc[i * W1_POLY_BYTES..(i + 1) * W1_POLY_BYTES],
        );
    }

    // Lines 12 and 13 (the z bound was checked above).
    let mut ctilde2 = [0u8; CTILDE_BYTES];
    shake256(&[mu.as_slice(), &w1_enc], &mut ctilde2);
    let ok = ctilde2 == *ctilde;
    mu.zeroize();
    w.zeroize();
    w1_enc.zeroize();
    ctilde2.zeroize();
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pow_mod(mut b: i64, mut e: u32) -> i64 {
        let q = Q as i64;
        let mut r = 1;
        b %= q;
        while e > 0 {
            if e & 1 == 1 {
                r = r * b % q;
            }
            b = b * b % q;
            e >>= 1;
        }
        r
    }

    /// A small deterministic generator for test inputs.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: u32) -> i32 {
            (self.next() % n) as i32
        }
    }

    #[test]
    fn zetas_are_powers_of_1753() {
        // FIPS 204 section 7.5: zetas[k] = ζ^BitRev8(k) mod q, ζ = 1753.
        assert_eq!(ZETAS[0], 0);
        for k in 1..N {
            let rev = (k as u8).reverse_bits() as u32;
            assert_eq!(ZETAS[k] as i64, pow_mod(1753, rev), "zetas[{k}]");
        }
        // 1753 is a primitive 512th root of unity.
        assert_eq!(pow_mod(1753, 256), Q as i64 - 1);
    }

    #[test]
    fn montgomery_constants() {
        assert_eq!((Q as u32).wrapping_mul(QINV as u32), 1, "QINV");
        assert_eq!(256 * 8_347_681 % Q as i64, 1, "256⁻¹");
        // ZETAS_MONT[k] · 2⁻³² = zetas[k].
        for k in 0..N {
            assert_eq!(freeze(montgomery_reduce(ZETAS_MONT[k] as i64)), ZETAS[k]);
        }
        let edge = ((1i64 << 31) - 1) * Q as i64;
        for a in [0i64, 1, -1, Q as i64, edge, -edge, 81 * (Q as i64).pow(2)] {
            let r = montgomery_reduce(a);
            assert!(r.abs() < Q, "range for {a}");
            assert_eq!(
                ((r as i64) << 32).rem_euclid(Q as i64),
                a.rem_euclid(Q as i64)
            );
        }
    }

    #[test]
    fn reductions_match_rem_euclid() {
        let mut g = Lcg(1);
        let edges = [0, 1, -1, Q, -Q, Q - 1, i32::MAX - (1 << 22), i32::MIN];
        let random = (0..200_000).map(|_| (g.next().wrapping_mul(2) ^ g.next()) as i32);
        for a in edges.into_iter().chain(random) {
            if a > i32::MAX - (1 << 22) {
                continue;
            }
            let r = reduce32(a);
            assert!((-6_283_009..=6_283_008).contains(&r), "reduce32({a}) = {r}");
            assert_eq!(freeze(a), a.rem_euclid(Q), "freeze({a})");
            let c = center(a);
            assert!(
                c.abs() <= (Q - 1) / 2 && (c - a).rem_euclid(Q) == 0,
                "center({a})"
            );
        }
    }

    /// FIPS 204 Algorithm 36 as written, with ordinary division.
    fn decompose_spec(r: i32) -> (i32, i32) {
        let alpha = 2 * GAMMA2;
        let rp = r.rem_euclid(Q);
        let mut r0 = rp.rem_euclid(alpha);
        if r0 > alpha / 2 {
            r0 -= alpha;
        }
        if rp - r0 == Q - 1 {
            (0, r0 - 1)
        } else {
            ((rp - r0) / alpha, r0)
        }
    }

    #[test]
    fn decompose_matches_algorithm_36() {
        for r in 0..Q {
            assert_eq!(decompose(r), decompose_spec(r), "r = {r}");
        }
    }

    #[test]
    fn power2round_matches_algorithm_35() {
        for r in 0..Q {
            let mut r0 = r.rem_euclid(1 << D);
            if r0 > 1 << (D - 1) {
                r0 -= 1 << D;
            }
            assert_eq!(power2round(r), ((r - r0) >> D, r0), "r = {r}");
        }
    }

    /// Algorithm 40 on the outputs of Algorithm 39: UseHint(MakeHint(z, r), r)
    /// = HighBits(r + z) for |z| ≤ γ₂ (FIPS 204 section 7.4).
    #[test]
    fn use_hint_recovers_high_bits() {
        let mut g = Lcg(2);
        for _ in 0..200_000 {
            let r = g.below(Q as u32);
            let z = g.below(2 * GAMMA2 as u32 + 1) - GAMMA2;
            let rz = (r + z).rem_euclid(Q);
            let hint = decompose_spec(r).0 != decompose_spec(rz).0;
            assert_eq!(use_hint(hint, r), decompose_spec(rz).0, "r = {r}, z = {z}");
        }
    }

    /// Negacyclic schoolbook product in Z_q[X]/(X²⁵⁶ + 1).
    fn schoolbook(a: &Poly, b: &Poly) -> Poly {
        let q = Q as i64;
        let mut r = [0i64; N];
        for i in 0..N {
            for j in 0..N {
                let p = a[i] as i64 * b[j] as i64 % q;
                if i + j < N {
                    r[i + j] = (r[i + j] + p) % q;
                } else {
                    r[i + j - N] = (r[i + j - N] - p) % q;
                }
            }
        }
        core::array::from_fn(|i| r[i].rem_euclid(q) as i32)
    }

    #[test]
    fn ntt_product_matches_schoolbook() {
        let mut g = Lcg(3);
        for round in 0..8 {
            // Full-range, signed and small operands, as signing uses.
            let a: Poly = core::array::from_fn(|_| g.below(Q as u32) - Q / 2);
            let b: Poly = match round % 3 {
                0 => core::array::from_fn(|_| g.below(9) - 4),
                1 => core::array::from_fn(|_| g.below(2 * GAMMA1 as u32) - GAMMA1 + 1),
                _ => core::array::from_fn(|_| g.below(Q as u32)),
            };
            let (mut ah, mut bh) = (a, b);
            ntt(&mut ah);
            ntt(&mut bh);
            let mut p = [0; N];
            pointwise(&mut p, &ah, &bh);
            invntt_tomont(&mut p);
            let p: Poly = core::array::from_fn(|i| freeze(p[i]));
            assert_eq!(p, schoolbook(&a, &b), "round {round}");
        }
    }

    #[test]
    fn ntt_matches_algorithm_41() {
        // Algorithm 41 with plain modular arithmetic.
        let mut g = Lcg(4);
        let w: Poly = core::array::from_fn(|_| g.below(Q as u32));
        let mut spec = w.map(|c| c as i64);
        let (mut m, mut len) = (0, 128);
        while len >= 1 {
            let mut start = 0;
            while start < N {
                m += 1;
                let z = ZETAS[m] as i64;
                for j in start..start + len {
                    let t = z * spec[j + len] % Q as i64;
                    spec[j + len] = (spec[j] - t).rem_euclid(Q as i64);
                    spec[j] = (spec[j] + t) % Q as i64;
                }
                start += 2 * len;
            }
            len /= 2;
        }
        let mut fast = w;
        ntt(&mut fast);
        assert_eq!(fast.map(freeze), spec.map(|c| c as i32));
    }

    #[test]
    fn pack_round_trips() {
        let mut g = Lcg(5);
        for bits in [4, 10, 13, 20] {
            let w: Poly = core::array::from_fn(|_| g.below(1 << bits));
            let mut bytes = vec![0u8; 32 * bits as usize];
            pack(&w, bits, &mut bytes);
            let mut back = [0; N];
            unpack(&bytes, bits, &mut back);
            assert_eq!(back, w, "{bits} bits");
        }
        // IntegerToBits is least significant bit first: 1 in 4 bits, then
        // 2, packs to 0x21.
        let mut w = [0; N];
        (w[0], w[1]) = (1, 2);
        let mut bytes = [0u8; 128];
        pack(&w, 4, &mut bytes);
        assert_eq!(bytes[0], 0x21);
    }

    #[test]
    fn hint_unpack_rejects_malformed_encodings() {
        let mut h = [[0; N]; K];
        (h[0][3], h[0][200], h[2][0], h[5][255]) = (1, 1, 1, 1);
        let mut y = [0u8; OMEGA + K];
        hint_bit_pack(&h, &mut y);
        assert_eq!(hint_bit_unpack(&y), Some(h));
        // Line 4: a count that decreases, or exceeds ω.
        let mut bad = y;
        bad[OMEGA + 1] = 1;
        assert_eq!(hint_bit_unpack(&bad), None, "decreasing count");
        let mut bad = y;
        bad[OMEGA + 5] = OMEGA as u8 + 1;
        assert_eq!(hint_bit_unpack(&bad), None, "count above omega");
        // Line 9: indices not strictly increasing within one polynomial.
        let mut bad = y;
        (bad[0], bad[1]) = (200, 3);
        assert_eq!(hint_bit_unpack(&bad), None, "decreasing index");
        let mut bad = y;
        bad[1] = 3;
        assert_eq!(hint_bit_unpack(&bad), None, "repeated index");
        // Across polynomials the index may restart.
        assert_eq!(y[2], 0);
        // Line 17: nonzero padding.
        let mut bad = y;
        bad[OMEGA - 1] = 1;
        assert_eq!(hint_bit_unpack(&bad), None, "nonzero padding");
        // At most ω ones fit.
        let mut full = [0u8; OMEGA + K];
        for (i, b) in full[..OMEGA].iter_mut().enumerate() {
            *b = i as u8;
        }
        full[OMEGA..].fill(OMEGA as u8);
        let h = hint_bit_unpack(&full).unwrap();
        assert_eq!(h[0].iter().sum::<i32>(), OMEGA as i32);
    }

    /// Algorithm 29 as written, with indexed accesses.
    fn sample_in_ball_spec(rho: &[u8]) -> Poly {
        let mut stream = vec![0u8; 136 * 8];
        shake256(&[rho], &mut stream);
        let h = u64::from_le_bytes(stream[..8].try_into().unwrap());
        let mut pos = 8;
        let mut c = [0i32; N];
        for i in N - TAU..N {
            let mut j = stream[pos] as usize;
            pos += 1;
            while j > i {
                j = stream[pos] as usize;
                pos += 1;
            }
            c[i] = c[j];
            c[j] = if (h >> (i + TAU - N)) & 1 == 1 { -1 } else { 1 };
        }
        c
    }

    #[test]
    fn sample_in_ball_matches_algorithm_29() {
        let mut g = Lcg(6);
        for _ in 0..200 {
            let rho: [u8; CTILDE_BYTES] = core::array::from_fn(|_| g.next() as u8);
            let c = sample_in_ball(&rho);
            assert_eq!(c, sample_in_ball_spec(&rho));
            assert_eq!(c.iter().filter(|&&x| x != 0).count(), TAU);
        }
    }

    #[test]
    fn rejection_samplers_match_their_algorithms() {
        // Algorithm 31 with η = 4, one byte at a time.
        let rho_prime = [0x5cu8; 64];
        let mut stream = vec![0u8; 136 * 8];
        shake256(&[rho_prime.as_slice(), &3u16.to_le_bytes()], &mut stream);
        let mut want = [0; N];
        let (mut j, mut pos) = (0, 0);
        while j < N {
            let z = stream[pos];
            pos += 1;
            for b in [z & 15, z >> 4] {
                if b < 9 && j < N {
                    want[j] = 4 - b as i32;
                    j += 1;
                }
            }
        }
        let mut got = [0; N];
        rej_bounded_poly(&rho_prime, 3, &mut got);
        assert_eq!(got, want);

        // Algorithm 30 for every entry, through the paired sampler.
        let rho = [0xa7u8; 32];
        let a = expand_a(&rho);
        for r in 0..K {
            for s in 0..L {
                let mut one = [0; N];
                rej_ntt_poly(&rho, r, s, &mut one);
                assert_eq!(a[r][s], one, "A[{r}][{s}]");
                assert!(one.iter().all(|&c| (0..Q).contains(&c)));
            }
        }
    }
}
