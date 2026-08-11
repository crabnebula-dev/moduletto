//! Number Theoretic Transform (NTT) for Kyber
//!
//! Provides O(n log n) polynomial multiplication using NTT over Z_q[x]/(x^n + 1).
//!
//! This is the key optimization that makes Kyber practical - it reduces polynomial
//! multiplication from O(n²) to O(n log n).
//!
//! # Background
//!
//! For Kyber-512, we have:
//! - n = 256 (polynomial degree)
//! - q = 3329 (prime modulus)
//! - ζ = 17 is a primitive 256-th root of unity (ζ^256 = 1, ζ^128 = -1)
//!
//! # Negacyclic NTT
//!
//! Kyber uses negacyclic convolution mod (x^256 + 1), not cyclic mod (x^256 - 1).
//! This requires a modified NTT where:
//! - Twiddle factors use odd powers: ζ^(2·br(i)+1)
//! - "Pointwise" multiply is actually basemul of pairs mod (x² - ζ^(2·br(i)+1))
//! - Bit-reversal permutation enables in-place computation

use crate::modn::ModN;

/// Kyber modulus
pub const KYBER_Q: i64 = 3329;

/// Polynomial degree
pub const KYBER_N: usize = 256;

/// Kyber coefficient type
pub type KyberCoeff = ModN<KYBER_Q>;

/// Primitive 512-th root of unity modulo 3329
/// ζ = 17 satisfies ζ^512 ≡ 1 (mod 3329)
const ZETA_PRIMITIVE: i64 = 17;

/// Precomputed powers of ζ for NTT
/// These are computed at compile time for maximum performance
pub struct NTTConstants {
    /// Forward NTT twiddle factors: ζ^bitrev(i) for i=0..256
    pub zetas: [KyberCoeff; KYBER_N],
    /// Inverse NTT twiddle factors
    pub zetas_inv: [KyberCoeff; KYBER_N],
    /// n^(-1) mod q for final INTT scaling
    pub n_inv: KyberCoeff,
}

/// Multiply two residues mod q in a `const` context.
const fn const_mul(a: i64, b: i64) -> i64 {
    (a * b) % KYBER_Q
}

/// Square-and-multiply exponentiation mod q, evaluable at compile time.
const fn const_pow(base: i64, exp: u64) -> i64 {
    let mut result = 1_i64;
    let mut b = base % KYBER_Q;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = const_mul(result, b);
        }
        b = const_mul(b, b);
        e >>= 1;
    }
    result
}

/// Bit-reverse a 7-bit number (for indices 0..127), evaluable at compile time.
const fn bit_reverse_7_const(x: usize) -> usize {
    let mut result = 0;
    let mut v = x;
    let mut i = 0;
    while i < 7 {
        result = (result << 1) | (v & 1);
        v >>= 1;
        i += 1;
    }
    result
}

/// Build the full twiddle-factor table at compile time.
const fn build_ntt_constants() -> NTTConstants {
    let mut zetas = [KyberCoeff::zero(); KYBER_N];
    let mut zetas_inv = [KyberCoeff::zero(); KYBER_N];

    // Forward/inverse twiddles: zetas[k] = ζ^brv(k, 7) for k = 1..127
    zetas[0] = KyberCoeff::new(1); // Index 0 unused
    let mut k = 1;
    while k < 128 {
        zetas[k] = KyberCoeff::new(const_pow(ZETA_PRIMITIVE, bit_reverse_7_const(k) as u64));
        k += 1;
    }

    // Inverse NTT walks the same table backwards (k = 127 down to 1).
    let mut i = 0;
    while i < 128 {
        zetas_inv[i] = zetas[i];
        i += 1;
    }

    // Basemul twiddles: ζ^(2·brv(i)+1) for i = 0..127, stored at indices 128..255
    let mut i = 0;
    while i < 128 {
        zetas[128 + i] = KyberCoeff::new(const_pow(
            ZETA_PRIMITIVE,
            (2 * bit_reverse_7_const(i) + 1) as u64,
        ));
        i += 1;
    }

    zetas_inv[255] = KyberCoeff::zero();

    // n^(-1) mod q for INTT scaling. Kyber's 7-layer NTT processes 128 pairs,
    // so the scaling factor is 128^(-1), not 256^(-1). q is prime, so
    // 128^(-1) ≡ 128^(q-2) (mod q) by Fermat's little theorem.
    let n_inv = KyberCoeff::new(const_pow(128, (KYBER_Q - 2) as u64));

    NTTConstants {
        zetas,
        zetas_inv,
        n_inv,
    }
}

/// The twiddle-factor tables, materialised entirely at compile time.
///
/// Previously these were built on first use behind a `OnceLock`, which cost an
/// acquire-load plus an initialisation branch on every NTT call and made the
/// module `std`-only. As a `static` initialised by const evaluation the tables
/// land in `.rodata`, the access is a plain PC-relative load, and `ntt` builds
/// under `no_std`.
static NTT_CONSTANTS: NTTConstants = build_ntt_constants();

impl NTTConstants {
    /// Bit-reverse a 7-bit number (for indices 0..127)
    #[allow(dead_code)]
    const fn bit_reverse_7(x: usize) -> usize {
        bit_reverse_7_const(x)
    }

    /// Returns the compile-time NTT constants.
    ///
    /// This is now a pure `const` construction; it performs no runtime work.
    pub const fn new() -> Self {
        build_ntt_constants()
    }
}

impl Default for NTTConstants {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Lazy-reduction NTT kernel ───────────────────────────────────────────────
//
// The butterfly loops below work on raw `i64` coefficients in a *redundant,
// centred* representation instead of on canonical `ModN` values. Canonical form
// costs a conditional fixup after every add and subtract; with q = 3329 sitting
// in a 64-bit register there are ~50 spare bits, so those fixups are pure waste.
// Instead only the multiply is reduced (to `[-q, q]`), coefficients are allowed
// to drift, and a single canonicalisation pass runs at the end.
//
// This also removes every `select` from the inner loop: what remains is
// straight-line multiply/add/shift on fixed-width integers, which is both
// faster and more obviously constant-time than a chain of conditional moves.
//
// Growth bounds (verified numerically against the analytic worst case):
//
//   forward   max |multiply input|  30_291_329   max |coefficient|    11_615
//   inverse   max |multiply input| 784_677_195   max |coefficient|   237_565
//
// Both multiply inputs stay under the 2^(S-1) = 2^31 limit of `fq_reduce` with
// ~2.7x margin, and the widest intermediate `x · μ` reaches ~1.0e15 against an
// i64 ceiling of ~9.2e18.

/// Shift width for the rounding Barrett reduction used inside the NTT.
const LAZY_S: u32 = 32;

/// μ = ⌊2^S / q⌋, the Barrett reciprocal for `LAZY_S`.
const LAZY_MU: i64 = (1_i64 << LAZY_S) / KYBER_Q;

/// Rounding Barrett reduction.
///
/// For any `|x| < 2^(S-1)` this returns some `r ≡ x (mod q)` with `|r| ≤ q`.
/// The result is *not* canonical — that is the point; canonicalising costs a
/// conditional and the NTT does not need it until the very end.
///
/// Four ALU operations (multiply, add, arithmetic shift, multiply-subtract),
/// no branch and no conditional move.
#[inline(always)]
fn fq_reduce(x: i64) -> i64 {
    debug_assert!(
        x.unsigned_abs() < (1_u64 << (LAZY_S - 1)),
        "fq_reduce input out of range"
    );
    let quot = (x.wrapping_mul(LAZY_MU) + (1_i64 << (LAZY_S - 1))) >> LAZY_S;
    x - quot * KYBER_Q
}

/// Branchless canonicalisation into `[0, q)`, valid for `|x| < 2^(S-1)`.
///
/// Pure mask arithmetic: no comparison, no conditional move, no branch. There
/// is nothing here for the optimiser to turn back into a data-dependent branch,
/// so this is constant-time by construction and needs no barrier.
#[inline(always)]
fn canonicalize(x: i64) -> i64 {
    let v = fq_reduce(x); // |v| ≤ q
    let v = v + (KYBER_Q & (v >> 63)); // → [0, q]
    v - (KYBER_Q & !((v - KYBER_Q) >> 63)) // → [0, q)
}

/// Canonicalisation valid for any `i64`, at the cost of a division-by-constant.
///
/// Used where the input can exceed `fq_reduce`'s range, e.g. the schoolbook
/// accumulator. Also branchless.
#[inline(always)]
fn canonicalize_wide(x: i64) -> i64 {
    let v = x % KYBER_Q;
    v + (KYBER_Q & (v >> 63))
}

/// Canonical modular addition: `a + b mod q` for canonical `a`, `b`.
///
/// The sum lies in `[0, 2q)`; the fixup subtracts q under a sign mask instead
/// of branching, so a loop over these vectorises.
#[inline(always)]
fn add_canonical(a: i64, b: i64) -> i64 {
    // Subtract q up front so the fixup is a masked *add* — one instruction
    // shorter than masking a subtract, which needs an extra bitwise-not.
    let s = a + b - KYBER_Q; // [-q, q-2]
    s + (KYBER_Q & (s >> 63))
}

/// Canonical modular subtraction: `a - b mod q` for canonical `a`, `b`.
#[inline(always)]
fn sub_canonical(a: i64, b: i64) -> i64 {
    let d = a - b;
    d + (KYBER_Q & (d >> 63))
}

/// Reinterpret canonical coefficients as raw `i64`.
#[inline(always)]
fn to_raw(c: &[KyberCoeff; KYBER_N]) -> [i64; KYBER_N] {
    // SAFETY: `ModN<N>` is `#[repr(transparent)]` over `i64`, so the arrays
    // have identical size, alignment and layout.
    unsafe { core::mem::transmute::<[KyberCoeff; KYBER_N], [i64; KYBER_N]>(*c) }
}

/// Reinterpret raw `i64` values as coefficients.
///
/// # Safety
///
/// Every element of `r` must already be canonical, i.e. in `[0, q)`.
#[inline(always)]
unsafe fn from_raw(r: [i64; KYBER_N]) -> [KyberCoeff; KYBER_N] {
    core::mem::transmute::<[i64; KYBER_N], [KyberCoeff; KYBER_N]>(r)
}

/// Cooley-Tukey forward NTT over the redundant representation.
///
/// Consumes canonical input and produces canonical output; everything in
/// between is lazy. Branchless throughout.
#[allow(dead_code)]
fn ntt_kernel(r: &mut [i64; KYBER_N]) {
    let zetas = &NTT_CONSTANTS.zetas;
    let mut k = 1;
    let mut len = 128;

    // 7 layers for n = 256
    while len >= 2 {
        let mut start = 0;
        while start < KYBER_N {
            let zeta = zetas[k].value();
            k += 1;

            // `split_at_mut` gives the optimiser two disjoint, provably
            // in-bounds halves, so the butterfly loop carries no bounds checks.
            let (lo, hi) = r[start..start + 2 * len].split_at_mut(len);
            for (a, b) in lo.iter_mut().zip(hi.iter_mut()) {
                let t = fq_reduce(zeta * *b);
                *b = *a - t;
                *a += t;
            }

            start += 2 * len;
        }
        len /= 2;
    }

    for c in r.iter_mut() {
        *c = canonicalize(*c);
    }
}

/// Gentleman-Sande inverse NTT over the redundant representation.
///
/// Consumes canonical input and produces canonical output, including the
/// `n^(-1)` scaling. Branchless throughout.
#[allow(dead_code)]
fn intt_kernel(r: &mut [i64; KYBER_N]) {
    let zetas = &NTT_CONSTANTS.zetas;
    let n_inv = NTT_CONSTANTS.n_inv.value();
    let mut k = 127;
    let mut len = 2;

    while len <= 128 {
        let mut start = 0;
        while start < KYBER_N {
            let zeta = zetas[k].value();
            // Decrement AFTER reading (like k-- in the C reference)
            k = k.saturating_sub(1);

            let (lo, hi) = r[start..start + 2 * len].split_at_mut(len);
            for (a, b) in lo.iter_mut().zip(hi.iter_mut()) {
                let t = *a;
                *a = t + *b;
                *b = fq_reduce(zeta * (*b - t));
            }

            start += 2 * len;
        }
        len *= 2;
    }

    // Scale by n^(-1) = 128^(-1) mod q and canonicalise in one pass.
    for c in r.iter_mut() {
        *c = canonicalize(*c * n_inv);
    }
}

/// Pointwise "basemul": multiply the 128 coefficient pairs as degree-1
/// polynomials mod (x² - ζ^(2·br(i)+1)). Consumes and produces canonical values.
#[allow(dead_code)]
fn basemul_kernel(a: &[i64; KYBER_N], b: &[i64; KYBER_N]) -> [i64; KYBER_N] {
    let zetas = &NTT_CONSTANTS.zetas;
    let mut out = [0_i64; KYBER_N];

    for i in (0..KYBER_N).step_by(2) {
        let zeta = zetas[128 + i / 2].value(); // ζ^(2·br(i/2)+1)

        let (a0, a1) = (a[i], a[i + 1]);
        let (b0, b1) = (b[i], b[i + 1]);

        // (a0 + a1·x)(b0 + b1·x) mod (x² - zeta)
        //   = a0·b0 + zeta·a1·b1 + (a0·b1 + a1·b0)·x
        out[i] = canonicalize(fq_reduce(a0 * b0) + fq_reduce(zeta * fq_reduce(a1 * b1)));
        out[i + 1] = canonicalize(fq_reduce(a0 * b1) + fq_reduce(a1 * b0));
    }

    out
}

// ─── ARM64 NEON int16 backend ────────────────────────────────────────────────
//
// q = 3329 fits in 12 bits, so a whole polynomial is 256 × i16 = 512 bytes
// rather than 2 KiB, and NEON can drive eight butterflies per instruction.
// AArch64 has no 64-bit SIMD multiply, so the portable `i64` kernel above can
// never vectorise its multiplies — this backend exists to get past that wall.
//
// The arithmetic mirrors pq-crystals/kyber `ref/ntt.c`: Montgomery
// multiplication with R = 2^16 and QINV = -3327, twiddles stored pre-multiplied
// by R. Coefficients are converted from the canonical `i64` representation on
// entry and back on exit; the conversion is ~30 ns each way against a ~230 ns
// transform, and in `mul_ntt` it is amortised over three transforms.
//
// Bounds (same as the reference): a canonical input `[0, q)` grows by at most q
// per layer, so |coeff| ≤ 8q = 26 632 < 2^15 after seven layers.
#[cfg(target_arch = "aarch64")]
mod neon16 {
    use super::{KyberCoeff, KYBER_N, KYBER_Q};
    use core::arch::aarch64::*;

    /// Montgomery-domain twiddles, ζ^brv(k)·R mod q, from pq-crystals/kyber
    /// `ref/ntt.c`. Indices 1..=127 drive the butterflies; 64..=127 double as
    /// the basemul pair twiddles (pair 2i uses `+ZETAS[64+i]`, pair 2i+1 uses
    /// `-ZETAS[64+i]`), a layout checked against the portable table in tests.
    static ZETAS: [i16; 128] = [
        -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202,
        -1474, 1468, 573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608,
        -1542, 411, -205, -1571, 1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8,
        -320, -666, -1618, -1162, 126, 1469, -853, -90, -271, 830, 107, -1421, -247, -951,
        -398, 961, -1508, -725, 448, -1065, 677, -1275, -1103, 430, 555, 843, -1251, 871,
        1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246, 778, 1159, -147, -777,
        1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097, 603, 610,
        1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
        -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522,
        1628,
    ];

    /// Final INTT scale for a standalone inverse transform: 128^(-1) mod q.
    ///
    /// The reference uses 1441 = 128^(-1)·R² because its inverse transform
    /// always follows a Montgomery basemul, which leaves an extra R^(-1).
    /// A standalone `intt()` has no basemul to compensate for, so the constant
    /// is one factor of R smaller.
    pub const F_STANDALONE: i16 = 512;

    /// Final INTT scale when the inverse transform follows [`basemul`], whose
    /// Montgomery products carry an R^(-1) that this cancels. Matches the
    /// reference implementation's constant.
    pub const F_AFTER_BASEMUL: i16 = 1441;

    const QINV: i16 = -3327; // q^(-1) mod 2^16
    const Q16: i16 = KYBER_Q as i16;

    /// Montgomery multiply: returns a·b·R^(-1) mod q, with |result| < q.
    #[inline(always)]
    fn fqmul(a: i16, b: i16) -> i16 {
        let t = (a as i32) * (b as i32);
        let u = (t as i16).wrapping_mul(QINV);
        ((t - (u as i32) * KYBER_Q as i32) >> 16) as i16
    }

    /// Barrett reduction to the centred representative, |result| < q.
    #[inline(always)]
    fn barrett(a: i16) -> i16 {
        const V: i32 = 20159; // round(2^26 / q)
        let t = ((V * (a as i32) + (1 << 25)) >> 26) as i16;
        a.wrapping_sub(t.wrapping_mul(Q16))
    }

    /// Eight-lane Montgomery multiply.
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn fqmul_vec(a: int16x8_t, b: int16x8_t) -> int16x8_t {
        let qinv = vdup_n_s16(QINV);
        let q = vdupq_n_s16(Q16);

        let t_lo = vmull_s16(vget_low_s16(a), vget_low_s16(b));
        let u_lo = vmul_s16(vmovn_s32(t_lo), qinv);
        let c_lo = vmull_s16(u_lo, vget_low_s16(q));
        let r_lo = vshrn_n_s32::<16>(vsubq_s32(t_lo, c_lo));

        let t_hi = vmull_s16(vget_high_s16(a), vget_high_s16(b));
        let u_hi = vmul_s16(vmovn_s32(t_hi), qinv);
        let c_hi = vmull_s16(u_hi, vget_high_s16(q));
        let r_hi = vshrn_n_s32::<16>(vsubq_s32(t_hi, c_hi));

        vcombine_s16(r_lo, r_hi)
    }

    /// Eight-lane Barrett reduction to the centred representative.
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn barrett_vec(a: int16x8_t) -> int16x8_t {
        let v = vdupq_n_s16(20159);
        let q = vdupq_n_s16(Q16);

        // t = (a·20159 + 2^25) >> 26, evaluated as ((a·20159 + 2^25) >> 16) >> 10
        let t_lo = vaddq_s32(vmull_s16(vget_low_s16(a), vget_low_s16(v)), vdupq_n_s32(1 << 25));
        let lo16 = vshr_n_s16::<10>(vshrn_n_s32::<16>(t_lo));
        let t_hi = vaddq_s32(vmull_s16(vget_high_s16(a), vget_high_s16(v)), vdupq_n_s32(1 << 25));
        let hi16 = vshr_n_s16::<10>(vshrn_n_s32::<16>(t_hi));

        let t = vcombine_s16(lo16, hi16);
        vsubq_s16(a, vmulq_s16(t, q))
    }

    // The len ∈ {4, 2} layers cannot use the straightforward "load top, load
    // bottom" pattern: at those widths both halves of a butterfly live inside
    // the same 8-lane vector. Doing them scalar is what the prototype in
    // `examples/kyber_benchmark.rs` does, and it costs ~250 ns of a ~300 ns
    // transform — five vectorised layers take only ~53 ns between them.
    //
    // The fix is to deinterleave with `uzp`/`zip` (for len = 2) or to split
    // 64-bit halves (for len = 4), so all eight lanes stay busy.

    /// Forward layer with len = 4: 32 blocks of 8, two blocks per iteration.
    #[target_feature(enable = "neon")]
    unsafe fn ntt_layer4(r: &mut [i16; KYBER_N], k0: usize) {
        for m in 0..16 {
            let base = m * 16;
            let zv = vcombine_s16(
                vdup_n_s16(ZETAS[k0 + 2 * m]),
                vdup_n_s16(ZETAS[k0 + 2 * m + 1]),
            );

            let v0 = vld1q_s16(r.as_ptr().add(base));
            let v1 = vld1q_s16(r.as_ptr().add(base + 8));

            let tops = vcombine_s16(vget_low_s16(v0), vget_low_s16(v1));
            let bots = vcombine_s16(vget_high_s16(v0), vget_high_s16(v1));

            let t = fqmul_vec(zv, bots);
            let nt = vaddq_s16(tops, t);
            let nb = vsubq_s16(tops, t);

            vst1q_s16(
                r.as_mut_ptr().add(base),
                vcombine_s16(vget_low_s16(nt), vget_low_s16(nb)),
            );
            vst1q_s16(
                r.as_mut_ptr().add(base + 8),
                vcombine_s16(vget_high_s16(nt), vget_high_s16(nb)),
            );
        }
    }

    /// Forward layer with len = 2: 64 blocks of 4, four blocks per iteration.
    ///
    /// Each i32 lane holds one coefficient pair, so `uzp1`/`uzp2` over i32
    /// separate the butterfly's top and bottom halves and `zip1`/`zip2` put
    /// them back.
    #[target_feature(enable = "neon")]
    unsafe fn ntt_layer2(r: &mut [i16; KYBER_N], k0: usize) {
        for m in 0..16 {
            let base = m * 16;
            let k = k0 + 4 * m;
            let zs: [i16; 8] = [
                ZETAS[k],
                ZETAS[k],
                ZETAS[k + 1],
                ZETAS[k + 1],
                ZETAS[k + 2],
                ZETAS[k + 2],
                ZETAS[k + 3],
                ZETAS[k + 3],
            ];
            let zv = vld1q_s16(zs.as_ptr());

            let v0 = vreinterpretq_s32_s16(vld1q_s16(r.as_ptr().add(base)));
            let v1 = vreinterpretq_s32_s16(vld1q_s16(r.as_ptr().add(base + 8)));

            let tops = vreinterpretq_s16_s32(vuzp1q_s32(v0, v1));
            let bots = vreinterpretq_s16_s32(vuzp2q_s32(v0, v1));

            let t = fqmul_vec(zv, bots);
            let nt = vreinterpretq_s32_s16(vaddq_s16(tops, t));
            let nb = vreinterpretq_s32_s16(vsubq_s16(tops, t));

            vst1q_s16(
                r.as_mut_ptr().add(base),
                vreinterpretq_s16_s32(vzip1q_s32(nt, nb)),
            );
            vst1q_s16(
                r.as_mut_ptr().add(base + 8),
                vreinterpretq_s16_s32(vzip2q_s32(nt, nb)),
            );
        }
    }

    /// Inverse layer with len = 2. Twiddle indices descend from `k0`.
    #[target_feature(enable = "neon")]
    unsafe fn intt_layer2(r: &mut [i16; KYBER_N], k0: usize) {
        for m in 0..16 {
            let base = m * 16;
            let k = k0 - 4 * m;
            let zs: [i16; 8] = [
                ZETAS[k],
                ZETAS[k],
                ZETAS[k - 1],
                ZETAS[k - 1],
                ZETAS[k - 2],
                ZETAS[k - 2],
                ZETAS[k - 3],
                ZETAS[k - 3],
            ];
            let zv = vld1q_s16(zs.as_ptr());

            let v0 = vreinterpretq_s32_s16(vld1q_s16(r.as_ptr().add(base)));
            let v1 = vreinterpretq_s32_s16(vld1q_s16(r.as_ptr().add(base + 8)));

            let tops = vreinterpretq_s16_s32(vuzp1q_s32(v0, v1));
            let bots = vreinterpretq_s16_s32(vuzp2q_s32(v0, v1));

            let sum = vreinterpretq_s32_s16(barrett_vec(vaddq_s16(tops, bots)));
            let scaled = vreinterpretq_s32_s16(fqmul_vec(zv, vsubq_s16(bots, tops)));

            vst1q_s16(
                r.as_mut_ptr().add(base),
                vreinterpretq_s16_s32(vzip1q_s32(sum, scaled)),
            );
            vst1q_s16(
                r.as_mut_ptr().add(base + 8),
                vreinterpretq_s16_s32(vzip2q_s32(sum, scaled)),
            );
        }
    }

    /// Inverse layer with len = 4. Twiddle indices descend from `k0`.
    #[target_feature(enable = "neon")]
    unsafe fn intt_layer4(r: &mut [i16; KYBER_N], k0: usize) {
        for m in 0..16 {
            let base = m * 16;
            let zv = vcombine_s16(
                vdup_n_s16(ZETAS[k0 - 2 * m]),
                vdup_n_s16(ZETAS[k0 - 2 * m - 1]),
            );

            let v0 = vld1q_s16(r.as_ptr().add(base));
            let v1 = vld1q_s16(r.as_ptr().add(base + 8));

            let tops = vcombine_s16(vget_low_s16(v0), vget_low_s16(v1));
            let bots = vcombine_s16(vget_high_s16(v0), vget_high_s16(v1));

            let sum = barrett_vec(vaddq_s16(tops, bots));
            let scaled = fqmul_vec(zv, vsubq_s16(bots, tops));

            vst1q_s16(
                r.as_mut_ptr().add(base),
                vcombine_s16(vget_low_s16(sum), vget_low_s16(scaled)),
            );
            vst1q_s16(
                r.as_mut_ptr().add(base + 8),
                vcombine_s16(vget_high_s16(sum), vget_high_s16(scaled)),
            );
        }
    }

    /// Forward NTT, in place. Every layer is vectorised.
    #[target_feature(enable = "neon")]
    unsafe fn ntt_inner(r: &mut [i16; KYBER_N]) {
        // Layers len = 128 .. 8 consume twiddles 1..=31.
        let mut k = 1usize;
        let mut len = 128usize;
        while len >= 8 {
            let mut start = 0usize;
            while start < KYBER_N {
                let zv = vdupq_n_s16(ZETAS[k]);
                k += 1;
                let mut j = start;
                while j < start + len {
                    let top = vld1q_s16(r.as_ptr().add(j));
                    let bot = vld1q_s16(r.as_ptr().add(j + len));
                    let t = fqmul_vec(zv, bot);
                    vst1q_s16(r.as_mut_ptr().add(j + len), vsubq_s16(top, t));
                    vst1q_s16(r.as_mut_ptr().add(j), vaddq_s16(top, t));
                    j += 8;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
        debug_assert_eq!(k, 32);

        ntt_layer4(r, 32); // twiddles 32..=63
        ntt_layer2(r, 64); // twiddles 64..=127
    }

    /// Inverse NTT, in place, with the caller-chosen final Montgomery scale.
    /// Every layer is vectorised.
    #[target_feature(enable = "neon")]
    unsafe fn intt_inner(r: &mut [i16; KYBER_N], f: i16) {
        intt_layer2(r, 127); // twiddles 127 down to 64
        intt_layer4(r, 63); // twiddles 63 down to 32

        // Layers len = 8 .. 128 consume twiddles 31 down to 1.
        let mut k = 31usize;
        let mut len = 8usize;
        while len <= 128 {
            let mut start = 0usize;
            while start < KYBER_N {
                let zv = vdupq_n_s16(ZETAS[k]);
                k = k.saturating_sub(1);
                let mut j = start;
                while j < start + len {
                    let top = vld1q_s16(r.as_ptr().add(j));
                    let bot = vld1q_s16(r.as_ptr().add(j + len));
                    let sum = barrett_vec(vaddq_s16(top, bot));
                    let scaled = fqmul_vec(zv, vsubq_s16(bot, top));
                    vst1q_s16(r.as_mut_ptr().add(j), sum);
                    vst1q_s16(r.as_mut_ptr().add(j + len), scaled);
                    j += 8;
                }
                start += 2 * len;
            }
            len <<= 1;
        }

        // Final scale by `f` (Montgomery), folding in n^(-1).
        let fv = vdupq_n_s16(f);
        let mut j = 0usize;
        while j < KYBER_N {
            let a = vld1q_s16(r.as_ptr().add(j));
            vst1q_s16(r.as_mut_ptr().add(j), fqmul_vec(fv, a));
            j += 8;
        }
    }

    /// Pointwise basemul of the 128 coefficient pairs mod (x² - ζ).
    ///
    /// Montgomery arithmetic, so the result carries an R^(-1) that the
    /// following inverse transform cancels via [`F_AFTER_BASEMUL`].
    fn basemul(a: &[i16; KYBER_N], b: &[i16; KYBER_N]) -> [i16; KYBER_N] {
        let mut out = [0i16; KYBER_N];
        for i in 0..64 {
            let zeta = ZETAS[64 + i];
            basemul_pair(&mut out[4 * i..], &a[4 * i..], &b[4 * i..], zeta);
            basemul_pair(&mut out[4 * i + 2..], &a[4 * i + 2..], &b[4 * i + 2..], -zeta);
        }
        out
    }

    #[inline(always)]
    fn basemul_pair(out: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
        // (a0 + a1·x)(b0 + b1·x) mod (x² - zeta)
        out[0] = fqmul(fqmul(a[1], b[1]), zeta).wrapping_add(fqmul(a[0], b[0]));
        out[1] = fqmul(a[0], b[1]).wrapping_add(fqmul(a[1], b[0]));
    }

    /// Narrow canonical `[0, q)` coefficients into `i16`.
    #[inline]
    fn to_i16(c: &[KyberCoeff; KYBER_N]) -> [i16; KYBER_N] {
        let mut out = [0i16; KYBER_N];
        for (o, s) in out.iter_mut().zip(c.iter()) {
            *o = s.value() as i16;
        }
        out
    }

    /// Widen centred `i16` coefficients back to canonical `[0, q)`.
    #[inline]
    fn to_canonical(r: &[i16; KYBER_N]) -> [KyberCoeff; KYBER_N] {
        let mut out = [KyberCoeff::zero(); KYBER_N];
        for (o, &s) in out.iter_mut().zip(r.iter()) {
            let v = barrett(s) as i64; // |v| < q
            // SAFETY: branchless fixup puts v in [0, q).
            *o = unsafe { KyberCoeff::new_unchecked(v + (KYBER_Q & (v >> 63))) };
        }
        out
    }

    /// The Montgomery twiddle at index `k`, for cross-checking against the
    /// portable table in tests.
    #[cfg(test)]
    pub fn zeta(k: usize) -> i16 {
        ZETAS[k]
    }

    pub fn forward(c: &[KyberCoeff; KYBER_N]) -> [KyberCoeff; KYBER_N] {
        let mut r = to_i16(c);
        // SAFETY: NEON is architecturally guaranteed on aarch64.
        unsafe { ntt_inner(&mut r) };
        to_canonical(&r)
    }

    pub fn inverse(c: &[KyberCoeff; KYBER_N]) -> [KyberCoeff; KYBER_N] {
        let mut r = to_i16(c);
        // SAFETY: NEON is architecturally guaranteed on aarch64.
        unsafe { intt_inner(&mut r, F_STANDALONE) };
        to_canonical(&r)
    }

    pub fn multiply(
        x: &[KyberCoeff; KYBER_N],
        y: &[KyberCoeff; KYBER_N],
    ) -> [KyberCoeff; KYBER_N] {
        let mut a = to_i16(x);
        let mut b = to_i16(y);
        // SAFETY: NEON is architecturally guaranteed on aarch64.
        unsafe {
            ntt_inner(&mut a);
            ntt_inner(&mut b);
            let mut r = basemul(&a, &b);
            intt_inner(&mut r, F_AFTER_BASEMUL);
            to_canonical(&r)
        }
    }
}

// ─── Backend dispatch ────────────────────────────────────────────────────────
//
// aarch64 uses the NEON int16 backend; everything else uses the portable i64
// lazy-reduction kernel. Both produce identical canonical results — the
// `backends_agree` tests pin that down.

#[cfg(target_arch = "aarch64")]
#[inline]
fn backend_ntt(c: &[KyberCoeff; KYBER_N]) -> [KyberCoeff; KYBER_N] {
    neon16::forward(c)
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
fn backend_ntt(c: &[KyberCoeff; KYBER_N]) -> [KyberCoeff; KYBER_N] {
    let mut r = to_raw(c);
    ntt_kernel(&mut r);
    // SAFETY: `ntt_kernel` canonicalises before returning.
    unsafe { from_raw(r) }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn backend_intt(c: &[KyberCoeff; KYBER_N]) -> [KyberCoeff; KYBER_N] {
    neon16::inverse(c)
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
fn backend_intt(c: &[KyberCoeff; KYBER_N]) -> [KyberCoeff; KYBER_N] {
    let mut r = to_raw(c);
    intt_kernel(&mut r);
    // SAFETY: `intt_kernel` canonicalises before returning.
    unsafe { from_raw(r) }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn backend_mul(x: &[KyberCoeff; KYBER_N], y: &[KyberCoeff; KYBER_N]) -> [KyberCoeff; KYBER_N] {
    neon16::multiply(x, y)
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
fn backend_mul(x: &[KyberCoeff; KYBER_N], y: &[KyberCoeff; KYBER_N]) -> [KyberCoeff; KYBER_N] {
    let mut a = to_raw(x);
    let mut b = to_raw(y);
    ntt_kernel(&mut a);
    ntt_kernel(&mut b);
    let mut r = basemul_kernel(&a, &b);
    intt_kernel(&mut r);
    // SAFETY: `intt_kernel` canonicalises before returning.
    unsafe { from_raw(r) }
}

/// Polynomial in R_q = Z_q[x] / (x^256 + 1)
#[derive(Clone, Debug)]
pub struct NTTPoly {
    pub coeffs: [KyberCoeff; KYBER_N],
}

impl NTTPoly {
    /// Create polynomial from coefficients
    pub fn new(coeffs: [KyberCoeff; KYBER_N]) -> Self {
        Self { coeffs }
    }

    /// Zero polynomial
    pub fn zero() -> Self {
        Self {
            coeffs: [KyberCoeff::zero(); KYBER_N],
        }
    }

    /// Create from slice (pads with zeros if needed)
    pub fn from_slice(data: &[i64]) -> Self {
        let mut coeffs = [KyberCoeff::zero(); KYBER_N];
        for (i, &val) in data.iter().take(KYBER_N).enumerate() {
            coeffs[i] = KyberCoeff::new(val);
        }
        Self { coeffs }
    }

    /// Forward NTT: coefficient → evaluation representation
    ///
    /// Implements Kyber's modified NTT for negacyclic convolution.
    /// Time complexity: O(n log n).
    ///
    /// Internally this runs the lazy-reduction kernel: coefficients are held in
    /// a redundant representation through all seven layers and canonicalised
    /// once at the end, so the butterflies cost one Barrett reduction plus a
    /// plain add and subtract each.
    pub fn ntt(&self) -> Self {
        Self {
            coeffs: backend_ntt(&self.coeffs),
        }
    }

    /// Inverse NTT: evaluation → coefficient representation
    ///
    /// Time complexity: O(n log n). Includes the `n^(-1)` scaling.
    pub fn intt(&self) -> Self {
        Self {
            coeffs: backend_intt(&self.coeffs),
        }
    }

    /// Multiply two polynomials using NTT
    /// This is the main optimization: O(n log n) instead of O(n²)
    pub fn mul_ntt(&self, other: &Self) -> Self {
        Self {
            coeffs: backend_mul(&self.coeffs, &other.coeffs),
        }
    }

    /// Add two polynomials (works in any representation)
    ///
    /// Reduction is a masked subtract rather than a compare-and-branch, which
    /// keeps the loop vectorisable.
    pub fn add(&self, other: &Self) -> Self {
        let a = to_raw(&self.coeffs);
        let b = to_raw(&other.coeffs);
        let mut out = [0_i64; KYBER_N];
        for i in 0..KYBER_N {
            out[i] = add_canonical(a[i], b[i]);
        }
        // SAFETY: `add_canonical` yields values in [0, q).
        Self {
            coeffs: unsafe { from_raw(out) },
        }
    }

    /// Subtract two polynomials (works in any representation)
    pub fn sub(&self, other: &Self) -> Self {
        let a = to_raw(&self.coeffs);
        let b = to_raw(&other.coeffs);
        let mut out = [0_i64; KYBER_N];
        for i in 0..KYBER_N {
            out[i] = sub_canonical(a[i], b[i]);
        }
        // SAFETY: `sub_canonical` yields values in [0, q).
        Self {
            coeffs: unsafe { from_raw(out) },
        }
    }

    /// Schoolbook multiplication (for comparison)
    ///
    /// The accumulator is kept unreduced: each `temp[k]` sums at most 256
    /// products of two values below q, so `|temp[k]| ≤ 256·(q-1)² ≈ 2.8e9`,
    /// which leaves ~32 spare bits in an i64. That removes the modular
    /// reduction from all 65 536 inner-loop iterations; only the final 256
    /// coefficients are reduced.
    pub fn mul_schoolbook(&self, other: &Self) -> Self {
        let a = to_raw(&self.coeffs);
        let b = to_raw(&other.coeffs);

        let mut temp = [0_i64; 2 * KYBER_N];
        for i in 0..KYBER_N {
            let ai = a[i];
            for (t, &bj) in temp[i..i + KYBER_N].iter_mut().zip(b.iter()) {
                *t += ai * bj;
            }
        }

        // Reduce modulo (x^n + 1): x^n ≡ -1. The difference can reach ~5.7e9,
        // beyond `fq_reduce`'s range, so use the wide canonicaliser here.
        let mut result = [0_i64; KYBER_N];
        for i in 0..KYBER_N {
            result[i] = canonicalize_wide(temp[i] - temp[i + KYBER_N]);
        }

        // SAFETY: `canonicalize_wide` yields values in [0, q).
        Self { coeffs: unsafe { from_raw(result) } }
    }

    // ========================================================================
    // CONSTANT-TIME OPERATIONS (for timing-attack resistance)
    // ========================================================================

    /// Constant-time forward NTT
    ///
    /// # Security
    ///
    /// This delegates to the same kernel as [`NTTPoly::ntt`], which is
    /// constant-time by construction: the butterfly loop is straight-line
    /// multiply / add / subtract / arithmetic-shift on fixed-width integers,
    /// with no data-dependent branch, no conditional move and no
    /// value-dependent memory access. The trip counts and the twiddle-index
    /// sequence depend only on `KYBER_N`, never on coefficient values.
    ///
    /// This is a change in strategy from the previous implementation, which
    /// composed [`ConstantTimeOps`] primitives and therefore paid a `subtle`
    /// optimisation barrier per operation. Those barriers exist to stop the
    /// compiler folding a `select` back into a branch; the lazy kernel contains
    /// no `select` to fold, so the barriers protect nothing here while costing
    /// roughly 4x. The remaining conditional — canonicalisation — is expressed
    /// as mask arithmetic (`v + (q & (v >> 63))`) rather than a comparison.
    ///
    /// One platform caveat: this assumes 64-bit integer multiply is
    /// fixed-latency, which holds on all 64-bit cores but not on some
    /// 32-bit microcontrollers with early-terminating multipliers.
    ///
    /// # Performance
    ///
    /// Identical to [`NTTPoly::ntt`] — there is no longer a constant-time
    /// penalty on the transform itself.
    pub fn ct_ntt(&self) -> Self {
        self.ntt()
    }

    /// Constant-time inverse NTT
    ///
    /// See [`NTTPoly::ct_ntt`] for the basis of the constant-time claim.
    pub fn ct_intt(&self) -> Self {
        self.intt()
    }

    /// Constant-time polynomial multiplication using NTT
    ///
    /// Complete timing-attack resistant polynomial multiplication.
    /// Use this when operating on secret polynomials.
    ///
    /// # Security
    ///
    /// All three stages (forward NTT, basemul, inverse NTT) are branchless
    /// straight-line arithmetic. See [`NTTPoly::ct_ntt`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Secret key polynomials
    /// let secret_a = NTTPoly::from_slice(&secret_coeffs_a);
    /// let secret_b = NTTPoly::from_slice(&secret_coeffs_b);
    ///
    /// // Use constant-time multiplication for security
    /// let product = secret_a.ct_mul_ntt(&secret_b);
    /// ```
    pub fn ct_mul_ntt(&self, other: &Self) -> Self {
        self.mul_ntt(other)
    }

    /// Constant-time polynomial addition
    ///
    /// Identical to [`NTTPoly::add`], which is already branchless: the modular
    /// fixup is mask arithmetic, not a conditional move, so there is no
    /// `select` for the compiler to turn into a branch and no barrier to place.
    /// See [`NTTPoly::ct_ntt`] for the reasoning behind this approach.
    pub fn ct_add(&self, other: &Self) -> Self {
        self.add(other)
    }

    /// Constant-time polynomial subtraction
    ///
    /// See [`NTTPoly::ct_add`].
    pub fn ct_sub(&self, other: &Self) -> Self {
        self.sub(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_roundtrip() {
        let poly = NTTPoly::from_slice(&[1, 2, 3, 4, 5]);
        let ntt_poly = poly.ntt();
        let result = ntt_poly.intt();

        // Should get back original polynomial
        for i in 0..5 {
            assert_eq!(result.coeffs[i].value(), poly.coeffs[i].value());
        }
        for i in 5..KYBER_N {
            assert_eq!(result.coeffs[i].value(), 0);
        }
    }

    #[test]
    fn test_ntt_multiplication() {
        // Test: (1 + x) * (1 + x) = 1 + 2x + x^2
        let f = NTTPoly::from_slice(&[1, 1]);
        let g = NTTPoly::from_slice(&[1, 1]);

        let product = f.mul_ntt(&g);

        assert_eq!(product.coeffs[0].value(), 1);
        assert_eq!(product.coeffs[1].value(), 2);
        assert_eq!(product.coeffs[2].value(), 1);
        for i in 3..KYBER_N {
            assert_eq!(product.coeffs[i].value(), 0);
        }
    }

    #[test]
    fn test_ntt_vs_schoolbook() {
        // Test that NTT and schoolbook give same result
        let f = NTTPoly::from_slice(&[1, 2, 3, 4, 5]);

        let ntt_result = f.mul_ntt(&f);
        let schoolbook_result = f.mul_schoolbook(&f);

        for i in 0..KYBER_N {
            assert_eq!(
                ntt_result.coeffs[i].value(),
                schoolbook_result.coeffs[i].value(),
                "Mismatch at coefficient {}", i
            );
        }
    }

    #[test]
    fn test_reduction_modulo_xn_plus_1() {
        // Test: x^128 * x^128 = x^256 ≡ -1 (mod x^256 + 1)
        let mut f_coeffs = [KyberCoeff::zero(); KYBER_N];
        f_coeffs[128] = KyberCoeff::new(1);
        let f = NTTPoly::new(f_coeffs);

        let product = f.mul_ntt(&f);

        // Should get -1 ≡ q-1 (mod q)
        assert_eq!(product.coeffs[0].value(), KYBER_Q - 1);
        for i in 1..KYBER_N {
            assert_eq!(product.coeffs[i].value(), 0);
        }
    }

    #[test]
    fn test_ntt_constants() {
        let constants = &NTT_CONSTANTS;

        // Verify ζ^256 ≡ 1 (mod q) (ζ is a 256-th root of unity)
        let zeta = KyberCoeff::new(ZETA_PRIMITIVE);
        let zeta_256 = zeta.pow(256);
        assert_eq!(zeta_256.value(), 1);

        // Verify n^(-1) * n ≡ 1 (mod q)
        // For Kyber NTT, we use 128^(-1) for scaling
        let n = KyberCoeff::new(128);
        let product = constants.n_inv * n;
        assert_eq!(product.value(), 1);
    }
}

#[cfg(test)]
mod ct_tests {
    use super::*;

    #[test]
    fn test_ct_ntt_roundtrip() {
        // Test that CT-NTT → CT-INTT recovers original polynomial
        let poly = NTTPoly::from_slice(&[1, 2, 3, 4, 5]);

        let ntt_poly = poly.ct_ntt();
        let result = ntt_poly.ct_intt();

        for i in 0..5 {
            assert_eq!(
                result.coeffs[i].value(),
                poly.coeffs[i].value(),
                "CT roundtrip failed at coefficient {}", i
            );
        }
    }

    #[test]
    fn test_ct_vs_vt_ntt() {
        // Verify constant-time NTT produces same results as variable-time
        let poly = NTTPoly::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let vt_result = poly.ntt();
        let ct_result = poly.ct_ntt();

        for i in 0..KYBER_N {
            assert_eq!(
                vt_result.coeffs[i].value(),
                ct_result.coeffs[i].value(),
                "CT-NTT differs from VT-NTT at coefficient {}", i
            );
        }
    }

    #[test]
    fn test_ct_vs_vt_intt() {
        // Verify constant-time INTT produces same results as variable-time
        let poly = NTTPoly::from_slice(&[1, 2, 3, 4, 5]);
        let ntt_poly = poly.ntt(); // Use VT to get NTT domain data

        let vt_result = ntt_poly.intt();
        let ct_result = ntt_poly.ct_intt();

        for i in 0..KYBER_N {
            assert_eq!(
                vt_result.coeffs[i].value(),
                ct_result.coeffs[i].value(),
                "CT-INTT differs from VT-INTT at coefficient {}", i
            );
        }
    }

    #[test]
    fn test_ct_mul_ntt_correctness() {
        // Test (1 + x) * (1 + x) = 1 + 2x + x²
        let f = NTTPoly::from_slice(&[1, 1]);

        let vt_result = f.mul_ntt(&f);
        let ct_result = f.ct_mul_ntt(&f);

        // Both should give [1, 2, 1, 0, 0, ...]
        assert_eq!(ct_result.coeffs[0].value(), 1);
        assert_eq!(ct_result.coeffs[1].value(), 2);
        assert_eq!(ct_result.coeffs[2].value(), 1);

        // Verify CT matches VT
        for i in 0..KYBER_N {
            assert_eq!(
                vt_result.coeffs[i].value(),
                ct_result.coeffs[i].value(),
                "CT-mul differs from VT-mul at coefficient {}", i
            );
        }
    }

    #[test]
    fn test_ct_mul_vs_schoolbook() {
        // Verify CT-NTT multiplication matches schoolbook
        let f = NTTPoly::from_slice(&[1, 2, 3, 4, 5]);

        let ntt_result = f.ct_mul_ntt(&f);
        let schoolbook_result = f.mul_schoolbook(&f);

        for i in 0..KYBER_N {
            assert_eq!(
                ntt_result.coeffs[i].value(),
                schoolbook_result.coeffs[i].value(),
                "CT-NTT mul differs from schoolbook at coefficient {}", i
            );
        }
    }

    #[test]
    fn test_ct_polynomial_add() {
        let a = NTTPoly::from_slice(&[1, 2, 3]);
        let b = NTTPoly::from_slice(&[4, 5, 6]);

        let ct_result = a.ct_add(&b);
        let vt_result = a.add(&b);

        for i in 0..KYBER_N {
            assert_eq!(
                ct_result.coeffs[i].value(),
                vt_result.coeffs[i].value(),
                "CT-add differs from VT-add at coefficient {}", i
            );
        }
    }

    #[test]
    fn test_ct_polynomial_sub() {
        let a = NTTPoly::from_slice(&[10, 20, 30]);
        let b = NTTPoly::from_slice(&[3, 5, 7]);

        let ct_result = a.ct_sub(&b);
        let vt_result = a.sub(&b);

        for i in 0..KYBER_N {
            assert_eq!(
                ct_result.coeffs[i].value(),
                vt_result.coeffs[i].value(),
                "CT-sub differs from VT-sub at coefficient {}", i
            );
        }
    }
}

/// Cross-checks between the NEON int16 backend and the portable i64 kernel.
///
/// The two are independent implementations over different representations, so
/// agreement on random inputs is a strong correctness signal for both. These
/// also pin the Montgomery scale constants `F_STANDALONE` / `F_AFTER_BASEMUL`,
/// which are the one place the backend diverges from the reference C.
#[cfg(test)]
mod backend_tests {
    use super::*;

    /// Deterministic pseudo-random coefficients — no dev-dependency needed.
    fn sample(seed: u64) -> [KyberCoeff; KYBER_N] {
        let mut s = seed | 1;
        core::array::from_fn(|_| {
            // xorshift64*
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            KyberCoeff::new((s.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as i64)
        })
    }

    fn portable_ntt(c: &[KyberCoeff; KYBER_N]) -> [i64; KYBER_N] {
        let mut r = to_raw(c);
        ntt_kernel(&mut r);
        r
    }

    fn portable_intt(c: &[KyberCoeff; KYBER_N]) -> [i64; KYBER_N] {
        let mut r = to_raw(c);
        intt_kernel(&mut r);
        r
    }

    fn portable_mul(x: &[KyberCoeff; KYBER_N], y: &[KyberCoeff; KYBER_N]) -> [i64; KYBER_N] {
        let mut a = to_raw(x);
        let mut b = to_raw(y);
        ntt_kernel(&mut a);
        ntt_kernel(&mut b);
        let mut r = basemul_kernel(&a, &b);
        intt_kernel(&mut r);
        r
    }

    #[test]
    fn backends_agree_on_forward_ntt() {
        for seed in 1..40u64 {
            let input = sample(seed);
            let dispatched = backend_ntt(&input);
            let portable = portable_ntt(&input);
            for i in 0..KYBER_N {
                assert_eq!(
                    dispatched[i].value(),
                    portable[i],
                    "forward NTT backend mismatch at coeff {i} (seed {seed})"
                );
            }
        }
    }

    #[test]
    fn backends_agree_on_inverse_ntt() {
        for seed in 1..40u64 {
            let input = sample(seed);
            let dispatched = backend_intt(&input);
            let portable = portable_intt(&input);
            for i in 0..KYBER_N {
                assert_eq!(
                    dispatched[i].value(),
                    portable[i],
                    "inverse NTT backend mismatch at coeff {i} (seed {seed})"
                );
            }
        }
    }

    #[test]
    fn backends_agree_on_multiplication() {
        for seed in 1..40u64 {
            let x = sample(seed);
            let y = sample(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let dispatched = backend_mul(&x, &y);
            let portable = portable_mul(&x, &y);
            for i in 0..KYBER_N {
                assert_eq!(
                    dispatched[i].value(),
                    portable[i],
                    "mul_ntt backend mismatch at coeff {i} (seed {seed})"
                );
            }
        }
    }

    #[test]
    fn random_roundtrip_and_schoolbook_agreement() {
        for seed in 1..25u64 {
            let f = NTTPoly::new(sample(seed));
            let g = NTTPoly::new(sample(seed ^ 0xDEAD_BEEF));

            // NTT ∘ INTT is the identity on random full-degree polynomials.
            let back = f.ntt().intt();
            for i in 0..KYBER_N {
                assert_eq!(
                    back.coeffs[i].value(),
                    f.coeffs[i].value(),
                    "roundtrip failed at coeff {i} (seed {seed})"
                );
            }

            // NTT multiplication agrees with schoolbook on random inputs.
            let via_ntt = f.mul_ntt(&g);
            let via_schoolbook = f.mul_schoolbook(&g);
            for i in 0..KYBER_N {
                assert_eq!(
                    via_ntt.coeffs[i].value(),
                    via_schoolbook.coeffs[i].value(),
                    "mul mismatch at coeff {i} (seed {seed})"
                );
            }
        }
    }

    /// The NEON backend reuses the reference's Montgomery twiddle table; this
    /// checks it really is the compile-time table scaled by R, including the
    /// ± pair layout that `basemul` relies on.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn montgomery_zetas_match_portable_table() {
        const R: i64 = 65536 % KYBER_Q;
        let r_inv = KyberCoeff::new(R).inverse().unwrap();

        for k in 1..128usize {
            let mont = neon16::zeta(k);
            let standard = KyberCoeff::new(mont as i64) * r_inv;
            assert_eq!(
                standard.value(),
                NTT_CONSTANTS.zetas[k].value(),
                "butterfly twiddle {k} disagrees with the portable table"
            );
        }

        // basemul: pair 2i uses +ZETAS[64+i], pair 2i+1 uses -ZETAS[64+i]
        for i in 0..64usize {
            let mont = neon16::zeta(64 + i);
            let plus = KyberCoeff::new(mont as i64) * r_inv;
            let minus = KyberCoeff::new(-(mont as i64)) * r_inv;
            assert_eq!(
                plus.value(),
                NTT_CONSTANTS.zetas[128 + 2 * i].value(),
                "basemul twiddle for pair {} disagrees",
                2 * i
            );
            assert_eq!(
                minus.value(),
                NTT_CONSTANTS.zetas[128 + 2 * i + 1].value(),
                "basemul twiddle for pair {} disagrees",
                2 * i + 1
            );
        }
    }
}
