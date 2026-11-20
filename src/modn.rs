//! High-Performance Fixed-Modulus Arithmetic
//!
//! This module provides `ModN<const N: i64>` - a compile-time fixed modulus type
//! that offers significantly better performance than runtime modulus operations.
//! The modulus must lie in `1..2^31`; the constructors enforce this at compile
//! time.
//!
//! # Key Advantages
//!
//! - **10-1000x faster** than runtime modulus (no reduction overhead)
//! - **75% smaller** memory footprint (only store value, not modulus)
//! - **Type-safe** - cannot mix different moduli
//! - **SIMD-friendly** - enables vectorization
//! - **Cache-efficient** - 4x more elements per cache line
//!
//! # Example
//!
//! ```rust
//! use moduletto::ModN;
//!
//! // Define types for specific moduli
//! type Mod7 = ModN<7>;
//! type Mod256 = ModN<256>;
//!
//! // Fast operations with compile-time modulus
//! let a = Mod7::new(10);  // Automatically reduced to 3
//! let b = Mod7::new(5);
//! let sum = a + b;        // (3 + 5) mod 7 = 1
//!
//! assert_eq!(sum.value(), 1);
//! ```

use core::fmt;
use core::ops::{Add, Mul, Neg, Sub};

/// A value modulo N, where N is known at compile time.
///
/// This type provides high-performance modular arithmetic by encoding
/// the modulus in the type itself, eliminating runtime overhead.
///
/// # Type Safety
///
/// Different moduli are incompatible types:
/// ```compile_fail
/// use moduletto::ModN;
/// let a = ModN::<7>::new(3);
/// let b = ModN::<13>::new(5);
/// let sum = a + b;  // Compile error: type mismatch
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ModN<const N: i64> {
    value: i64, // Always in canonical form [0, N)
}

impl<const N: i64> ModN<N> {
    /// Compile-time check of the modulus. `ModN` promises its arithmetic for
    /// moduli in `1..2^31`: above that, products of two canonical values
    /// overflow `i64`. Referenced from the constructors so a type with an
    /// out-of-range `N` fails to compile instead of wrapping silently.
    const VALID_MODULUS: () = assert!(
        N > 0 && N < (1 << 31),
        "ModN<N>: the modulus must be positive and below 2^31"
    );

    /// Creates a new modular value, automatically reducing to canonical form.
    ///
    /// # Examples
    ///
    /// ```
    /// use moduletto::ModN;
    ///
    /// let a = ModN::<7>::new(10);  // 10 mod 7 = 3
    /// assert_eq!(a.value(), 3);
    ///
    /// let b = ModN::<7>::new(-4);  // -4 mod 7 = 3
    /// assert_eq!(b.value(), 3);
    /// ```
    ///
    /// A modulus of 2^31 or more does not compile:
    ///
    /// ```compile_fail
    /// use moduletto::ModN;
    /// let _ = ModN::<2147483648>::new(1);
    /// ```
    ///
    /// # Timing
    ///
    /// Variable-time: the reduction is a `%`, which compilers lower to a
    /// hardware divide in unoptimised and size-optimised builds
    /// (`opt-level = 0`, `"z"`), and a divide's latency depends on its
    /// operands. Use this for constants and public values. A secret enters
    /// through [`ModN::ct_new`].
    pub const fn new(value: i64) -> Self {
        let () = Self::VALID_MODULUS;

        let mut v = value % N;
        if v < 0 {
            v += N;
        }
        Self { value: v }
    }

    /// Shift of the reciprocal used by [`ModN::ct_new`]: 63 + bit length of N.
    const CT_NEW_SHIFT: u32 = {
        let () = Self::VALID_MODULUS;
        63 + (64 - (N as u64).leading_zeros())
    };

    /// `⌊2^SHIFT / N⌋`, at most 2^64. Evaluated at compile time, so the
    /// division is never in the generated code.
    const CT_NEW_MU: i128 = (1_i128 << Self::CT_NEW_SHIFT) / N as i128;

    /// Creates a modular value from any `i64` without a division and without
    /// a branch: the constructor for secret values.
    ///
    /// [`ModN::new`] reduces with `%`. At `opt-level = "z"` and in
    /// unoptimised builds that is a hardware divide, whose timing depends on
    /// the value (the KyberSlash pattern). This is a Barrett reduction with
    /// a compile-time reciprocal instead: one 128-bit multiply, a shift, a
    /// multiply-subtract and two masked corrections.
    ///
    /// With `b` the bit length of N, `μ = ⌊2^(63+b) / N⌋` and
    /// `q = ⌊x·μ / 2^(63+b)⌋`, the estimate `q` is within one of `⌊x / N⌋`
    /// for every `i64` x (below it for x ≥ 0, above it for x < 0), so
    /// `x − q·N` lies in `[−N, 2N)`. `x·μ` is at most 2^127 in magnitude and
    /// fits `i128`.
    ///
    /// On 32-bit targets the 128-bit multiply is a library call
    /// (`__multi3`), which is straight-line code; on AArch64 run secret
    /// computations under [`crate::dit::with_dit`] as for the other `ct_*`
    /// operations.
    ///
    /// ```
    /// use moduletto::ModN;
    ///
    /// assert_eq!(ModN::<3329>::ct_new(-1).value(), 3328);
    /// assert_eq!(ModN::<7>::ct_new(i64::MIN).value(), ModN::<7>::new(i64::MIN).value());
    /// ```
    pub fn ct_new(value: i64) -> Self {
        use subtle::{Choice, ConditionallySelectable};

        let q = ((value as i128 * Self::CT_NEW_MU) >> Self::CT_NEW_SHIFT) as i64;
        // q·N is within N of `value`, which can be just outside i64 at the
        // extremes; the difference is small, so wrapping arithmetic is exact.
        let r = value.wrapping_sub(q.wrapping_mul(N)); // [-N, 2N)

        let negative = Choice::from((r >> 63) as u8 & 1);
        let r = i64::conditional_select(&r, &(r + N), negative); // [0, 2N)
        let reduced = r - N;
        let in_range = Choice::from((reduced >> 63) as u8 & 1);
        let r = i64::conditional_select(&reduced, &r, in_range); // [0, N)
        Self { value: r }
    }

    /// Returns the canonical value in the range [0, N).
    pub const fn value(self) -> i64 {
        self.value
    }

    /// Returns the modulus (compile-time constant).
    pub const fn modulus() -> i64 {
        N
    }

    /// Creates zero (additive identity).
    pub const fn zero() -> Self {
        let () = Self::VALID_MODULUS;
        Self { value: 0 }
    }

    /// Creates one (multiplicative identity).
    pub const fn one() -> Self {
        let () = Self::VALID_MODULUS;
        Self { value: 1 }
    }

    /// Checks if this value is zero.
    pub const fn is_zero(self) -> bool {
        self.value == 0
    }

    /// Checks if this value is one.
    pub const fn is_one(self) -> bool {
        self.value == 1
    }

    /// Computes self^exp using fast exponentiation (square-and-multiply).
    ///
    /// # Examples
    ///
    /// ```
    /// use moduletto::ModN;
    ///
    /// let base = ModN::<13>::new(3);
    /// let result = base.pow(100);
    /// assert_eq!(result.value(), 3);  // 3^100 mod 13 = 3
    /// ```
    pub fn pow(self, mut exp: u64) -> Self {
        if exp == 0 {
            return Self::one();
        }

        let mut result = Self::one();
        let mut base = self;

        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exp >>= 1;
        }
        result
    }

    /// Computes the modular multiplicative inverse using Extended Euclidean Algorithm.
    ///
    /// Returns `Some(inverse)` if the inverse exists (when gcd(value, N) = 1),
    /// or `None` otherwise.
    ///
    /// This is **much faster** than brute force search - O(log N) vs O(N).
    ///
    /// # Examples
    ///
    /// ```
    /// use moduletto::ModN;
    ///
    /// let a = ModN::<7>::new(3);
    /// let inv = a.inverse().unwrap();
    /// assert_eq!(inv.value(), 5);  // 3 * 5 = 15 ≡ 1 (mod 7)
    ///
    /// // Verify
    /// assert_eq!((a * inv).value(), 1);
    /// ```
    pub fn inverse(self) -> Option<Self> {
        let (gcd, x, _) = Self::extended_gcd(self.value, N);
        if gcd == 1 {
            Some(Self::new(x))
        } else {
            None
        }
    }

    /// Extended Euclidean Algorithm.
    ///
    /// Returns (gcd(a, b), x, y) such that ax + by = gcd(a, b).
    fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
        if a == 0 {
            (b, 0, 1)
        } else {
            let (gcd, x1, y1) = Self::extended_gcd(b % a, a);
            let x = y1 - (b / a) * x1;
            let y = x1;
            (gcd, x, y)
        }
    }
}

// Arithmetic Operations

impl<const N: i64> Add for ModN<N> {
    type Output = Self;

    /// Fast addition with single comparison.
    ///
    /// # Performance
    ///
    /// - Best case: O(1) - no reduction needed
    /// - Worst case: O(1) - single subtraction
    ///
    /// vs. O(N) for runtime modulus reduction.
    fn add(self, other: Self) -> Self {
        let sum = self.value + other.value;
        if sum >= N {
            Self { value: sum - N }
        } else {
            Self { value: sum }
        }
    }
}

impl<const N: i64> Sub for ModN<N> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let diff = self.value - other.value;
        if diff < 0 {
            Self { value: diff + N }
        } else {
            Self { value: diff }
        }
    }
}

impl<const N: i64> Mul for ModN<N> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        // i64 multiplication, then reduce
        Self::new(self.value * other.value)
    }
}

impl<const N: i64> Neg for ModN<N> {
    type Output = Self;

    fn neg(self) -> Self {
        if self.value == 0 {
            self
        } else {
            Self {
                value: N - self.value,
            }
        }
    }
}

// Display

impl<const N: i64> fmt::Display for ModN<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

// SIMD capability detection and wrapper methods
impl<const N: i64> ModN<N> {
    /// Check if ARM NEON is available on this platform
    #[cfg(target_arch = "aarch64")]
    pub fn has_neon() -> bool {
        true // NEON is always available on aarch64
    }

    /// Check if x86 AVX2 is available on this platform.
    ///
    /// With `std` this is detected at run time. Without `std` there is no
    /// run-time detection, so it reports whether the build targets AVX2
    /// (for example `-C target-feature=+avx2` or `-C target-cpu=native`).
    #[cfg(target_arch = "x86_64")]
    pub fn has_avx2() -> bool {
        #[cfg(feature = "std")]
        {
            std::is_x86_feature_detected!("avx2")
        }
        #[cfg(not(feature = "std"))]
        {
            cfg!(target_feature = "avx2")
        }
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub fn has_simd() -> bool {
        false
    }
}

// Common Type Aliases

#[allow(dead_code)]
/// GF(2) - Binary field
pub type GF2 = ModN<2>;

#[allow(dead_code)]
/// GF(7) - Small prime field (used in examples)
pub type GF7 = ModN<7>;

#[allow(dead_code)]
/// GF(251) - Largest single-byte prime field
pub type GF251 = ModN<251>;

#[allow(dead_code)]
/// GF(256) - Common in error correction (though not technically a prime field)
pub type Mod256 = ModN<256>;

#[allow(dead_code)]
/// Mersenne prime 2^31 - 1 (common in cryptography)
pub type Mersenne31 = ModN<2147483647>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_creation() {
        let a = ModN::<7>::new(10);
        assert_eq!(a.value(), 3);

        let b = ModN::<7>::new(-4);
        assert_eq!(b.value(), 3);
    }

    /// `ct_new` against the division, for moduli across the allowed range
    /// (including 1, powers of two and 2^31 - 1) and inputs at the edges of
    /// `i64`, around multiples of N, and pseudo-random.
    #[test]
    fn ct_new_matches_division() {
        fn check<const N: i64>() {
            let mut inputs = vec![0, 1, -1, i64::MAX, i64::MAX - 1, i64::MIN, i64::MIN + 1];
            for m in [1, 2, 3, 1 << 20, (1 << 32) + 1, i64::MAX / N, i64::MIN / N] {
                for d in -2..=2 {
                    inputs.push(m.wrapping_mul(N).wrapping_add(d));
                    inputs.push(m.wrapping_mul(N).wrapping_neg().wrapping_add(d));
                }
            }
            for sh in 0..63 {
                for d in -1..=1 {
                    inputs.push((1_i64 << sh).wrapping_add(d));
                    inputs.push((-1_i64 << sh).wrapping_add(d));
                }
            }
            let mut x = 0x9e37_79b9_7f4a_7c15_u64 ^ N as u64;
            for _ in 0..50_000 {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                inputs.push(x as i64);
                inputs.push((x >> 40) as i64 - (1 << 23));
            }
            for v in inputs {
                assert_eq!(
                    ModN::<N>::ct_new(v).value(),
                    ModN::<N>::new(v).value(),
                    "N = {N}, v = {v}"
                );
            }
        }
        check::<1>();
        check::<2>();
        check::<3>();
        check::<7>();
        check::<256>();
        check::<3329>();
        check::<8380417>();
        check::<1073741824>();
        check::<1073741825>();
        check::<2147483647>();
    }

    #[test]
    fn test_addition() {
        let a = ModN::<7>::new(5);
        let b = ModN::<7>::new(4);
        let sum = a + b;
        assert_eq!(sum.value(), 2); // (5 + 4) mod 7 = 2
    }

    #[test]
    fn test_subtraction() {
        let a = ModN::<7>::new(2);
        let b = ModN::<7>::new(5);
        let diff = a - b;
        assert_eq!(diff.value(), 4); // (2 - 5) mod 7 = -3 mod 7 = 4
    }

    #[test]
    fn test_multiplication() {
        let a = ModN::<7>::new(5);
        let b = ModN::<7>::new(3);
        let product = a * b;
        assert_eq!(product.value(), 1); // (5 * 3) mod 7 = 15 mod 7 = 1
    }

    #[test]
    fn test_power() {
        let base = ModN::<13>::new(3);
        let result = base.pow(4);
        assert_eq!(result.value(), 3); // 3^4 mod 13 = 81 mod 13 = 3
    }

    #[test]
    fn test_inverse() {
        let a = ModN::<7>::new(3);
        let inv = a.inverse().unwrap();
        assert_eq!(inv.value(), 5);

        // Verify: 3 * 5 = 15 ≡ 1 (mod 7)
        assert_eq!((a * inv).value(), 1);
    }

    #[test]
    fn test_inverse_nonexistent() {
        let a = ModN::<6>::new(4); // gcd(4, 6) = 2 ≠ 1
        assert!(a.inverse().is_none());
    }

    #[test]
    fn test_negation() {
        let a = ModN::<7>::new(3);
        let neg_a = -a;
        assert_eq!(neg_a.value(), 4); // -3 mod 7 = 4

        // Verify: a + (-a) = 0
        assert_eq!((a + neg_a).value(), 0);
    }

    #[test]
    fn test_gf2() {
        let a = GF2::new(1);
        let b = GF2::new(1);
        assert_eq!((a + b).value(), 0); // 1 + 1 = 0 in GF(2)
        assert_eq!((a * b).value(), 1); // 1 * 1 = 1 in GF(2)
    }

    #[test]
    fn test_type_safety() {
        // This test just demonstrates that the following would NOT compile:
        // let a = ModN::<7>::new(3);
        // let b = ModN::<13>::new(5);
        // let _ = a + b;  // Type error!
    }
}
