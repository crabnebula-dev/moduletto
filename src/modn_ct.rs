//! Constant-Time ModN Operations for Side-Channel Resistance
//!
//! This module provides constant-time (CT) implementations of modular arithmetic
//! operations that are resistant to timing attacks. These should be used when
//! operating on secret data in cryptographic contexts.
//!
//! # Security Guarantees
//!
//! All operations in this module:
//! - Execute in constant time (no data-dependent branches)
//! - Have constant memory access patterns
//! - Do not leak secrets through timing side channels
//!
//! # Performance Trade-offs
//!
//! Constant-time operations are typically 1.5-3x slower than variable-time
//! operations due to the elimination of optimizations. Use them only for
//! operations on secret data.
//!
//! # Example
//!
//! ```rust
//! use moduletto::ModN;
//! use moduletto::modn_ct::ConstantTimeOps;
//!
//! type KyberMod = ModN<3329>;
//!
//! // Operating on secret key material
//! let secret_a = KyberMod::new(1234);
//! let secret_b = KyberMod::new(5678);
//!
//! // Use constant-time operations
//! let result = secret_a.ct_add(secret_b);
//! let product = secret_a.ct_mul(secret_b);
//! ```

use crate::modn::ModN;

/// Extension trait providing constant-time operations for ModN
pub trait ConstantTimeOps<const N: i64>: Sized {
    /// Constant-time addition
    fn ct_add(self, other: Self) -> Self;

    /// Constant-time subtraction
    fn ct_sub(self, other: Self) -> Self;

    /// Constant-time multiplication
    fn ct_mul(self, other: Self) -> Self;

    /// Constant-time negation
    fn ct_neg(self) -> Self;

    /// Constant-time conditional selection
    /// Returns `a` if bit 0 of `choice` is 0, returns `b` if bit 0 is 1.
    /// Only bit 0 is examined; upper bits are ignored.
    fn ct_select(a: Self, b: Self, choice: u8) -> Self;

    /// Constant-time conditional swap
    /// Swaps `a` and `b` if bit 0 of `choice` is 1. Upper bits are ignored.
    fn ct_swap(a: &mut Self, b: &mut Self, choice: u8);

    /// Constant-time equality check
    /// Returns 1 if equal, 0 otherwise (as u8 to avoid bool timing leaks)
    fn ct_eq(self, other: Self) -> u8;

    /// Constant-time comparison: returns 1 if self < other, 0 otherwise
    fn ct_lt(self, other: Self) -> u8;
}

/// Opaque mask barrier: prevents the compiler from observing that `mask` is
/// always 0 or -1, which could let it reintroduce branches.
///
/// Uses `core::hint::black_box` to hide the value from the optimiser.
/// This is weaker than inline asm (which `subtle` uses) but is the best
/// tool available in stable Rust without an asm dependency.
#[inline(always)]
fn ct_mask(mask: i64) -> i64 {
    core::hint::black_box(mask)
}

impl<const N: i64> ConstantTimeOps<N> for ModN<N> {
    /// Constant-time addition with branchless reduction
    ///
    /// # Implementation
    ///
    /// Uses bitwise operations to avoid data-dependent branches:
    /// ```text
    /// sum = a + b
    /// needs_reduction = (sum >= N) ? 0xFF...FF : 0x00...00
    /// result = (sum - N) & needs_reduction | sum & ~needs_reduction
    /// ```
    ///
    /// # Performance
    ///
    /// ~1.5x slower than branching version, but constant-time.
    fn ct_add(self, other: Self) -> Self {
        let sum = self.value() + other.value();

        // Compute reduction mask without branching
        // If sum >= N, this will be all 1s (-1), otherwise all 0s (0)
        let needs_reduction = ct_mask(((N - 1 - sum) >> 63) as i64);

        let reduced = sum - N;

        // Branchless selection:
        // If needs_reduction is -1 (all 1s), select reduced
        // If needs_reduction is 0, select sum
        let result = (reduced & needs_reduction) | (sum & !needs_reduction);

        // SAFETY: result is guaranteed to be in [0, N) by construction
        // - If sum < N: result = sum (which is < N)
        // - If sum >= N: result = sum - N (which is in [0, N))
        unsafe { Self::new_unchecked(result) }
    }

    /// Constant-time subtraction with branchless underflow handling
    fn ct_sub(self, other: Self) -> Self {
        let diff = self.value() - other.value();

        // Compute underflow mask: -1 if diff < 0, 0 otherwise
        let needs_adjustment = ct_mask((diff >> 63) as i64);

        let adjusted = diff + N;

        // Branchless selection
        let result = (adjusted & needs_adjustment) | (diff & !needs_adjustment);

        unsafe { Self::new_unchecked(result) }
    }

    /// Constant-time multiplication with constant-time reduction
    fn ct_mul(self, other: Self) -> Self {
        let product = self.value() * other.value();

        // Constant-time reduction modulo N
        // This uses the fact that product < N² for inputs in [0, N)
        ct_reduce::<N>(product)
    }

    /// Constant-time negation
    fn ct_neg(self) -> Self {
        let is_zero = ct_is_zero(self.value());

        // If zero, result is 0; otherwise result is N - value
        let negated = N - self.value();

        // Branchless selection
        let mask = ct_mask(-(is_zero as i64));
        let result = (self.value() & mask) | (negated & !mask);

        unsafe { Self::new_unchecked(result) }
    }

    /// Constant-time conditional selection
    ///
    /// Returns `a` if bit 0 of `choice` is 0, returns `b` if bit 0 is 1.
    /// This operation takes constant time regardless of the choice value.
    fn ct_select(a: Self, b: Self, choice: u8) -> Self {
        let mask = ct_mask(-((choice & 1) as i64));
        let result = (a.value() & !mask) | (b.value() & mask);
        unsafe { Self::new_unchecked(result) }
    }

    /// Constant-time conditional swap
    ///
    /// Swaps `a` and `b` if bit 0 of `choice` is 1, using XOR-based swap trick.
    fn ct_swap(a: &mut Self, b: &mut Self, choice: u8) {
        let mask = ct_mask(-((choice & 1) as i64));
        let xor = (a.value() ^ b.value()) & mask;

        let new_a = a.value() ^ xor;
        let new_b = b.value() ^ xor;

        *a = unsafe { Self::new_unchecked(new_a) };
        *b = unsafe { Self::new_unchecked(new_b) };
    }

    /// Constant-time equality check
    ///
    /// Returns 1 if equal, 0 otherwise (as u8).
    /// Avoids bool to prevent compiler from introducing branches.
    fn ct_eq(self, other: Self) -> u8 {
        ct_is_zero(self.value() ^ other.value())
    }

    /// Constant-time less-than comparison
    fn ct_lt(self, other: Self) -> u8 {
        // Compute diff = self - other
        let diff = self.value() - other.value();

        // If diff < 0, sign bit is 1
        ((core::hint::black_box(diff) >> 63) & 1) as u8
    }
}

// Helper functions

/// Constant-time check if value is zero
/// Returns 1 if zero, 0 otherwise
#[inline]
fn ct_is_zero(x: i64) -> u8 {
    // If x == 0, then x | -x == 0
    // If x != 0, then x | -x has sign bit set
    let neg_x = x.wrapping_neg();
    let result = x | neg_x;

    // Extract inverted sign bit: 1 if zero, 0 if non-zero
    (1 & ((result >> 63) ^ 1)) as u8
}

/// Constant-time reduction modulo N using Barrett reduction
///
/// Barrett reduction uses precomputed constants to reduce a product x (where x < N²)
/// to its canonical form modulo N in constant time.
///
/// # Algorithm
///
/// Given x < N², compute:
///   k = ⌈log₂(N)⌉
///   μ = ⌊2^(2k) / N⌋  (precomputed constant)
///   q = ⌊(x · μ) / 2^(2k)⌋
///   r = x - q · N
///   if r >= N: r -= N  (at most one conditional subtraction)
///   return r
///
/// # References
///
/// Barrett, Paul (1987). "Implementing the Rivest Shamir and Adleman Public Key
/// Encryption Algorithm on a Standard Digital Signal Processor"
///
/// # Performance
///
/// ~2-3x slower than division, but constant-time for all inputs < N²
#[inline]
fn ct_reduce<const N: i64>(x: i64) -> ModN<N> {
    // Compute k = ⌈log₂(N)⌉
    // For Kyber q=3329: log₂(3329) ≈ 11.7, so k = 12
    let k = if N <= 0 {
        panic!("Modulus must be positive");
    } else {
        64 - (N - 1).leading_zeros()
    };

    // Compute μ = ⌊2^(2k) / N⌋
    // For Kyber (k=12), this is (1 << 24) / 3329 = 5041
    let two_k = (k * 2) as u32;
    let mu = (1_i128 << two_k) / (N as i128);

    // Barrett reduction
    // q ≈ x / N, computed as q = ⌊(x · μ) / 2^(2k)⌋
    // Use i128 to avoid overflow when N is large (up to 2^31)
    let q = (((x as i128) * mu) >> two_k) as i64;

    // r = x - q · N
    let mut r = x - q * N;

    // At this point, r is in the range [0, 2N)
    // We need at most one conditional subtraction to get r < N

    // Constant-time conditional subtraction
    // Check if r >= N using: (r - N) has sign bit 0 if r >= N, 1 if r < N
    let diff = r - N;
    let is_negative = (core::hint::black_box(diff) >> 63) & 1;
    let needs_reduction = 1 - is_negative;
    let mask = ct_mask(-(needs_reduction as i64));

    // If needs_reduction, use diff (r - N); otherwise use r
    r = (diff & mask) | (r & !mask);

    // r is now guaranteed to be in [0, N)
    unsafe { ModN::new_unchecked(r) }
}

// We need to extend ModN with unsafe operations for constant-time code
impl<const N: i64> ModN<N> {
    /// Creates a ModN without checking that value is in [0, N)
    ///
    /// # Safety
    ///
    /// The caller must ensure that 0 <= value < N
    #[inline(always)]
    pub(crate) unsafe fn new_unchecked(value: i64) -> Self {
        // SAFETY: ModN is a transparent wrapper around i64
        // We can directly construct it from a value
        core::mem::transmute(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestMod = ModN<3329>; // Kyber modulus

    #[test]
    fn test_ct_add_correctness() {
        // Test various cases
        let a = TestMod::new(1000);
        let b = TestMod::new(2000);
        assert_eq!(a.ct_add(b).value(), (a + b).value());

        // Test wraparound
        let a = TestMod::new(3000);
        let b = TestMod::new(1000);
        assert_eq!(a.ct_add(b).value(), (a + b).value());

        // Test edge cases
        let a = TestMod::new(0);
        let b = TestMod::new(3328);
        assert_eq!(a.ct_add(b).value(), (a + b).value());
    }

    #[test]
    fn test_ct_sub_correctness() {
        let a = TestMod::new(2000);
        let b = TestMod::new(1000);
        assert_eq!(a.ct_sub(b).value(), (a - b).value());

        // Test underflow
        let a = TestMod::new(500);
        let b = TestMod::new(1000);
        assert_eq!(a.ct_sub(b).value(), (a - b).value());

        // Test edge case
        let a = TestMod::new(0);
        let b = TestMod::new(1);
        assert_eq!(a.ct_sub(b).value(), (a - b).value());
    }

    #[test]
    fn test_ct_mul_correctness() {
        let a = TestMod::new(123);
        let b = TestMod::new(456);
        assert_eq!(a.ct_mul(b).value(), (a * b).value());

        // Test large values
        let a = TestMod::new(3000);
        let b = TestMod::new(3000);
        assert_eq!(a.ct_mul(b).value(), (a * b).value());

        // Test zero
        let a = TestMod::new(0);
        let b = TestMod::new(1234);
        assert_eq!(a.ct_mul(b).value(), 0);
    }

    #[test]
    fn test_ct_neg_correctness() {
        let a = TestMod::new(1234);
        assert_eq!(a.ct_neg().value(), (-a).value());

        // Test zero
        let a = TestMod::new(0);
        assert_eq!(a.ct_neg().value(), 0);

        // Test edge case
        let a = TestMod::new(3328);
        assert_eq!(a.ct_neg().value(), 1);
    }

    #[test]
    fn test_ct_select() {
        let a = TestMod::new(111);
        let b = TestMod::new(222);

        assert_eq!(TestMod::ct_select(a, b, 0).value(), 111);
        assert_eq!(TestMod::ct_select(a, b, 1).value(), 222);
        assert_eq!(TestMod::ct_select(a, b, 255).value(), 222); // Any non-zero
    }

    #[test]
    fn test_ct_swap() {
        let mut a = TestMod::new(111);
        let mut b = TestMod::new(222);

        TestMod::ct_swap(&mut a, &mut b, 0);
        assert_eq!(a.value(), 111);
        assert_eq!(b.value(), 222);

        TestMod::ct_swap(&mut a, &mut b, 1);
        assert_eq!(a.value(), 222);
        assert_eq!(b.value(), 111);
    }

    #[test]
    fn test_ct_eq() {
        let a = TestMod::new(1234);
        let b = TestMod::new(1234);
        let c = TestMod::new(5678);

        assert_eq!(a.ct_eq(b), 1);
        assert_eq!(a.ct_eq(c), 0);
    }

    #[test]
    fn test_ct_lt() {
        let a = TestMod::new(100);
        let b = TestMod::new(200);

        assert_eq!(a.ct_lt(b), 1);
        assert_eq!(b.ct_lt(a), 0);
        assert_eq!(a.ct_lt(a), 0);
    }

    #[test]
    fn test_ct_is_zero() {
        assert_eq!(ct_is_zero(0), 1);
        assert_eq!(ct_is_zero(1), 0);
        assert_eq!(ct_is_zero(-1), 0);
        assert_eq!(ct_is_zero(12345), 0);
    }

    // Comprehensive correctness test against variable-time operations
    #[test]
    fn test_ct_operations_comprehensive() {
        // Test all operations with random-looking values
        for i in 0..100 {
            for j in 0..100 {
                let a = TestMod::new(i * 33 + 17);
                let b = TestMod::new(j * 47 + 23);

                // Addition
                assert_eq!(
                    a.ct_add(b).value(),
                    (a + b).value(),
                    "CT add mismatch for {} + {}",
                    a.value(),
                    b.value()
                );

                // Subtraction
                assert_eq!(
                    a.ct_sub(b).value(),
                    (a - b).value(),
                    "CT sub mismatch for {} - {}",
                    a.value(),
                    b.value()
                );

                // Multiplication
                assert_eq!(
                    a.ct_mul(b).value(),
                    (a * b).value(),
                    "CT mul mismatch for {} * {}",
                    a.value(),
                    b.value()
                );
            }
        }
    }
}
