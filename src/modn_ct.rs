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
//! Side-channel resistance is enforced by the [`subtle`] crate, which uses
//! `read_volatile` barriers to prevent the compiler from optimising branchless
//! code back into branches.
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
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

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

impl<const N: i64> ConstantTimeOps<N> for ModN<N> {
    /// Constant-time addition with branchless reduction
    ///
    /// # Implementation
    ///
    /// Uses `subtle::ConditionallySelectable` for the final selection:
    /// ```text
    /// sum = a + b
    /// reduced = sum - N
    /// choice = (sum >= N)     // derived from sign of (N - 1 - sum)
    /// result = select(sum, reduced, choice)
    /// ```
    ///
    /// # Performance
    ///
    /// ~1.5x slower than branching version, but constant-time.
    fn ct_add(self, other: Self) -> Self {
        let sum = self.value() + other.value();
        let reduced = sum - N;

        // sum >= N iff (N - 1 - sum) < 0, i.e. sign bit is set
        // Arithmetic right shift gives -1 (all 1s) if negative, 0 if non-negative
        // We want Choice(1) when sum >= N, i.e. when (N - 1 - sum) is negative
        let needs_reduction = Choice::from(((N - 1 - sum) >> 63) as u8 & 1);

        let result = i64::conditional_select(&sum, &reduced, needs_reduction);
        unsafe { Self::new_unchecked(result) }
    }

    /// Constant-time subtraction with branchless underflow handling
    fn ct_sub(self, other: Self) -> Self {
        let diff = self.value() - other.value();
        let adjusted = diff + N;

        // diff < 0 iff sign bit is set
        let needs_adjustment = Choice::from((diff >> 63) as u8 & 1);

        let result = i64::conditional_select(&diff, &adjusted, needs_adjustment);
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
        let negated = N - self.value();

        // If value == 0, result should be 0; otherwise N - value
        let is_zero = self.value().ct_eq(&0);

        let result = i64::conditional_select(&negated, &0, is_zero);
        unsafe { Self::new_unchecked(result) }
    }

    /// Constant-time conditional selection
    ///
    /// Returns `a` if bit 0 of `choice` is 0, returns `b` if bit 0 is 1.
    /// This operation takes constant time regardless of the choice value.
    fn ct_select(a: Self, b: Self, choice: u8) -> Self {
        let c = Choice::from(choice & 1);
        let result = i64::conditional_select(&a.value(), &b.value(), c);
        unsafe { Self::new_unchecked(result) }
    }

    /// Constant-time conditional swap
    ///
    /// Swaps `a` and `b` if bit 0 of `choice` is 1, using XOR-based swap trick.
    fn ct_swap(a: &mut Self, b: &mut Self, choice: u8) {
        let c = Choice::from(choice & 1);
        let mut va = a.value();
        let mut vb = b.value();
        i64::conditional_swap(&mut va, &mut vb, c);
        *a = unsafe { Self::new_unchecked(va) };
        *b = unsafe { Self::new_unchecked(vb) };
    }

    /// Constant-time equality check
    ///
    /// Returns 1 if equal, 0 otherwise (as u8).
    /// Avoids bool to prevent compiler from introducing branches.
    fn ct_eq(self, other: Self) -> u8 {
        self.value().ct_eq(&other.value()).unwrap_u8()
    }

    /// Constant-time less-than comparison
    fn ct_lt(self, other: Self) -> u8 {
        // For values in [0, N) where N < 2^62, (a - b) fits in i64
        // and the sign bit correctly indicates a < b.
        let diff = self.value() - other.value();
        // Use subtle's barrier to prevent the compiler from seeing the sign test
        let diff = subtle::BlackBox::new(diff).get();
        ((diff >> 63) & 1) as u8
    }
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
    let r = x - q * N;
    let reduced = r - N;

    // Constant-time conditional subtraction
    // If r >= N (i.e., reduced >= 0), use reduced; otherwise use r
    let needs_reduction = Choice::from(((!(reduced >> 63)) & 1) as u8);
    let result = i64::conditional_select(&r, &reduced, needs_reduction);

    // result is now guaranteed to be in [0, N)
    unsafe { ModN::new_unchecked(result) }
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
        // SAFETY: ModN has #[repr(transparent)] over i64
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
