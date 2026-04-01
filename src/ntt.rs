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

impl NTTConstants {
    /// Bit-reverse a 7-bit number (for indices 0..127)
    fn bit_reverse_7(mut x: usize) -> usize {
        let mut result = 0;
        for _ in 0..7 {
            result = (result << 1) | (x & 1);
            x >>= 1;
        }
        result
    }

    /// Compute NTT constants at runtime (could be const fn in future Rust)
    pub fn new() -> Self {
        // ζ = 17 is a primitive 256-th root of unity mod 3329
        // ζ^256 ≡ 1 (mod 3329), ζ^128 ≡ -1 (mod 3329)
        let zeta = KyberCoeff::new(ZETA_PRIMITIVE);  // ζ = 17
        let mut zetas = [KyberCoeff::zero(); KYBER_N];
        let mut zetas_inv = [KyberCoeff::zero(); KYBER_N];

        // Generate twiddle factors following Kyber's pattern
        // Formula: zetas[k] = ζ^brv(k, 7) for k=1..127
        // This matches the Kyber reference implementation pattern

        zetas[0] = KyberCoeff::new(1);  // Index 0 unused

        for k in 1..128 {
            let br_k = Self::bit_reverse_7(k);
            let exp = br_k as u64;
            zetas[k] = zeta.pow(exp);
        }

        // Inverse NTT: Use the SAME zetas as forward
        // They will be accessed in reverse order (k=127 down to 1)
        for i in 0..128 {
            zetas_inv[i] = zetas[i];
        }

        // For basemul: need ζ^(2·br(i)+1) for i=0..127 (128 pairs total!)
        // Store at indices 128..255
        for i in 0..128 {
            let br_i = Self::bit_reverse_7(i);
            let exp = (2 * br_i + 1) as u64;
            zetas[128 + i] = zeta.pow(exp);
        }

        // Fill remaining (only index 255 now)
        zetas_inv[255] = KyberCoeff::zero();

        // Compute n^(-1) mod q for INTT scaling
        // For Kyber's modified NTT with 7 layers, we actually process 128 pairs
        // So we need 128^(-1) = 3303, not 256^(-1)
        let n_inv = KyberCoeff::new(128)
            .inverse()
            .expect("128 must be invertible mod q");

        Self {
            zetas,
            zetas_inv,
            n_inv,
        }
    }
}

// Lazy static initialization for NTT constants
use std::sync::OnceLock;
static NTT_CONSTANTS: OnceLock<NTTConstants> = OnceLock::new();

fn get_ntt_constants() -> &'static NTTConstants {
    NTT_CONSTANTS.get_or_init(NTTConstants::new)
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
    /// Implements Kyber's modified NTT for negacyclic convolution
    /// Time complexity: O(n log n)
    pub fn ntt(&self) -> Self {
        let constants = get_ntt_constants();
        let mut r = self.coeffs;
        let mut k = 1;  // Twiddle factor index (skipping zetas[0])
        let mut len = 128;  // Start with largest butterflies

        // Cooley-Tukey: 7 layers for n=256
        while len >= 2 {
            let mut start = 0;
            while start < KYBER_N {
                let zeta = constants.zetas[k];
                k += 1;

                // Butterfly operations for this block
                for j in start..(start + len) {
                    let t = zeta * r[j + len];
                    r[j + len] = r[j] - t;
                    r[j] = r[j] + t;
                }

                start += 2 * len;
            }
            len /= 2;
        }

        Self { coeffs: r }
    }

    /// Inverse NTT: evaluation → coefficient representation
    /// Time complexity: O(n log n)
    pub fn intt(&self) -> Self {
        let constants = get_ntt_constants();
        let mut r = self.coeffs;
        let mut k = 127;  // Start from index 127, counting DOWN (like Kyber reference)
        let mut len = 2;  // Start with smallest butterflies

        // Gentleman-Sande: 7 layers for n=256, opposite direction from forward
        while len <= 128 {
            let mut start = 0;
            while start < KYBER_N {
                // Use the SAME zetas array as forward, accessed backwards
                let zeta = constants.zetas[k];
                // Decrement AFTER reading (like k-- in C)
                if k > 0 { k -= 1; }

                // Inverse butterfly - match C reference EXACTLY:
                // t = r[j];
                // r[j] = barrett_reduce(t + r[j + len]);
                // r[j + len] = r[j + len] - t;
                // r[j + len] = fqmul(zeta, r[j + len]);
                for j in start..(start + len) {
                    let t = r[j];
                    r[j] = t + r[j + len];
                    let diff = r[j + len] - t;  // Calculate separately to be explicit
                    r[j + len] = zeta * diff;
                }

                start += 2 * len;
            }
            len *= 2;
        }

        // Scale by n^(-1) = 128^(-1) mod 3329
        for coeff in &mut r {
            *coeff = *coeff * constants.n_inv;
        }

        Self { coeffs: r }
    }

    /// Multiply two polynomials using NTT
    /// This is the main optimization: O(n log n) instead of O(n²)
    pub fn mul_ntt(&self, other: &Self) -> Self {
        let constants = get_ntt_constants();

        // Transform both polynomials to NTT domain
        let self_ntt = self.ntt();
        let other_ntt = other.ntt();

        // "Pointwise" multiplication in NTT domain
        // Actually multiplies pairs as polynomials mod (x² - ζ^(2·br(i)+1))
        // This is the "basemul" operation from Kyber
        let mut product_ntt = [KyberCoeff::zero(); KYBER_N];

        // Process in pairs (128 iterations, each handling 2 coefficients)
        for i in (0..KYBER_N).step_by(2) {
            let zeta = constants.zetas[128 + i / 2];  // ζ^(2·br(i/2)+1) stored at 128+

            // Basemul: multiply two degree-1 polynomials mod (x² - zeta)
            // (a0 + a1·x) * (b0 + b1·x) mod (x² - zeta)
            // = a0·b0 + zeta·a1·b1 + (a0·b1 + a1·b0)·x
            let a0 = self_ntt.coeffs[i];
            let a1 = self_ntt.coeffs[i + 1];
            let b0 = other_ntt.coeffs[i];
            let b1 = other_ntt.coeffs[i + 1];

            product_ntt[i] = a0 * b0 + zeta * a1 * b1;
            product_ntt[i + 1] = a0 * b1 + a1 * b0;
        }

        // Transform back to coefficient representation
        Self { coeffs: product_ntt }.intt()
    }

    /// Add two polynomials (works in any representation)
    pub fn add(&self, other: &Self) -> Self {
        let mut result = [KyberCoeff::zero(); KYBER_N];
        for i in 0..KYBER_N {
            result[i] = self.coeffs[i] + other.coeffs[i];
        }
        Self { coeffs: result }
    }

    /// Subtract two polynomials (works in any representation)
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = [KyberCoeff::zero(); KYBER_N];
        for i in 0..KYBER_N {
            result[i] = self.coeffs[i] - other.coeffs[i];
        }
        Self { coeffs: result }
    }

    /// Schoolbook multiplication (for comparison)
    pub fn mul_schoolbook(&self, other: &Self) -> Self {
        let mut temp = [KyberCoeff::zero(); 2 * KYBER_N];

        // Schoolbook multiplication
        for i in 0..KYBER_N {
            for j in 0..KYBER_N {
                temp[i + j] = temp[i + j] + self.coeffs[i] * other.coeffs[j];
            }
        }

        // Reduce modulo (x^n + 1): x^n ≡ -1
        let mut result = [KyberCoeff::zero(); KYBER_N];
        for i in 0..KYBER_N {
            result[i] = temp[i] - temp[i + KYBER_N];
        }

        Self { coeffs: result }
    }

    // ========================================================================
    // CONSTANT-TIME OPERATIONS (for timing-attack resistance)
    // ========================================================================

    /// Constant-time forward NTT
    ///
    /// Uses constant-time ModN operations to prevent timing attacks when
    /// operating on secret polynomial coefficients.
    ///
    /// # Security
    ///
    /// All ModN operations use Barrett reduction and branchless conditionals
    /// to ensure execution time is independent of input values.
    ///
    /// # Performance
    ///
    /// Expected overhead: ~1x (essentially identical to variable-time version)
    pub fn ct_ntt(&self) -> Self {
        use crate::modn_ct::ConstantTimeOps;

        let constants = get_ntt_constants();
        let mut r = self.coeffs;
        let mut k = 1;
        let mut len = 128;

        // Cooley-Tukey: 7 layers for n=256
        while len >= 2 {
            let mut start = 0;
            while start < KYBER_N {
                let zeta = constants.zetas[k];
                k += 1;

                // Constant-time butterfly operations
                for j in start..(start + len) {
                    let t = zeta.ct_mul(r[j + len]);
                    r[j + len] = r[j].ct_sub(t);
                    r[j] = r[j].ct_add(t);
                }

                start += 2 * len;
            }
            len /= 2;
        }

        Self { coeffs: r }
    }

    /// Constant-time inverse NTT
    ///
    /// Uses constant-time ModN operations to prevent timing attacks.
    pub fn ct_intt(&self) -> Self {
        use crate::modn_ct::ConstantTimeOps;

        let constants = get_ntt_constants();
        let mut r = self.coeffs;
        let mut k = 127;
        let mut len = 2;

        // Gentleman-Sande: 7 layers for n=256, opposite direction from forward
        while len <= 128 {
            let mut start = 0;
            while start < KYBER_N {
                let zeta = constants.zetas[k];
                if k > 0 { k -= 1; }

                // Constant-time inverse butterfly
                for j in start..(start + len) {
                    let t = r[j];
                    r[j] = t.ct_add(r[j + len]);
                    let diff = r[j + len].ct_sub(t);
                    r[j + len] = zeta.ct_mul(diff);
                }

                start += 2 * len;
            }
            len *= 2;
        }

        // Constant-time scaling by n^(-1)
        for coeff in &mut r {
            *coeff = coeff.ct_mul(constants.n_inv);
        }

        Self { coeffs: r }
    }

    /// Constant-time polynomial multiplication using NTT
    ///
    /// Complete timing-attack resistant polynomial multiplication.
    /// Use this when operating on secret polynomials.
    ///
    /// # Security
    ///
    /// All operations (NTT, basemul, INTT) use constant-time implementations.
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
        use crate::modn_ct::ConstantTimeOps;

        let constants = get_ntt_constants();

        // Constant-time forward NTT for both polynomials
        let self_ntt = self.ct_ntt();
        let other_ntt = other.ct_ntt();

        // Constant-time basemul
        let mut product_ntt = [KyberCoeff::zero(); KYBER_N];

        for i in (0..KYBER_N).step_by(2) {
            let zeta = constants.zetas[128 + i / 2];

            let a0 = self_ntt.coeffs[i];
            let a1 = self_ntt.coeffs[i + 1];
            let b0 = other_ntt.coeffs[i];
            let b1 = other_ntt.coeffs[i + 1];

            // Constant-time basemul formula
            product_ntt[i] = a0.ct_mul(b0).ct_add(zeta.ct_mul(a1).ct_mul(b1));
            product_ntt[i + 1] = a0.ct_mul(b1).ct_add(a1.ct_mul(b0));
        }

        let product_poly = Self { coeffs: product_ntt };

        // Constant-time inverse NTT
        product_poly.ct_intt()
    }

    /// Constant-time polynomial addition
    pub fn ct_add(&self, other: &Self) -> Self {
        use crate::modn_ct::ConstantTimeOps;

        let mut result = [KyberCoeff::zero(); KYBER_N];
        for i in 0..KYBER_N {
            result[i] = self.coeffs[i].ct_add(other.coeffs[i]);
        }
        Self { coeffs: result }
    }

    /// Constant-time polynomial subtraction
    pub fn ct_sub(&self, other: &Self) -> Self {
        use crate::modn_ct::ConstantTimeOps;

        let mut result = [KyberCoeff::zero(); KYBER_N];
        for i in 0..KYBER_N {
            result[i] = self.coeffs[i].ct_sub(other.coeffs[i]);
        }
        Self { coeffs: result }
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
        let constants = get_ntt_constants();

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
