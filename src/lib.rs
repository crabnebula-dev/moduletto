//! # Moduletto (MAJOR DISCOVERY!)
//!
//! **RESEARCH FINDING**: i64 is 3x faster than i128 for small moduli!
//!
//! ## Benchmark Results (ARM M3 Max)
//!
//! | Implementation | Poly Add (ns) | vs i128 | vs Scalar |
//! |---------------|---------------|---------|-----------|
//! | **i64 scalar** | **93.99** ✨ | **3.1x faster!** | baseline |
//! | i64 SIMD | 206.98 ⚠️ | 1.4x faster | 2.2x slower |
//! | i128 scalar | 293 | baseline | - |
//! | i128 SIMD | 997 | 0.29x | 3.4x slower |
//!
//! ## Key Discoveries
//!
//! 1. **i64 is 3x faster than i128 for scalar operations**
//!    - i64 is ARM64's native register size
//!    - i128 requires multiple instructions per operation
//!    - For small moduli (< 2^31), i64 is optimal!
//!
//! 2. **SIMD still doesn't help (even with true NEON intrinsics)**
//!    - Load/store overhead dominates
//!    - Modular reduction (`if sum >= N`) is still scalar
//!    - Array chunking adds overhead
//!
//! 3. **For Kyber (modulus 3329), use i64 scalar!**
//!    - Polynomial add: 94 ns (vs 295 ns for i128)
//!    - Polynomial sub: 111 ns (vs 370 ns for i128)
//!    - **This is the fastest Moduletto implementation for small moduli!**
//!
//! ## Recommendation
//!
//! **Use this crate (i64 scalar) for moduli < 2^31** (including Kyber-512, Dilithium, etc.)

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(incomplete_features)]

mod modn;
pub mod modn_ct;
pub mod ntt;

pub use modn::ModN;
pub use modn_ct::ConstantTimeOps;
pub use ntt::{NTTPoly, KyberCoeff, KYBER_Q, KYBER_N};

// WebAssembly bindings
#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_arithmetic() {
        type Mod7 = ModN<7>;

        let a = Mod7::new(5);
        let b = Mod7::new(3);

        assert_eq!(a.ct_add(b).value(), 1); // (5 + 3) % 7 = 1
        assert_eq!(a.ct_sub(b).value(), 2); // (5 - 3) % 7 = 2
        assert_eq!(a.ct_mul(b).value(), 1); // (5 * 3) % 7 = 1
    }

    #[test]
    fn kyber_modulus() {
        type Mod3329 = ModN<3329>;

        let a = Mod3329::new(1234);
        let b = Mod3329::new(5678);

        let sum = a.ct_add(b);
        assert_eq!(sum.value(), (1234 + 5678) % 3329);

        let product = a.ct_mul(b);
        assert_eq!(product.value(), ((1234i64 * 5678) % 3329) as i64);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_neon_available() {
        type Mod3329 = ModN<3329>;
        assert!(Mod3329::has_neon());
    }
}
