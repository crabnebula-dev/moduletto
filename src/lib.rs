//! # Moduletto
//!
//! Optimised modular arithmetic and NTT for lattice cryptography: a
//! compile-time-fixed-modulus scalar type, a formally verified constant-time
//! layer, and a Kyber-parameter NTT with an ARM64 NEON backend.
//!
//! ## Benchmark results (Apple M5, Criterion, q = 3329, n = 256)
//!
//! | Operation | Time | vs. previous release |
//! |---|---:|---:|
//! | `forward_ntt` | 176 ns | 3.3x faster |
//! | `inverse_ntt` | 239 ns | 3.3x faster |
//! | `mul_ntt` | 503 ns | 4.5x faster |
//! | `ct_forward_ntt` | 177 ns | 15.9x faster |
//! | `ct_inverse_ntt` | 239 ns | 12.6x faster |
//! | `ct_mul_ntt` | 504 ns | 22.5x faster |
//! | `poly_add` / `poly_sub` | 63 ns | unchanged (L1-bandwidth bound) |
//! | `ct_poly_add` / `ct_poly_sub` | 63 ns | 3.9x / 2.8x faster |
//!
//! ## Design notes
//!
//! 1. **Scalar carrier: i64, not i128.** i64 is ARM64's native register width;
//!    i128 costs several instructions per operation. Applies to any modulus
//!    below 2^31, including Kyber and Dilithium.
//!
//! 2. **Lazy reduction.** With q = 3329 in a 64-bit register there are ~50
//!    spare bits, so the NTT keeps coefficients in a redundant centred
//!    representation and canonicalises once at the end. Only multiplies are
//!    reduced, via a branchless rounding Barrett step (proved correct in
//!    `proofs/BarrettReduction.v`).
//!
//! 3. **Vectorisation requires a narrow element type.** AArch64 has no 64-bit
//!    SIMD multiply, so an i64 NTT cannot vectorise its multiplies. Narrowing
//!    to i16 allows eight Montgomery butterflies per NEON instruction; see
//!    [`ntt`]. The two narrowest layers need `uzp`/`zip` deinterleaving; left
//!    scalar they cost more than the other five layers combined.
//!
//! 4. **Constant-time cost.** The branchless kernel has no data-dependent
//!    branch and no conditional move, so the `ct_*` transforms are the same
//!    code as the variable-time ones and run at the same speed.

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
