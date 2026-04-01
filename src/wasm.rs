//! WebAssembly bindings for Moduletto
//!
//! This module provides JavaScript-friendly wrappers for modular arithmetic operations
//! with the Kyber-512 modulus (3329).

use wasm_bindgen::prelude::*;
use crate::{ModN, ConstantTimeOps, NTTPoly, KyberCoeff, KYBER_Q, KYBER_N};

// Type alias for Kyber-512 modulus
type Mod3329 = ModN<3329>;

/// Get the Kyber-512 modulus value
#[wasm_bindgen]
pub fn kyber_modulus() -> i32 {
    KYBER_Q as i32
}

/// Get the polynomial degree for Kyber-512
#[wasm_bindgen]
pub fn kyber_degree() -> usize {
    KYBER_N
}

/// Modular addition: (a + b) mod 3329
#[wasm_bindgen]
pub fn mod_add(a: i32, b: i32) -> i32 {
    let x = Mod3329::new(a as i64);
    let y = Mod3329::new(b as i64);
    x.ct_add(y).value() as i32
}

/// Modular subtraction: (a - b) mod 3329
#[wasm_bindgen]
pub fn mod_sub(a: i32, b: i32) -> i32 {
    let x = Mod3329::new(a as i64);
    let y = Mod3329::new(b as i64);
    x.ct_sub(y).value() as i32
}

/// Modular multiplication: (a * b) mod 3329
#[wasm_bindgen]
pub fn mod_mul(a: i32, b: i32) -> i32 {
    let x = Mod3329::new(a as i64);
    let y = Mod3329::new(b as i64);
    x.ct_mul(y).value() as i32
}

/// Modular negation: (-a) mod 3329
#[wasm_bindgen]
pub fn mod_neg(a: i32) -> i32 {
    let x = Mod3329::new(a as i64);
    (-x).value() as i32
}

/// Modular inverse: a^(-1) mod 3329
/// Returns -1 if inverse doesn't exist
#[wasm_bindgen]
pub fn mod_inverse(a: i32) -> i32 {
    let x = Mod3329::new(a as i64);
    match x.inverse() {
        Some(inv) => inv.value() as i32,
        None => -1,
    }
}

/// Modular exponentiation: a^exp mod 3329
#[wasm_bindgen]
pub fn mod_pow(a: i32, exp: u32) -> i32 {
    let x = Mod3329::new(a as i64);
    x.pow(exp as u64).value() as i32
}

/// Check if a value is zero modulo 3329
#[wasm_bindgen]
pub fn is_zero(a: i32) -> bool {
    let x = Mod3329::new(a as i64);
    x.is_zero()
}

/// Check if a value is one modulo 3329
#[wasm_bindgen]
pub fn is_one(a: i32) -> bool {
    let x = Mod3329::new(a as i64);
    x.is_one()
}

/// Create a zero polynomial
#[wasm_bindgen]
pub fn poly_zero() -> Vec<i32> {
    let poly = NTTPoly::zero();
    poly.coeffs.iter().map(|c| c.value() as i32).collect()
}

/// Add two polynomials (coefficient arrays)
/// Both arrays must have length 256
#[wasm_bindgen]
pub fn poly_add(a: &[i32], b: &[i32]) -> Result<Vec<i32>, JsValue> {
    if a.len() != KYBER_N || b.len() != KYBER_N {
        return Err(JsValue::from_str(&format!("Polynomials must have {} coefficients", KYBER_N)));
    }

    let mut poly_a = NTTPoly::zero();
    let mut poly_b = NTTPoly::zero();

    for i in 0..KYBER_N {
        poly_a.coeffs[i] = KyberCoeff::new(a[i] as i64);
        poly_b.coeffs[i] = KyberCoeff::new(b[i] as i64);
    }

    let result = poly_a.add(&poly_b);
    Ok(result.coeffs.iter().map(|c| c.value() as i32).collect())
}

/// Subtract two polynomials (coefficient arrays)
/// Both arrays must have length 256
#[wasm_bindgen]
pub fn poly_sub(a: &[i32], b: &[i32]) -> Result<Vec<i32>, JsValue> {
    if a.len() != KYBER_N || b.len() != KYBER_N {
        return Err(JsValue::from_str(&format!("Polynomials must have {} coefficients", KYBER_N)));
    }

    let mut poly_a = NTTPoly::zero();
    let mut poly_b = NTTPoly::zero();

    for i in 0..KYBER_N {
        poly_a.coeffs[i] = KyberCoeff::new(a[i] as i64);
        poly_b.coeffs[i] = KyberCoeff::new(b[i] as i64);
    }

    let result = poly_a.sub(&poly_b);
    Ok(result.coeffs.iter().map(|c| c.value() as i32).collect())
}

/// Perform NTT (Number Theoretic Transform) on a polynomial
/// Input array must have length 256
#[wasm_bindgen]
pub fn poly_ntt(coeffs: &[i32]) -> Result<Vec<i32>, JsValue> {
    if coeffs.len() != KYBER_N {
        return Err(JsValue::from_str(&format!("Polynomial must have {} coefficients", KYBER_N)));
    }

    let mut poly = NTTPoly::zero();
    for i in 0..KYBER_N {
        poly.coeffs[i] = KyberCoeff::new(coeffs[i] as i64);
    }

    let ntt_poly = poly.ct_ntt();
    Ok(ntt_poly.coeffs.iter().map(|c| c.value() as i32).collect())
}

/// Perform inverse NTT on a polynomial
/// Input array must have length 256
#[wasm_bindgen]
pub fn poly_intt(coeffs: &[i32]) -> Result<Vec<i32>, JsValue> {
    if coeffs.len() != KYBER_N {
        return Err(JsValue::from_str(&format!("Polynomial must have {} coefficients", KYBER_N)));
    }

    let mut poly = NTTPoly::zero();
    for i in 0..KYBER_N {
        poly.coeffs[i] = KyberCoeff::new(coeffs[i] as i64);
    }

    let intt_poly = poly.ct_intt();
    Ok(intt_poly.coeffs.iter().map(|c| c.value() as i32).collect())
}

/// Multiply two polynomials using NTT (fast O(n log n))
/// Both arrays must have length 256
#[wasm_bindgen]
pub fn poly_mul_ntt(a: &[i32], b: &[i32]) -> Result<Vec<i32>, JsValue> {
    if a.len() != KYBER_N || b.len() != KYBER_N {
        return Err(JsValue::from_str(&format!("Polynomials must have {} coefficients", KYBER_N)));
    }

    let mut poly_a = NTTPoly::zero();
    let mut poly_b = NTTPoly::zero();

    for i in 0..KYBER_N {
        poly_a.coeffs[i] = KyberCoeff::new(a[i] as i64);
        poly_b.coeffs[i] = KyberCoeff::new(b[i] as i64);
    }

    let result = poly_a.ct_mul_ntt(&poly_b);
    Ok(result.coeffs.iter().map(|c| c.value() as i32).collect())
}

/// Get library version info
#[wasm_bindgen]
pub fn version_info() -> String {
    format!("Moduletto v{} - i64 modular arithmetic (3x faster than i128!)",
            env!("CARGO_PKG_VERSION"))
}

/// Run a performance test with the specified number of iterations
/// Returns the time in milliseconds
#[wasm_bindgen]
pub fn perf_test_add(iterations: u32) -> f64 {
    let mut a = Mod3329::new(1234);
    let b = Mod3329::new(5678);

    let start = web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or(0.0);

    // Accumulate to prevent optimization
    for _ in 0..iterations {
        a = a.ct_add(b);
    }

    let end = web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or(0.0);

    // Use the result to prevent dead code elimination
    if a.is_zero() {
        return 0.0;
    }

    end - start
}

/// Run a multiplication performance test
#[wasm_bindgen]
pub fn perf_test_mul(iterations: u32) -> f64 {
    let mut a = Mod3329::new(1234);
    let b = Mod3329::new(5678);

    let start = web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or(0.0);

    // Accumulate to prevent optimization
    for _ in 0..iterations {
        a = a.ct_mul(b);
    }

    let end = web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or(0.0);

    // Use the result to prevent dead code elimination
    if a.is_zero() {
        return 0.0;
    }

    end - start
}
