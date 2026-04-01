// WASM Benchmark example for Moduletto
// Run with: cargo run --example bench_wasm --release --features wasm --target wasm32-unknown-unknown
//
// Note: This can also be compiled to WASM and run in a browser/Node.js environment
// For browser testing, use wasm-pack: wasm-pack build --target web --features wasm

#[cfg(target_arch = "wasm32")]
use moduletto::{ModN, ConstantTimeOps, NTTPoly, KyberCoeff, KYBER_N};

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen::prelude::*;

// For WASM, we'll use a simple timing approach
// In a real WASM environment, you'd use performance.now() from JavaScript

#[cfg(target_arch = "wasm32")]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn run_wasm_benchmarks() {
    let iterations = 100_000; // Reduced for WASM

    type Mod3329 = ModN<3329>;

    // We can't easily do timing in pure WASM without JS interop,
    // but we can still run the operations to verify they work

    // Coefficient creation
    for i in 0..iterations {
        let _ = Mod3329::new(i as i64);
    }

    // Constant-time addition
    let a = Mod3329::new(1234);
    let b = Mod3329::new(5678);

    for _ in 0..iterations {
        let _ = a.ct_add(b);
    }

    // Constant-time subtraction
    for _ in 0..iterations {
        let _ = a.ct_sub(b);
    }

    // Constant-time multiplication
    for _ in 0..iterations {
        let _ = a.ct_mul(b);
    }

    // Polynomial operations
    let poly1 = NTTPoly::zero();
    let poly2 = NTTPoly::zero();

    for _ in 0..(iterations / 10) {
        let _ = poly1.add(&poly2);
    }

    for _ in 0..(iterations / 10) {
        let _ = poly1.sub(&poly2);
    }

    // NTT operations (more expensive)
    for _ in 0..(iterations / 100) {
        let _ = poly1.ct_ntt();
    }

    for _ in 0..(iterations / 100) {
        let ntt = poly1.ct_ntt();
        let _ = ntt.ct_intt();
    }

    // Modular inverse (when applicable)
    for i in 0..(iterations / 10) {
        let value = Mod3329::new((i % 3328) + 1);
        let _ = value.inverse();
    }

    // Modular exponentiation
    for _ in 0..(iterations / 100) {
        let base = Mod3329::new(3);
        let _ = base.pow(100);
    }

    // Kyber-512 polynomial multiplication via NTT
    let mut secret = NTTPoly::zero();
    let mut public = NTTPoly::zero();

    for i in 0..KYBER_N {
        secret.coeffs[i] = KyberCoeff::new((i as i64 * 17 + 42) % 3329);
        public.coeffs[i] = KyberCoeff::new((i as i64 * 23 + 7) % 3329);
    }

    for _ in 0..(iterations / 1000) {
        let _ = secret.ct_mul_ntt(&public);
    }
}

// For native compilation (not WASM), provide a simple benchmark runner
#[cfg(not(target_arch = "wasm32"))]
fn main() {
    println!("This example is designed to run in WASM environments.");
    println!("To compile for WASM, use:");
    println!("  wasm-pack build --target web --features wasm");
    println!("  cargo build --example bench_wasm --release --features wasm --target wasm32-unknown-unknown");
}

// For WASM, export a main that can be called from JS
#[cfg(target_arch = "wasm32")]
fn main() {
    // In WASM, main is not typically used - functions are exported via wasm_bindgen
    run_wasm_benchmarks();
}
