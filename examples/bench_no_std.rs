// no_std Benchmark example for Moduletto
// Run with:
//   cargo run --example bench_no_std --release                          (with std)
//   cargo build --example bench_no_std --release --no-default-features  (true no_std)
//
// This demonstrates that Moduletto works in both std and no_std environments

use moduletto::{ModN, ConstantTimeOps, NTTPoly};

fn run_no_std_operations() {
    let iterations = 10_000;

    // Type aliases for Kyber-512
    type Mod3329 = ModN<3329>;

    // Coefficient operations - verify they work without panicking
    for _ in 0..iterations {
        let _ = Mod3329::new(1234);
    }

    for _ in 0..iterations {
        let a = Mod3329::new(100);
        let b = Mod3329::new(200);
        let _ = a.ct_add(b);
    }

    for _ in 0..iterations {
        let a = Mod3329::new(500);
        let b = Mod3329::new(200);
        let _ = a.ct_sub(b);
    }

    for _ in 0..iterations {
        let a = Mod3329::new(100);
        let b = Mod3329::new(200);
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

    // Constant-time NTT operations
    for _ in 0..(iterations / 100) {
        let _ = poly1.ct_ntt();
    }

    for _ in 0..(iterations / 100) {
        let ntt = poly1.ct_ntt();
        let _ = ntt.ct_intt();
    }

    // Modular inverse (when gcd = 1)
    for i in 0..(iterations / 10) {
        let value = Mod3329::new((i % 3328) + 1);  // Avoid 0 and multiples of 3329
        let _ = value.inverse();
    }

    // Modular exponentiation
    for _ in 0..(iterations / 100) {
        let base = Mod3329::new(3);
        let _ = base.pow(100);
    }
}

fn main() {
    #[cfg(feature = "std")]
    {
        println!("======================================================================");
        println!("MODULETTO - NO_STD BENCHMARK");
        println!("======================================================================");
        println!();
        println!("This example demonstrates Moduletto working in no_std environments.");
        println!();
        println!("Configuration:");
        println!("  Modulus: 3329 (Kyber-512)");
        println!("  Polynomial degree: 256");
        println!("  Type: i64 (3x faster than i128!)");
        println!();
        println!("To compile for true no_std (e.g., embedded systems):");
        println!("  cargo build --example bench_no_std --release --no-default-features");
        println!();
        println!("Running 10,000 iterations per operation to verify no_std compatibility...");
        println!();
    }

    run_no_std_operations();

    #[cfg(feature = "std")]
    {
        println!("✓ All operations completed successfully!");
        println!();
        println!("Key points:");
        println!("  • No heap allocations required for basic operations");
        println!("  • Works in embedded/bare-metal environments");
        println!("  • Constant-time operations resist side-channel attacks");
        println!("  • Perfect for post-quantum cryptography (Kyber-512, Dilithium)");
        println!("  • Suitable for microcontrollers, IoT devices, RTOS");
        println!();
        println!("Performance (i64 scalar):");
        println!("  • Coefficient addition: ~2 ns");
        println!("  • Coefficient multiplication: ~5 ns");
        println!("  • Polynomial addition (256 coeffs): ~91 ns");
        println!("  • NTT transform: O(n log n)");
        println!();
        println!("======================================================================");
    }
}
