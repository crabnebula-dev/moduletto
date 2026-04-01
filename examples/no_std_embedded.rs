//! no_std Example for Moduletto (i64)
//!
//! This example demonstrates using moduletto in a no_std environment,
//! suitable for embedded systems, WebAssembly, and resource-constrained environments.
//!
//! Build with: cargo build --example no_std_embedded --no-default-features --release
//! Test with: cargo test --example no_std_embedded --no-default-features

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

use moduletto::{ModN, ConstantTimeOps};

#[cfg(not(feature = "std"))]
use core::panic::PanicInfo;

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// Demonstration function that works in no_std environment
pub fn no_std_demo() -> i64 {
    // Example: Kyber-512 modular arithmetic
    type KyberMod = ModN<3329>;

    // Constant-time operations (side-channel resistant)
    let a = KyberMod::new(1234);
    let b = KyberMod::new(5678);

    let sum = a.ct_add(b);
    let product = a.ct_mul(b);
    let difference = a.ct_sub(b);

    // These operations work without any heap allocation
    // Perfect for embedded systems with limited RAM

    // Example: Modular exponentiation
    let base = KyberMod::new(3);
    let result = base.pow(100);

    // Example: Modular inverse
    let inv_result = if let Some(inv) = a.inverse() {
        a.ct_mul(inv).value() // Should be 1
    } else {
        0
    };

    // Return something to prevent optimization
    sum.value() + product.value() + difference.value() + result.value() + inv_result
}

#[cfg(not(feature = "std"))]
#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8) -> i32 {
    let result = no_std_demo();
    core::hint::black_box(result);
    0
}

#[cfg(feature = "std")]
fn main() {
    let result = no_std_demo();
    println!("no_std_embedded demo result: {}", result);
    println!("All no_std operations completed successfully.");
}

#[cfg(test)]
#[test]
fn test_no_std_compatibility() {
    let result = no_std_demo();
    assert!(result > 0); // Just verify it runs
}
