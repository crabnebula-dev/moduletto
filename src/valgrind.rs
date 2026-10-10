//! Valgrind memcheck client requests for constant-time checking.
//!
//! The ctgrind technique: mark secret inputs as *undefined* memory, run the
//! code under `valgrind --tool=memcheck`, and let memcheck report every
//! conditional jump or memory address that depends on them. Values that are
//! derived from secrets but public by design (the matrix seed ρ, the
//! encapsulation key, the ciphertext) are *declassified* so that the
//! variable-time code that legitimately consumes them does not report.
//!
//! Enabled by the `valgrind-ct` feature and effective only on x86-64 Linux,
//! where the client-request instruction sequence below is defined; elsewhere
//! every function is a no-op and [`running`] returns `false`. The library
//! itself never calls these except through the feature-gated hooks in
//! [`crate::kem`]. `examples/valgrind_ct.rs` is the harness.
//!
//! Memcheck does not model arithmetic timing: it cannot see a variable-time
//! multiply or divide. It catches secret-dependent control flow and memory
//! access, which is what the code shape is meant to exclude.

#![allow(dead_code)]

const MAKE_MEM_UNDEFINED: u64 = 0x4D43_0001; // ('M' << 24 | 'C' << 16) + 1
const MAKE_MEM_DEFINED: u64 = 0x4D43_0002;
const RUNNING_ON_VALGRIND: u64 = 0x1001;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[inline(never)]
fn client_request(default: u64, args: &[u64; 6]) -> u64 {
    let mut result: u64 = default;
    // The magic preamble from valgrind.h (amd64): four rotates of %rdi that
    // compose to the identity, then `xchg %rbx,%rbx`. A real CPU executes
    // nothing of consequence; memcheck recognises the sequence and performs
    // the request described by the array in %rax, returning in %rdx.
    // SAFETY: the instructions touch only rdi (restored by the rotations) and
    // leave rbx unchanged; the args array outlives the call.
    unsafe {
        core::arch::asm!(
            "rol rdi, 3",
            "rol rdi, 13",
            "rol rdi, 61",
            "rol rdi, 51",
            "xchg rbx, rbx",
            in("rax") args.as_ptr(),
            inout("rdx") result,
            out("rdi") _,
            options(nostack, readonly, preserves_flags)
        );
    }
    result
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
#[inline(always)]
fn client_request(default: u64, _args: &[u64; 6]) -> u64 {
    default
}

/// True when the process runs under Valgrind.
pub fn running() -> bool {
    client_request(0, &[RUNNING_ON_VALGRIND, 0, 0, 0, 0, 0]) != 0
}

/// Mark `x` as secret: memcheck treats its bytes as undefined from here on.
pub fn poison<T: ?Sized>(x: &mut T) {
    let addr = x as *mut T as *mut u8 as u64;
    let len = core::mem::size_of_val(x) as u64;
    client_request(0, &[MAKE_MEM_UNDEFINED, addr, len, 0, 0, 0]);
}

/// Mark `x` as public: memcheck treats its bytes as defined from here on.
pub fn declassify<T: ?Sized>(x: &T) {
    let addr = x as *const T as *const u8 as u64;
    let len = core::mem::size_of_val(x) as u64;
    client_request(0, &[MAKE_MEM_DEFINED, addr, len, 0, 0, 0]);
}
