//! Data Independent Timing (AArch64 `PSTATE.DIT`).
//!
//! Branch-free code is constant-time only if the instructions it runs take
//! the same time for every operand. On AArch64 that is not guaranteed by
//! default: the architecture lists the instructions whose timing becomes
//! data-independent once `PSTATE.DIT` is set (FEAT_DIT, ARMv8.4), and
//! measurements on Apple M5 show the difference. A dependent chain of 64-bit
//! multiplies takes about 25% longer on all-zero operands than on random
//! ones with DIT clear, and the same time for every operand class with DIT
//! set (`examples/ct_dudect.rs`, `hw_mul64_*`). On Apple M3 and later, DIT
//! also disables the data-memory-dependent prefetcher (GoFetch).
//!
//! The ML-KEM entry points in [`crate::kem`] run under [`with_dit`]. Code that
//! uses the `ct_*` primitives of [`crate::modn_ct`] and [`crate::ntt`] on
//! secrets should wrap the whole computation in [`with_dit`] as well; the
//! per-operation cost of toggling the bit would dwarf the operations.
//!
//! On other architectures [`with_dit`] just calls the closure. x86-64 has no
//! user-settable equivalent (Intel's DOITM is a kernel-controlled MSR).

#[cfg(target_arch = "aarch64")]
mod imp {
    /// Bit 24 of the DIT system register.
    pub const BIT: u64 = 1 << 24;

    /// # Safety
    /// The core must implement FEAT_DIT; otherwise the instruction is undefined.
    #[inline(always)]
    pub unsafe fn read() -> u64 {
        let v: u64;
        core::arch::asm!("mrs {0}, DIT", out(reg) v, options(nomem, nostack, preserves_flags));
        v
    }

    /// # Safety
    /// As for [`read`].
    #[inline(always)]
    pub unsafe fn write(v: u64) {
        core::arch::asm!("msr DIT, {0}", in(reg) v, options(nomem, nostack, preserves_flags));
    }
}

/// Whether this core implements FEAT_DIT. Detected once and cached. Without
/// `std` there is no safe way to detect it, so this returns `false` and
/// [`with_dit`] runs the closure unchanged; callers who know their core can
/// use [`with_dit_unchecked`].
#[cfg(all(target_arch = "aarch64", feature = "std"))]
pub fn available() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    static CACHE: AtomicU8 = AtomicU8::new(0);
    match CACHE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let ok = std::arch::is_aarch64_feature_detected!("dit");
            CACHE.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
            ok
        }
    }
}

/// Whether this core implements FEAT_DIT (always `false` here: not AArch64,
/// or no `std` to detect it with).
#[cfg(not(all(target_arch = "aarch64", feature = "std")))]
pub fn available() -> bool {
    false
}

/// Run `f` with `PSTATE.DIT` set, restoring the previous state afterwards.
///
/// A plain call to `f` when the core has no FEAT_DIT, when it cannot be
/// detected (no `std`), or off AArch64. If `f` panics the bit stays set,
/// which is harmless.
#[inline]
pub fn with_dit<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(all(target_arch = "aarch64", feature = "std"))]
    if available() {
        // SAFETY: FEAT_DIT confirmed by `available`.
        return unsafe { with_dit_unchecked(f) };
    }
    f()
}

/// Run `f` with `PSTATE.DIT` set, without checking for FEAT_DIT.
///
/// # Safety
/// The core must implement FEAT_DIT (every Apple Silicon core does; on other
/// AArch64 cores check ID_AA64PFR0_EL1.DIT or the OS's feature report).
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn with_dit_unchecked<R>(f: impl FnOnce() -> R) -> R {
    let prev = imp::read();
    imp::write(prev | imp::BIT);
    let r = f();
    imp::write(prev);
    r
}

/// Whether `PSTATE.DIT` is currently set. `false` where it cannot be read.
pub fn is_set() -> bool {
    #[cfg(all(target_arch = "aarch64", feature = "std"))]
    if available() {
        // SAFETY: FEAT_DIT confirmed by `available`.
        return unsafe { imp::read() } & imp::BIT != 0;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_previous_state() {
        let before = is_set();
        let inside = with_dit(|| is_set());
        assert_eq!(is_set(), before);
        if available() {
            assert!(inside, "DIT not set inside with_dit on a core that has it");
        } else {
            assert!(!inside);
        }
    }
}
