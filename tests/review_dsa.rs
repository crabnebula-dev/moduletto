//! Independent review (side channels and memory hygiene) of `src/dsa.rs`.
//!
//! The test looks for secret residue on the thread's stack after an
//! ML-DSA-65 signing call returns. It runs in a fresh thread, so the stack
//! starts as fresh zeroed pages, and the private key lives on the heap. After
//! the call, the dead stack region below the caller is read back and
//! searched for the signing seed K.
//!
//! Reading dead stack below the stack pointer is outside the Rust abstract
//! machine. It is done with volatile raw reads inside the mapped 16 MiB
//! thread stack, which works on every tier-1 target.
//!
//! It is a regression test. It once failed in the release profile, where LTO
//! inlined the signing core into the entry point's own frame. That frame
//! lay above the buffer of `scrub_stack`, so the scrub never reached it. The
//! signing core is now kept out of line, below the scrubbing frame.

use moduletto::dsa::ml_dsa_65;

/// How far below the anchor to search, inside a 16 MiB thread stack.
const WINDOW: usize = 4 * 1024 * 1024;
const STACK: usize = 16 * 1024 * 1024;

/// Every depth (bytes below `anchor`) at which `needle` appears in the dead
/// stack region `[anchor - WINDOW, anchor)`.
#[inline(never)]
fn find_below(anchor: usize, needle: &[u8]) -> Vec<usize> {
    let lo = anchor - WINDOW;
    let mut hay = vec![0u8; WINDOW];
    for (i, b) in hay.iter_mut().enumerate() {
        // SAFETY: inside this thread's mapped stack (16 MiB, anchor near the
        // top); volatile so that the read is not elided.
        *b = unsafe { core::ptr::read_volatile((lo + i) as *const u8) };
    }
    let mut hits = Vec::new();
    for i in 0..=hay.len() - needle.len() {
        if &hay[i..i + needle.len()] == needle {
            hits.push(anchor - (lo + i));
        }
    }
    hits
}

#[inline(never)]
fn sign_on_heap(sk: &[u8]) -> Box<[u8; ml_dsa_65::SIG_BYTES]> {
    Box::new(ml_dsa_65::sign(sk, b"review message", b"", &[0u8; 32]).unwrap())
}

fn fresh_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

/// After `sign` returns, no copy of the 32-byte signing seed K (sk[32..64])
/// may remain on the stack below the caller. The `dsa` module documentation
/// promises that the decoded key wipes itself and that `scrub_stack`
/// overwrites the stack region the operation used. FIPS 204 section 3.6.3
/// asks for intermediate values to be destroyed. K with one deterministic
/// signature gives ρ″, hence y, hence c·s₁ = z − y and s₁.
#[test]
fn review_sign_leaves_no_copy_of_k_on_stack() {
    // Generate the key in another thread so that its residue is not here.
    let sk = fresh_thread(|| ml_dsa_65::keygen_internal(&[0x3c; 32]).1.to_vec());
    let k = sk[32..64].to_vec();
    let hits = fresh_thread(move || {
        let anchor = 0u8;
        let anchor = core::hint::black_box(&anchor) as *const u8 as usize;
        let sig = sign_on_heap(&sk);
        core::hint::black_box(&sig);
        find_below(anchor - 256, &k)
    });
    assert!(
        hits.is_empty(),
        "K found on the stack after sign, at these depths below the caller: {hits:?}"
    );
}
