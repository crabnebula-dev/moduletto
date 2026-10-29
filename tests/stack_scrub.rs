//! Stack-paint regression tests for the stack scrub of the ML-DSA and
//! ML-KEM entry points.
//!
//! Each test runs in a fresh thread. It first paints a large region of the
//! stack with a marker byte, then calls one entry point, then reads the dead
//! stack below the caller back. Two properties are checked:
//!
//! * no copy of a secret key component (K, packed s₁ or t₀ for ML-DSA; the
//!   packed ŝ or z for ML-KEM) is left anywhere below the caller;
//! * for ML-DSA, nothing below the scrub buffer was touched, so the scrub
//!   covers the deepest frame of the operation.
//!
//! Both properties must hold in the release profile, where LTO inlines
//! aggressively, and in the debug profile, where nothing is inlined and the
//! frames are largest. CI runs this file in both.
//!
//! Reading dead stack below the stack pointer is outside the Rust abstract
//! machine. It is done with volatile raw reads inside the mapped 16 MiB
//! thread stack, which works on every tier-1 target.

use moduletto::dsa::ml_dsa_65;
use moduletto::kem::ml_kem_768;

const STACK: usize = 16 * 1024 * 1024;
/// How far below the caller to paint and to search.
const WINDOW: usize = 2 * 1024 * 1024;
const PAINT: u8 = 0xa5;
/// The shortest zero run taken to be the scrub buffer.
const MIN_SCRUB_RUN: usize = 64 * 1024;
/// Bytes below the scrub buffer that the scrub's own callee (`memset` and,
/// in debug builds, `write_bytes`) may use for its frame.
const SCRUB_CALLEE_SLACK: usize = 512;

/// Fill `WINDOW` bytes of the stack below the caller with [`PAINT`].
#[inline(never)]
fn paint() {
    const BYTES: usize = WINDOW + 64 * 1024;
    let mut buf = core::mem::MaybeUninit::<[u8; BYTES]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;
    // SAFETY: `p` points to `BYTES` writable bytes owned by this frame.
    unsafe { core::ptr::write_bytes(p, PAINT, BYTES) };
    core::hint::black_box(p);
}

/// A copy of the stack region `[anchor - WINDOW, anchor)`, deepest byte
/// first.
#[inline(never)]
fn snapshot(anchor: usize) -> Vec<u8> {
    let lo = anchor - WINDOW;
    let mut hay = vec![0u8; WINDOW];
    for (i, b) in hay.iter_mut().enumerate() {
        // SAFETY: inside this thread's mapped stack (16 MiB, anchor near the
        // top); volatile so that the read is not elided.
        *b = unsafe { core::ptr::read_volatile((lo + i) as *const u8) };
    }
    hay
}

/// The dead stack below the caller after `op` has run on a painted stack.
/// Index i of the result is at depth `WINDOW - i` below the anchor.
fn stack_after<F: FnOnce() + Send + 'static>(op: F) -> Vec<u8> {
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            paint();
            let a = 0u8;
            // 256 bytes of headroom for this frame's own locals.
            let anchor = core::hint::black_box(&a) as *const u8 as usize - 256;
            op();
            snapshot(anchor)
        })
        .unwrap()
        .join()
        .unwrap()
}

/// Depths below the anchor at which `needle` occurs.
fn find(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    (0..=hay.len() - needle.len())
        .filter(|&i| &hay[i..i + needle.len()] == needle)
        .map(|i| WINDOW - i)
        .collect()
}

fn assert_no_secret(what: &str, hay: &[u8], needles: &[(&str, &[u8])]) {
    for (name, needle) in needles {
        let hits = find(hay, needle);
        assert!(
            hits.is_empty(),
            "{what}: {name} found on the stack at these depths below the caller: {hits:?}"
        );
    }
}

/// The scrub buffer is the longest run of zero bytes. Every byte deeper than
/// it, apart from the scrub callee's small frame, must still hold the paint.
fn assert_scrub_covers_operation(what: &str, hay: &[u8]) {
    let (mut best, mut i) = ((0, 0), 0);
    while i < hay.len() {
        let start = i;
        while i < hay.len() && hay[i] == 0 {
            i += 1;
        }
        if i - start > best.1 - best.0 {
            best = (start, i);
        }
        i += 1;
    }
    assert!(
        best.1 - best.0 >= MIN_SCRUB_RUN,
        "{what}: no scrub buffer found (longest zero run {} bytes)",
        best.1 - best.0
    );
    // `best.0` is the deepest byte of the scrub buffer.
    let limit = best.0.saturating_sub(SCRUB_CALLEE_SLACK);
    if let Some(deepest) = hay[..limit].iter().position(|&b| b != PAINT) {
        panic!(
            "{what}: the operation wrote {} bytes below the scrub buffer (deepest write at \
             depth {}, scrub ends at depth {})",
            best.0 - deepest,
            WINDOW - deepest,
            WINDOW - best.0
        );
    }
}

fn dsa_key() -> Vec<u8> {
    // Generated in another thread so that its residue is not on the test's
    // stack.
    std::thread::spawn(|| ml_dsa_65::keygen_internal(&[0x3c; 32]).1.to_vec())
        .join()
        .unwrap()
}

fn dsa_needles(sk: &[u8]) -> [(&'static str, &[u8]); 3] {
    [
        ("K", &sk[32..64]),
        ("packed s1", &sk[128..160]),
        ("packed t0", &sk[2000..2032]),
    ]
}

/// FIPS 204 section 3.6.3: no copy of K, s₁ or t₀ survives signing on the
/// stack, and the scrub reaches the deepest frame of the signing core.
#[test]
fn dsa_sign_leaves_no_secret_on_stack() {
    let sk = dsa_key();
    let sk2 = sk.clone();
    let hay = stack_after(move || {
        let sig = Box::new(ml_dsa_65::sign(&sk2, b"stack message", b"ctx", &[0; 32]).unwrap());
        core::hint::black_box(&sig);
    });
    assert_no_secret("sign", &hay, &dsa_needles(&sk));
    assert_scrub_covers_operation("sign", &hay);
}

/// As above for key generation into caller-owned storage. The by-value
/// `keygen_internal` may leave copies of `sk` in its own frames; its
/// documentation says so.
#[test]
fn dsa_keygen_into_leaves_no_secret_on_stack() {
    let sk = dsa_key();
    let hay = stack_after(|| {
        let mut pk = Box::new([0u8; ml_dsa_65::PK_BYTES]);
        let mut sk = Box::new([0u8; ml_dsa_65::SK_BYTES]);
        ml_dsa_65::keygen_internal_into(&[0x3c; 32], &mut pk, &mut sk);
        core::hint::black_box((&pk, &sk));
    });
    assert_no_secret("keygen_internal_into", &hay, &dsa_needles(&sk));
    assert_scrub_covers_operation("keygen_internal_into", &hay);
}

/// As above for the RNG-backed `keygen_into` (FIPS 204 Algorithm 1). The
/// key is random, so the needles are read from the heap copy afterwards.
#[cfg(feature = "getrandom")]
#[test]
fn dsa_os_keygen_into_leaves_no_secret_on_stack() {
    let (tx, rx) = std::sync::mpsc::channel();
    let hay = stack_after(move || {
        let mut pk = Box::new([0u8; ml_dsa_65::PK_BYTES]);
        let mut sk = Box::new([0u8; ml_dsa_65::SK_BYTES]);
        ml_dsa_65::keygen_into(&mut pk, &mut sk).unwrap();
        core::hint::black_box((&pk, &sk));
        tx.send(sk).unwrap();
    });
    let sk = rx.recv().unwrap();
    assert_no_secret("keygen_into", &hay, &dsa_needles(&sk[..]));
    assert_scrub_covers_operation("keygen_into", &hay);
}

/// No copy of the packed ŝ or of z survives ML-KEM decapsulation on the
/// stack.
#[test]
fn kem_decaps_leaves_no_secret_on_stack() {
    let (ek, dk) = std::thread::spawn(|| ml_kem_768::keygen_derand(&[7; 32], &[9; 32]))
        .join()
        .unwrap();
    let (ct, _) = ml_kem_768::encaps_derand(&ek, &[3; 32]).unwrap();
    let dk2 = dk.to_vec();
    let hay = stack_after(move || {
        let ss = Box::new(ml_kem_768::decaps(&dk2, &ct).unwrap());
        core::hint::black_box(&ss);
    });
    let n = dk.len();
    assert_no_secret(
        "decaps",
        &hay,
        &[("packed s", &dk[..32]), ("z", &dk[n - 32..])],
    );
}
