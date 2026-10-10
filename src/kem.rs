//! ML-KEM (FIPS 203) as a library API: ML-KEM-512 and ML-KEM-768.
//!
//! This is the int16 path from `examples/kyber_benchmark.rs`: the NEON
//! backend on aarch64 and the scalar mirror of the pqcrystals reference C
//! elsewhere, with the inline Keccak. The two parameter sets share the code
//! and differ only in the module rank k and the noise parameter η₁ (the
//! compression widths du = 10 and dv = 4 are the same for both). The NIST
//! ACVP vectors in `tests/kat/` validate both (see `tests/kem_kat.rs`).
//!
//! | | [`ml_kem_512`] | [`ml_kem_768`] |
//! |---|---:|---:|
//! | NIST security category | 1 | 3 |
//! | k, η₁ | 2, 3 | 3, 2 |
//! | encapsulation key `ek` | 800 | 1184 |
//! | decapsulation key `dk` | 1632 | 2400 |
//! | ciphertext `c` | 768 | 1088 |
//! | shared secret | 32 | 32 |
//!
//! The deterministic `*_derand` functions take the randomness explicitly
//! (FIPS 203 `ML-KEM.KeyGen_internal` and `ML-KEM.Encaps_internal`); the
//! caller supplies it from a CSPRNG. With the `getrandom` feature, `keygen()`
//! and `encaps(ek)` draw it from the operating system instead.
//!
//! # Handling of secrets
//!
//! Seeds, noise polynomials, Keccak states and the re-encryption state of
//! decapsulation are wiped with [`zeroize`] before they go out of scope, and
//! the internal key structs wipe themselves on drop. Polynomials are
//! transformed in place rather than copied where the algorithm allows. After
//! each public operation returns, [`scrub_stack`] overwrites the stack region
//! the operation used, so spilled registers and temporaries the compiler
//! placed there are cleared too; that is a best-effort measure (libsodium's
//! `sodium_stackzero`), not a guarantee. The decapsulation key and the shared
//! secret are returned by value as plain arrays: wrap them in
//! [`zeroize::Zeroizing`] or wipe them yourself when you are done.
//!
//! Decapsulation never branches on secret data. The ciphertext comparison
//! that drives implicit rejection goes through [`subtle`], and the rounding
//! divisions by q in message decoding and compression are fixed-point
//! multiplications, so no target can lower them to a variable-time divide.
//! On AArch64 every entry point runs under [`crate::dit::with_dit`]: without
//! `PSTATE.DIT` the 64-bit multiplier's latency depends on its operands
//! (measured on Apple M5), which dudect detects in decapsulation. Measured
//! results are in `audits/README.md`.

#![allow(clippy::needless_range_loop)]
// Some helpers are used only on aarch64 (NEON) or only on other targets.
#![allow(dead_code)]

extern crate std;
use std::vec::Vec;

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// Size of the shared secret for every parameter set.
pub const SS_BYTES: usize = 32;

/// Why an input was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemError {
    /// A key or ciphertext had the wrong length.
    Length,
    /// The encapsulation key failed the FIPS 203 modulus check
    /// (a coefficient is not below q), or the decapsulation key's
    /// embedded hash of `ek` does not match.
    InvalidKey,
    /// The operating system's random source failed (`getrandom` feature).
    Randomness,
}

impl core::fmt::Display for KemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KemError::Length => f.write_str("ML-KEM: wrong input length"),
            KemError::InvalidKey => f.write_str("ML-KEM: invalid key"),
            KemError::Randomness => f.write_str("ML-KEM: OS random source failed"),
        }
    }
}

impl std::error::Error for KemError {}

macro_rules! parameter_set {
    ($module:ident, $name:literal, $k:literal) => {
        #[doc = concat!($name, " (FIPS 203).")]
        pub mod $module {
            use super::{KemError, SS_BYTES};

            /// Size of an encapsulation key.
            pub const EK_BYTES: usize = super::ek_len($k);
            /// Size of a decapsulation key.
            pub const DK_BYTES: usize = super::dk_len($k);
            /// Size of a ciphertext.
            pub const CT_BYTES: usize = super::ct_len($k);

            /// FIPS 203 `ML-KEM.KeyGen_internal(d, z)`: returns `(ek, dk)`.
            ///
            /// `d` and `z` must each be 32 bytes from a CSPRNG. The returned
            /// `dk` is secret: wipe it when you are done with it.
            pub fn keygen_derand(d: &[u8; 32], z: &[u8; 32]) -> ([u8; EK_BYTES], [u8; DK_BYTES]) {
                crate::dit::with_dit(|| {
                    let sk = super::keygen::<$k>(d, z);
                    let mut ek = [0u8; EK_BYTES];
                    let mut dk = [0u8; DK_BYTES];
                    super::ek_to_bytes(&sk.pk, &mut ek);
                    super::dk_to_bytes(&sk, &mut dk);
                    drop(sk);
                    super::scrub_stack();
                    // ek, and the copy of ek ‖ H(ek) inside dk, are public.
                    super::declassify(&ek);
                    super::declassify(&dk[384 * $k..768 * $k + 64]);
                    (ek, dk)
                })
            }

            /// FIPS 203 `ML-KEM.KeyGen()`: draws `d` and `z` from the operating
            /// system's CSPRNG. Requires the `getrandom` feature.
            #[cfg(feature = "getrandom")]
            pub fn keygen() -> Result<([u8; EK_BYTES], [u8; DK_BYTES]), KemError> {
                let mut d = zeroize::Zeroizing::new([0u8; 32]);
                let mut z = zeroize::Zeroizing::new([0u8; 32]);
                super::os_random(&mut *d)?;
                super::os_random(&mut *z)?;
                Ok(keygen_derand(&d, &z))
            }

            /// FIPS 203 `ML-KEM.Encaps(ek)`: draws `m` from the operating
            /// system's CSPRNG. Performs the encapsulation key check of
            /// FIPS 203 section 7.2. Requires the `getrandom` feature.
            #[cfg(feature = "getrandom")]
            pub fn encaps(ek: &[u8]) -> Result<([u8; CT_BYTES], [u8; SS_BYTES]), KemError> {
                super::check_ek::<$k>(ek)?;
                let mut m = zeroize::Zeroizing::new([0u8; 32]);
                super::os_random(&mut *m)?;
                encaps_derand(ek, &m)
            }

            /// FIPS 203 `ML-KEM.Encaps(ek)` with the message `m` supplied by
            /// the caller. Performs the encapsulation key check of FIPS 203
            /// section 7.2. Returns `(ciphertext, shared_secret)`.
            pub fn encaps_derand(
                ek: &[u8],
                m: &[u8; 32],
            ) -> Result<([u8; CT_BYTES], [u8; SS_BYTES]), KemError> {
                super::check_ek::<$k>(ek)?;
                Ok(crate::dit::with_dit(|| {
                    let (ct, ss) = super::encaps::<$k>(&super::ek_from_bytes(ek), m);
                    super::scrub_stack();
                    // unwrap: the encoder produces exactly this length.
                    let c: [u8; CT_BYTES] = super::ct_to_bytes(&ct).try_into().unwrap();
                    super::declassify(&c);
                    (c, ss)
                }))
            }

            /// FIPS 203 `ML-KEM.Decaps(dk, c)`. Performs the input checks of
            /// FIPS 203 section 7.3 (lengths and the hash of `ek` inside
            /// `dk`). A tampered ciphertext yields the implicit-rejection
            /// key, not an error.
            pub fn decaps(dk: &[u8], c: &[u8]) -> Result<[u8; SS_BYTES], KemError> {
                super::check_dk::<$k>(dk)?;
                if c.len() != CT_BYTES {
                    return Err(KemError::Length);
                }
                Ok(crate::dit::with_dit(|| {
                    let ss = super::decaps::<$k>(&super::dk_from_bytes(dk), &super::ct_from_bytes(c));
                    super::scrub_stack();
                    ss
                }))
            }

            /// FIPS 203 section 7.2 encapsulation key check on its own.
            pub fn check_encapsulation_key(ek: &[u8]) -> Result<(), KemError> {
                super::check_ek::<$k>(ek)
            }

            /// FIPS 203 section 7.3 decapsulation key check on its own.
            pub fn check_decapsulation_key(dk: &[u8]) -> Result<(), KemError> {
                super::check_dk::<$k>(dk)
            }
        }
    };
}

parameter_set!(ml_kem_512, "ML-KEM-512", 2);
parameter_set!(ml_kem_768, "ML-KEM-768", 3);

#[cfg(feature = "getrandom")]
fn os_random(buf: &mut [u8]) -> Result<(), KemError> {
    getrandom::fill(buf).map_err(|_| KemError::Randomness)
}

/// Overwrite the stack region below the caller's frame.
///
/// Called by the public entry points right after the KEM operation returns,
/// from the same frame, so this function's buffer occupies the addresses the
/// operation's frames just vacated: spilled registers, `.map()` temporaries,
/// Keccak lanes, array copies the compiler chose to make. 32 KiB covers the
/// deepest path (ML-KEM-768 decapsulation re-encrypting with a 9-polynomial
/// matrix) with margin. The write is kept by an optimisation barrier.
///
/// This is the `sodium_stackzero` approach and shares its limits: it reaches
/// only the main stack of this thread, below this frame, and only memory, not
/// registers that the OS or a signal handler may have saved elsewhere.
#[inline(never)]
fn scrub_stack() {
    const BYTES: usize = 32 * 1024;
    let mut buf = core::mem::MaybeUninit::<[u8; BYTES]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;
    // SAFETY: `p` points to `BYTES` writable bytes owned by this frame.
    unsafe { core::ptr::write_bytes(p, 0, BYTES) };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::hint::black_box(p);
}

/// Mark derived-but-public data as defined for the ctgrind-style check.
/// A no-op unless the `valgrind-ct` feature is enabled.
#[inline(always)]
fn declassify<T: ?Sized>(_x: &T) {
    #[cfg(feature = "valgrind-ct")]
    crate::valgrind::declassify(_x);
}

const fn ek_len(k: usize) -> usize {
    384 * k + 32
}
const fn dk_len(k: usize) -> usize {
    768 * k + 96
}
const fn ct_len(k: usize) -> usize {
    320 * k + 128
}
/// η₁: 3 for ML-KEM-512, 2 for ML-KEM-768 and ML-KEM-1024.
const fn eta1(k: usize) -> u32 {
    if k == 2 { 3 } else { 2 }
}

/// FIPS 203 section 7.2: length check and the modulus check
/// `ByteEncode12(ByteDecode12(ek)) == ek`, which holds exactly when every
/// 12-bit coefficient is below q.
fn check_ek<const K: usize>(ek: &[u8]) -> Result<(), KemError> {
    if ek.len() != ek_len(K) {
        return Err(KemError::Length);
    }
    let mut bad = 0u16;
    for chunk in ek[..384 * K].chunks_exact(3) {
        let (b0, b1, b2) = (chunk[0] as u16, chunk[1] as u16, chunk[2] as u16);
        let c0 = b0 | ((b1 & 0x0f) << 8);
        let c1 = (b1 >> 4) | (b2 << 4);
        // Branch-free: the high bit of (q - 1 - c) is set when c >= q.
        bad |= (3328u16.wrapping_sub(c0) | 3328u16.wrapping_sub(c1)) & 0x8000;
    }
    if bad == 0 { Ok(()) } else { Err(KemError::InvalidKey) }
}

/// FIPS 203 section 7.3: length check and `H(ek) == h` for the `ek` and `h`
/// embedded in `dk`.
fn check_dk<const K: usize>(dk: &[u8]) -> Result<(), KemError> {
    if dk.len() != dk_len(K) {
        return Err(KemError::Length);
    }
    let (ek, h) = (&dk[384 * K..768 * K + 32], &dk[768 * K + 32..768 * K + 64]);
    if sha3_256(&[ek]) != h {
        return Err(KemError::InvalidKey);
    }
    Ok(())
}

use crate::ntt::KYBER_Q;



// ── Inline Keccak-f[1600] (XKCP plain-64-bit, non-bebigokimisa variant) ──────
//
// Translated from:
//   KeccakP-1600-opt64.c  — KeccakP1600_Permute_24rounds
//   KeccakP-1600-64.macros — thetaRhoPiChiIota (non-bebigokimisa)
//   KeccakP-1600-unrolling.macros — FullUnrolling / rounds24
//
// State mapping (A[x + 5*y], named ba/be/…/su):
//   s[0..4]   = A[0..4][0]  (ba, be, bi, bo, bu)
//   s[5..9]   = A[0..4][1]  (ga, ge, gi, go, gu)
//   s[10..14] = A[0..4][2]  (ka, ke, ki, ko, ku)
//   s[15..19] = A[0..4][3]  (ma, me, mi, mo, mu)
//   s[20..24] = A[0..4][4]  (sa, se, si, so, su)
//
// Each round: θ (column parity), then combined θρπ per output row, then χ+ι.
// The 25 source indices across the 5 rows are all distinct, so in-place is safe.

#[inline(always)]
fn keccak_f1600(s: &mut [u64; 25]) {

    const RC: [u64; 24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];

    // Load state into named locals so LLVM can allocate all 25 to registers.
    // The A/E interleaving matches the XKCP FullUnrolling approach: each round reads
    // one set of variables and writes another, so the compiler sees no aliasing.
    let (mut a0,  mut a1,  mut a2,  mut a3,  mut a4)  = (s[0],  s[1],  s[2],  s[3],  s[4]);
    let (mut a5,  mut a6,  mut a7,  mut a8,  mut a9)  = (s[5],  s[6],  s[7],  s[8],  s[9]);
    let (mut a10, mut a11, mut a12, mut a13, mut a14) = (s[10], s[11], s[12], s[13], s[14]);
    let (mut a15, mut a16, mut a17, mut a18, mut a19) = (s[15], s[16], s[17], s[18], s[19]);
    let (mut a20, mut a21, mut a22, mut a23, mut a24) = (s[20], s[21], s[22], s[23], s[24]);

    // prepareTheta: column XOR values
    let mut ca = a0^a5^a10^a15^a20;
    let mut ce = a1^a6^a11^a16^a21;
    let mut ci = a2^a7^a12^a17^a22;
    let mut co = a3^a8^a13^a18^a23;
    let mut cu = a4^a9^a14^a19^a24;

    for rc in RC {
        // θ: diagonal parity mixing
        let da = cu ^ ce.rotate_left(1);
        let de = ca ^ ci.rotate_left(1);
        let di = ce ^ co.rotate_left(1);
        let do_ = ci ^ cu.rotate_left(1);
        let du = co ^ ca.rotate_left(1);

        // Combined θ + ρ + π for each output row (all 25 source indices are distinct).
        // Column sums for the next round are accumulated inline — no write-back needed.

        // Row b: sources a0,a6,a12,a18,a24 with d[a,e,i,o,u]
        let bba =  a0  ^ da;
        let bbe = (a6  ^ de).rotate_left(44);
        let bbi = (a12 ^ di).rotate_left(43);
        let bbo = (a18 ^ do_).rotate_left(21);
        let bbu = (a24 ^ du).rotate_left(14);
        let eba = bba ^ (!bbe & bbi) ^ rc;
        let ebe = bbe ^ (!bbi & bbo);
        let ebi = bbi ^ (!bbo & bbu);
        let ebo = bbo ^ (!bbu & bba);
        let ebu = bbu ^ (!bba & bbe);
        ca = eba; ce = ebe; ci = ebi; co = ebo; cu = ebu;

        // Row g: sources a3,a9,a10,a16,a22 with d[o,u,a,e,i]
        let bga = (a3  ^ do_).rotate_left(28);
        let bge = (a9  ^ du).rotate_left(20);
        let bgi = (a10 ^ da).rotate_left(3);
        let bgo = (a16 ^ de).rotate_left(45);
        let bgu = (a22 ^ di).rotate_left(61);
        let ega = bga ^ (!bge & bgi);
        let ege = bge ^ (!bgi & bgo);
        let egi = bgi ^ (!bgo & bgu);
        let ego = bgo ^ (!bgu & bga);
        let egu = bgu ^ (!bga & bge);
        ca ^= ega; ce ^= ege; ci ^= egi; co ^= ego; cu ^= egu;

        // Row k: sources a1,a7,a13,a19,a20 with d[e,i,o,u,a]
        let bka = (a1  ^ de).rotate_left(1);
        let bke = (a7  ^ di).rotate_left(6);
        let bki = (a13 ^ do_).rotate_left(25);
        let bko = (a19 ^ du).rotate_left(8);
        let bku = (a20 ^ da).rotate_left(18);
        let eka = bka ^ (!bke & bki);
        let eke = bke ^ (!bki & bko);
        let eki = bki ^ (!bko & bku);
        let eko = bko ^ (!bku & bka);
        let eku = bku ^ (!bka & bke);
        ca ^= eka; ce ^= eke; ci ^= eki; co ^= eko; cu ^= eku;

        // Row m: sources a4,a5,a11,a17,a23 with d[u,a,e,i,o]
        let bma = (a4  ^ du).rotate_left(27);
        let bme = (a5  ^ da).rotate_left(36);
        let bmi = (a11 ^ de).rotate_left(10);
        let bmo = (a17 ^ di).rotate_left(15);
        let bmu = (a23 ^ do_).rotate_left(56);
        let ema = bma ^ (!bme & bmi);
        let eme = bme ^ (!bmi & bmo);
        let emi = bmi ^ (!bmo & bmu);
        let emo = bmo ^ (!bmu & bma);
        let emu = bmu ^ (!bma & bme);
        ca ^= ema; ce ^= eme; ci ^= emi; co ^= emo; cu ^= emu;

        // Row s: sources a2,a8,a14,a15,a21 with d[i,o,u,a,e]
        let bsa = (a2  ^ di).rotate_left(62);
        let bse = (a8  ^ do_).rotate_left(55);
        let bsi = (a14 ^ du).rotate_left(39);
        let bso = (a15 ^ da).rotate_left(41);
        let bsu = (a21 ^ de).rotate_left(2);
        let esa = bsa ^ (!bse & bsi);
        let ese = bse ^ (!bsi & bso);
        let esi = bsi ^ (!bso & bsu);
        let eso = bso ^ (!bsu & bsa);
        let esu = bsu ^ (!bsa & bse);
        ca ^= esa; ce ^= ese; ci ^= esi; co ^= eso; cu ^= esu;

        // Update named state locals for next round
        a0=eba; a1=ebe; a2=ebi; a3=ebo; a4=ebu;
        a5=ega; a6=ege; a7=egi; a8=ego; a9=egu;
        a10=eka; a11=eke; a12=eki; a13=eko; a14=eku;
        a15=ema; a16=eme; a17=emi; a18=emo; a19=emu;
        a20=esa; a21=ese; a22=esi; a23=eso; a24=esu;
    }

    // Store back to memory
    (s[0],  s[1],  s[2],  s[3],  s[4])  = (a0,  a1,  a2,  a3,  a4);
    (s[5],  s[6],  s[7],  s[8],  s[9])  = (a5,  a6,  a7,  a8,  a9);
    (s[10], s[11], s[12], s[13], s[14]) = (a10, a11, a12, a13, a14);
    (s[15], s[16], s[17], s[18], s[19]) = (a15, a16, a17, a18, a19);
    (s[20], s[21], s[22], s[23], s[24]) = (a20, a21, a22, a23, a24);
}

// ── Sponge helpers ─────────────────────────────────────────────────────────────

#[inline]
fn xor_bytes_at(s: &mut [u64; 25], offset: usize, data: &[u8]) {
    for (i, &b) in data.iter().enumerate() {
        let pos = offset + i;
        s[pos >> 3] ^= (b as u64) << ((pos & 7) * 8);
    }
}

#[inline]
fn xor_lanes(s: &mut [u64; 25], data: &[u8], lane_count: usize) {
    for i in 0..lane_count {
        s[i] ^= u64::from_le_bytes(data[8*i..8*i+8].try_into().unwrap());
    }
}

#[inline]
fn extract_bytes(s: &[u64; 25], out: &mut [u8]) {
    let full = out.len() / 8;
    for i in 0..full {
        out[8*i..8*i+8].copy_from_slice(&s[i].to_le_bytes());
    }
    let rem = out.len() & 7;
    if rem > 0 {
        let lane = s[full].to_le_bytes();
        out[full*8..].copy_from_slice(&lane[..rem]);
    }
}

/// Absorb `inputs` into a fresh Keccak state, pad with `domain`, permute, squeeze.
fn keccak_sponge(rate: usize, inputs: &[&[u8]], domain: u8, output: &mut [u8]) {
    let mut s = [0u64; 25];
    let lane_rate = rate / 8; // rate is always a multiple of 8 for SHA3/SHAKE
    let mut pos = 0usize;     // byte offset within current rate block

    for &data in inputs {
        let mut d = data;

        // Fill any partial block first
        if pos > 0 && !d.is_empty() {
            let fill = (rate - pos).min(d.len());
            xor_bytes_at(&mut s, pos, &d[..fill]);
            pos += fill;
            d = &d[fill..];
            if pos == rate {
                keccak_f1600(&mut s);
                pos = 0;
            }
        }

        // Process full blocks with bulk lane XOR
        while d.len() >= rate {
            xor_lanes(&mut s, d, lane_rate);
            keccak_f1600(&mut s);
            d = &d[rate..];
        }

        // Remaining partial bytes
        if !d.is_empty() {
            xor_bytes_at(&mut s, pos, d);
            pos += d.len();
        }
    }

    // Domain separation byte + multi-rate padding (0x80 at rate-1)
    s[pos >> 3] ^= (domain as u64) << ((pos & 7) * 8);
    let last = rate - 1;
    s[last >> 3] ^= 0x80u64 << ((last & 7) * 8);
    keccak_f1600(&mut s);

    // Squeeze: extract `output.len()` bytes, permuting between rate-sized blocks
    let mut out = output;
    while !out.is_empty() {
        let take = rate.min(out.len());
        extract_bytes(&s, &mut out[..take]);
        out = &mut out[take..];
        if !out.is_empty() {
            keccak_f1600(&mut s);
        }
    }
    s.zeroize();
}

/// Single-lane incremental XOF: absorb once, then squeeze rate-sized blocks on
/// demand. `keccak_sponge` needs the total output length up front, which forces
/// callers doing rejection sampling to guess an upper bound; this does not.
struct ShakeStream {
    s: [u64; 25],
    rate: usize,
    permute_pending: bool,
}

impl Drop for ShakeStream {
    fn drop(&mut self) {
        self.s.zeroize();
    }
}

impl ShakeStream {
    fn new(rate: usize, inputs: &[&[u8]], domain: u8) -> Self {
        let mut s = [0u64; 25];
        let mut pos = 0usize;
        for &data in inputs {
            for &b in data {
                s[pos >> 3] ^= (b as u64) << ((pos & 7) * 8);
                pos += 1;
                if pos == rate {
                    keccak_f1600(&mut s);
                    pos = 0;
                }
            }
        }
        s[pos >> 3] ^= (domain as u64) << ((pos & 7) * 8);
        s[(rate - 1) >> 3] ^= 0x80u64 << (((rate - 1) & 7) * 8);
        keccak_f1600(&mut s);
        Self { s, rate, permute_pending: false }
    }

    fn squeeze_block(&mut self, out: &mut [u8]) {
        if self.permute_pending {
            keccak_f1600(&mut self.s);
        }
        self.permute_pending = true;
        for i in 0..self.rate / 8 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.s[i].to_le_bytes());
        }
    }
}

// ── Hash wrappers using inline Keccak ─────────────────────────────────────────
//
// Rates: SHAKE-128=168, SHAKE-256=136, SHA3-256=136, SHA3-512=72 (bytes)
// Domain bytes: SHAKE=0x1F, SHA3=0x06

fn sha3_256(inputs: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    keccak_sponge(136, inputs, 0x06, &mut out);
    out
}

fn sha3_512(inputs: &[&[u8]]) -> [u8; 64] {
    let mut out = [0u8; 64];
    keccak_sponge(72, inputs, 0x06, &mut out);
    out
}

fn shake128(inputs: &[&[u8]], output: &mut [u8]) {
    keccak_sponge(168, inputs, 0x1f, output);
}

fn shake256(inputs: &[&[u8]], output: &mut [u8]) {
    keccak_sponge(136, inputs, 0x1f, output);
}


// ── ARM64 NEON i16 NTT — mirrors the pqcrystals-kyber_kyber512_ref reference C ─
//
// Zeta table from pqcrystals-kyber_kyber512_ref/ntt.c (R = 2^16, QINV = -3327).
// Indices 1..127  → NTT butterfly twiddle factors (k=1..127).
// Indices 64..127 → also used in basemul (pair zetas).
// zetas[0] is unused (placeholder 0).
//
// Montgomery arithmetic:  fqmul(a, b) = a*b*R⁻¹ mod q  (result in (-q,q)).
// NEON acceleration: inner butterfly loop vectorised for len ≥ 8 via int16x8_t.

// Matches pqcrystals-kyber_kyber512_ref ntt.c exactly (0-indexed).
// NTT uses k=1..127 (zetas[1..127]); basemul uses zetas[64+i] for i=0..63.
static ZETAS_I16: [i16; 128] = [
   -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
    -171,   622,  1577,   182,   962, -1202, -1474,  1468,
     573, -1325,   264,   383,  -829,  1458, -1602,  -130,
    -681,  1017,   732,   608, -1542,   411,  -205, -1571,
    1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
     516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
    -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
    -398,   961, -1508,  -725,   448, -1065,   677, -1275,
   -1103,   430,   555,   843, -1251,   871,  1550,   105,
     422,   587,   177,  -235,  -291,  -460,  1574,  1653,
    -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
   -1590,   644,  -872,   349,   418,   329,  -156,   -75,
     817,  1097,   603,   610,  1322, -1285, -1465,   384,
   -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
   -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
    -108,  -308,   996,   991,   958, -1460,  1522,  1628,
];

// Montgomery multiply: a*b*2^{-16} mod 3329, result in (-q, q).
#[inline(always)]
fn fqmul_s(a: i16, b: i16) -> i16 {
    let t = (a as i32) * (b as i32);
    let u = (t as i16).wrapping_mul(-3327_i16); // (t mod 2^16) * QINV mod 2^16
    ((t - (u as i32) * 3329) >> 16) as i16
}

// Barrett reduce: centered representative in (-q, q) for |a| ≤ q·2^15.
#[inline(always)]
fn barrett_s(a: i16) -> i16 {
    const V: i32 = 20159; // round(2^26 / 3329)
    let t = ((V * (a as i32) + (1 << 25)) >> 26) as i16;
    a - t * 3329_i16
}

// Forward NTT in-place (7 Cooley-Tukey layers, reference C structure).
// NEON-accelerated for len ≥ 8; scalar for len ∈ {2, 4}.
fn ntt_i16(r: &mut [i16; 256]) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        ntt_i16_neon(r);
    }
    #[cfg(not(target_arch = "aarch64"))]
    ntt_i16_scalar(r);
}

fn ntt_i16_scalar(r: &mut [i16; 256]) {
    let mut k: usize = 1;
    let mut len: usize = 128;
    while len >= 2 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS_I16[k]; k += 1;
            for j in start..start + len {
                let t = fqmul_s(zeta, r[j + len]);
                r[j + len] = r[j].wrapping_sub(t);
                r[j] = r[j].wrapping_add(t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

// Barrett reduce all 256 coefficients.
fn poly_reduce_i16(r: &mut [i16; 256]) {
    for c in r.iter_mut() { *c = barrett_s(*c); }
}

// Inverse NTT in-place (Gentleman-Sande, f=1441 final scale).
fn intt_i16(r: &mut [i16; 256]) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        intt_i16_neon(r);
    }
    #[cfg(not(target_arch = "aarch64"))]
    intt_i16_scalar(r);
}

fn intt_i16_scalar(r: &mut [i16; 256]) {
    let mut k: usize = 127;
    let mut len: usize = 2;
    while len <= 128 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS_I16[k];
            if k > 0 { k -= 1; }
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_s(t.wrapping_add(r[j + len]));
                r[j + len] = fqmul_s(zeta, r[j + len].wrapping_sub(t));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in r.iter_mut() { *c = fqmul_s(*c, 1441); } // 128^{-1} * R mod q
}

// basemul: multiply two degree-1 polys in Z_q[x]/(x²-zeta), using fqmul.
// Matches pqcrystals-kyber reference C basemul() exactly.
#[inline(always)]
fn basemul_s(r: &mut [i16; 2], a: &[i16], b: &[i16], zeta: i16) {
    r[0] = fqmul_s(a[1], b[1]);
    r[0] = fqmul_s(r[0], zeta);
    r[0] = r[0].wrapping_add(fqmul_s(a[0], b[0]));
    r[1] = fqmul_s(a[0], b[1]);
    r[1] = r[1].wrapping_add(fqmul_s(a[1], b[0]));
}

// Accumulate poly_basemul_montgomery into acc.
// Zeta layout: pair [4i..4i+1] uses ZETAS_I16[64+i], pair [4i+2..4i+3] uses -ZETAS_I16[64+i].
fn basemul_acc_i16(acc: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) {
    for i in 0..64 {
        let zeta = ZETAS_I16[64 + i];
        let mut tmp = [0i16; 2];
        basemul_s(&mut tmp, &a[4*i..], &b[4*i..], zeta);
        acc[4*i]     = acc[4*i].wrapping_add(tmp[0]);
        acc[4*i + 1] = acc[4*i + 1].wrapping_add(tmp[1]);
        basemul_s(&mut tmp, &a[4*i+2..], &b[4*i+2..], -zeta);
        acc[4*i + 2] = acc[4*i + 2].wrapping_add(tmp[0]);
        acc[4*i + 3] = acc[4*i + 3].wrapping_add(tmp[1]);
    }
}

// ── NEON intrinsic implementations (aarch64 only) ────────────────────────────

#[cfg(target_arch = "aarch64")]
mod neon_poly {
    use std::arch::aarch64::*;
    use super::ZETAS_I16;

    // Montgomery multiply: 8 lanes of int16, result in (-q,q).
    #[target_feature(enable = "neon")]
    pub unsafe fn fqmul_vec(a: int16x8_t, b: int16x8_t) -> int16x8_t {
        let qinv = vdup_n_s16(-3327_i16);
        let q    = vdupq_n_s16(3329_i16);
        // lower 4 lanes
        let t_lo = vmull_s16(vget_low_s16(a), vget_low_s16(b));
        let u_lo = vmul_s16(vmovn_s32(t_lo), qinv);
        let c_lo = vmull_s16(u_lo, vget_low_s16(q));
        let r_lo = vshrn_n_s32::<16>(vsubq_s32(t_lo, c_lo));
        // upper 4 lanes
        let t_hi = vmull_s16(vget_high_s16(a), vget_high_s16(b));
        let u_hi = vmul_s16(vmovn_s32(t_hi), qinv);
        let c_hi = vmull_s16(u_hi, vget_high_s16(q));
        let r_hi = vshrn_n_s32::<16>(vsubq_s32(t_hi, c_hi));
        vcombine_s16(r_lo, r_hi)
    }

    // Barrett reduce: 8 lanes of int16, centered result in (-q,q).
    #[target_feature(enable = "neon")]
    pub unsafe fn barrett_vec(a: int16x8_t) -> int16x8_t {
        let v = vdupq_n_s16(20159_i16);
        let q = vdupq_n_s16(3329_i16);
        // t = (a * 20159 + 2^25) >> 26  via  (((a*20159) >> 16) >> 10)
        // Lower 4
        let t_lo = vaddq_s32(
            vmull_s16(vget_low_s16(a), vget_low_s16(v)),
            vdupq_n_s32(1 << 25),
        );
        let lo16 = vshrq_n_s16::<10>(vcombine_s16(vshrn_n_s32::<16>(t_lo), vdup_n_s16(0)));
        // Upper 4
        let t_hi = vaddq_s32(
            vmull_s16(vget_high_s16(a), vget_high_s16(v)),
            vdupq_n_s32(1 << 25),
        );
        let hi16 = vshrq_n_s16::<10>(vcombine_s16(vshrn_n_s32::<16>(t_hi), vdup_n_s16(0)));
        let t = vcombine_s16(vget_low_s16(lo16), vget_low_s16(hi16));
        vsubq_s16(a, vmulq_s16(t, q))
    }

    // The len ∈ {4, 2} layers cannot use the plain "load top / load bottom"
    // pattern: at those widths both halves of a butterfly sit inside the same
    // 8-lane vector. Running them scalar costs ~250 ns of a ~300 ns transform,
    // while the five wide layers together take ~53 ns. Deinterleaving with
    // uzp/zip (len = 2) or 64-bit half splits (len = 4) uses all lanes.

    #[target_feature(enable = "neon")]
    pub unsafe fn ntt_layer4(r: &mut [i16; 256], k0: usize) {
        for m in 0..16 {
            let base = m * 16;
            let zv = vcombine_s16(
                vdup_n_s16(ZETAS_I16[k0 + 2 * m]),
                vdup_n_s16(ZETAS_I16[k0 + 2 * m + 1]),
            );
            let v0 = vld1q_s16(r.as_ptr().add(base));
            let v1 = vld1q_s16(r.as_ptr().add(base + 8));
            let tops = vcombine_s16(vget_low_s16(v0), vget_low_s16(v1));
            let bots = vcombine_s16(vget_high_s16(v0), vget_high_s16(v1));
            let t = fqmul_vec(zv, bots);
            let nt = vaddq_s16(tops, t);
            let nb = vsubq_s16(tops, t);
            vst1q_s16(r.as_mut_ptr().add(base), vcombine_s16(vget_low_s16(nt), vget_low_s16(nb)));
            vst1q_s16(r.as_mut_ptr().add(base + 8), vcombine_s16(vget_high_s16(nt), vget_high_s16(nb)));
        }
    }

    #[target_feature(enable = "neon")]
    pub unsafe fn ntt_layer2(r: &mut [i16; 256], k0: usize) {
        for m in 0..16 {
            let base = m * 16;
            let k = k0 + 4 * m;
            let zs: [i16; 8] = [
                ZETAS_I16[k], ZETAS_I16[k],
                ZETAS_I16[k + 1], ZETAS_I16[k + 1],
                ZETAS_I16[k + 2], ZETAS_I16[k + 2],
                ZETAS_I16[k + 3], ZETAS_I16[k + 3],
            ];
            let zv = vld1q_s16(zs.as_ptr());
            let v0 = vreinterpretq_s32_s16(vld1q_s16(r.as_ptr().add(base)));
            let v1 = vreinterpretq_s32_s16(vld1q_s16(r.as_ptr().add(base + 8)));
            let tops = vreinterpretq_s16_s32(vuzp1q_s32(v0, v1));
            let bots = vreinterpretq_s16_s32(vuzp2q_s32(v0, v1));
            let t = fqmul_vec(zv, bots);
            let nt = vreinterpretq_s32_s16(vaddq_s16(tops, t));
            let nb = vreinterpretq_s32_s16(vsubq_s16(tops, t));
            vst1q_s16(r.as_mut_ptr().add(base), vreinterpretq_s16_s32(vzip1q_s32(nt, nb)));
            vst1q_s16(r.as_mut_ptr().add(base + 8), vreinterpretq_s16_s32(vzip2q_s32(nt, nb)));
        }
    }

    #[target_feature(enable = "neon")]
    pub unsafe fn intt_layer2(r: &mut [i16; 256], k0: usize) {
        for m in 0..16 {
            let base = m * 16;
            let k = k0 - 4 * m;
            let zs: [i16; 8] = [
                ZETAS_I16[k], ZETAS_I16[k],
                ZETAS_I16[k - 1], ZETAS_I16[k - 1],
                ZETAS_I16[k - 2], ZETAS_I16[k - 2],
                ZETAS_I16[k - 3], ZETAS_I16[k - 3],
            ];
            let zv = vld1q_s16(zs.as_ptr());
            let v0 = vreinterpretq_s32_s16(vld1q_s16(r.as_ptr().add(base)));
            let v1 = vreinterpretq_s32_s16(vld1q_s16(r.as_ptr().add(base + 8)));
            let tops = vreinterpretq_s16_s32(vuzp1q_s32(v0, v1));
            let bots = vreinterpretq_s16_s32(vuzp2q_s32(v0, v1));
            let sum = vreinterpretq_s32_s16(barrett_vec(vaddq_s16(tops, bots)));
            let scaled = vreinterpretq_s32_s16(fqmul_vec(zv, vsubq_s16(bots, tops)));
            vst1q_s16(r.as_mut_ptr().add(base), vreinterpretq_s16_s32(vzip1q_s32(sum, scaled)));
            vst1q_s16(r.as_mut_ptr().add(base + 8), vreinterpretq_s16_s32(vzip2q_s32(sum, scaled)));
        }
    }

    #[target_feature(enable = "neon")]
    pub unsafe fn intt_layer4(r: &mut [i16; 256], k0: usize) {
        for m in 0..16 {
            let base = m * 16;
            let zv = vcombine_s16(
                vdup_n_s16(ZETAS_I16[k0 - 2 * m]),
                vdup_n_s16(ZETAS_I16[k0 - 2 * m - 1]),
            );
            let v0 = vld1q_s16(r.as_ptr().add(base));
            let v1 = vld1q_s16(r.as_ptr().add(base + 8));
            let tops = vcombine_s16(vget_low_s16(v0), vget_low_s16(v1));
            let bots = vcombine_s16(vget_high_s16(v0), vget_high_s16(v1));
            let sum = barrett_vec(vaddq_s16(tops, bots));
            let scaled = fqmul_vec(zv, vsubq_s16(bots, tops));
            vst1q_s16(r.as_mut_ptr().add(base), vcombine_s16(vget_low_s16(sum), vget_low_s16(scaled)));
            vst1q_s16(r.as_mut_ptr().add(base + 8), vcombine_s16(vget_high_s16(sum), vget_high_s16(scaled)));
        }
    }

    // Forward NTT — every layer vectorised.
    #[target_feature(enable = "neon")]
    pub unsafe fn ntt_i16_neon_inner(r: &mut [i16; 256]) {
        let mut k: usize = 1;
        let mut len: usize = 128;
        while len >= 8 {
            let mut start = 0usize;
            while start < 256 {
                let zeta_vec = vdupq_n_s16(ZETAS_I16[k]); k += 1;
                let mut j = start;
                while j < start + len {
                    let top = vld1q_s16(r.as_ptr().add(j));
                    let bot = vld1q_s16(r.as_ptr().add(j + len));
                    let t = fqmul_vec(zeta_vec, bot);
                    vst1q_s16(r.as_mut_ptr().add(j + len), vsubq_s16(top, t));
                    vst1q_s16(r.as_mut_ptr().add(j), vaddq_s16(top, t));
                    j += 8;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
        debug_assert_eq!(k, 32);
        ntt_layer4(r, 32);
        ntt_layer2(r, 64);
    }

    // Inverse NTT — every layer vectorised.
    #[target_feature(enable = "neon")]
    pub unsafe fn intt_i16_neon_inner(r: &mut [i16; 256]) {
        intt_layer2(r, 127);
        intt_layer4(r, 63);

        let mut k: usize = 31;
        let mut len: usize = 8;
        while len <= 128 {
            let mut start = 0usize;
            while start < 256 {
                let zeta_vec = vdupq_n_s16(ZETAS_I16[k]);
                if k > 0 { k -= 1; }
                let mut j = start;
                while j < start + len {
                    let top = vld1q_s16(r.as_ptr().add(j));
                    let bot = vld1q_s16(r.as_ptr().add(j + len));
                    let sum   = barrett_vec(vaddq_s16(top, bot));
                    let scaled = fqmul_vec(zeta_vec, vsubq_s16(bot, top));
                    vst1q_s16(r.as_mut_ptr().add(j), sum);
                    vst1q_s16(r.as_mut_ptr().add(j + len), scaled);
                    j += 8;
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        // Final scale: f = 1441 = 128^{-1} * R mod q
        let f_vec = vdupq_n_s16(1441_i16);
        let mut j = 0usize;
        while j < 256 {
            let a = vld1q_s16(r.as_ptr().add(j));
            vst1q_s16(r.as_mut_ptr().add(j), fqmul_vec(f_vec, a));
            j += 8;
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn ntt_i16_neon(r: &mut [i16; 256]) {
    neon_poly::ntt_i16_neon_inner(r);
}

#[cfg(target_arch = "aarch64")]
unsafe fn intt_i16_neon(r: &mut [i16; 256]) {
    neon_poly::intt_i16_neon_inner(r);
}

// ── i16 KEM helper types ──────────────────────────────────────────────────────

type Poly16 = [i16; 256];

struct SecretKey16<const K: usize> {
    s_hat: [Poly16; K],
    pk: PublicKey16<K>,
    z: [u8; 32],
}

impl<const K: usize> Drop for SecretKey16<K> {
    fn drop(&mut self) {
        self.s_hat.zeroize();
        self.z.zeroize();
    }
}

struct PublicKey16<const K: usize> {
    t_hat: [Poly16; K],
    rho: [u8; 32],
    h_pk: [u8; 32],
}

struct Ciphertext16<const K: usize> {
    u_enc: [[u8; 320]; K],
    v_enc: [u8; 128],
}

// ── FIPS 203 byte encodings ───────────────────────────────────────────────────
//
//   ek = ByteEncode12(t_hat) ‖ rho                     (384k + 32)
//   dk = ByteEncode12(s_hat) ‖ ek ‖ H(ek) ‖ z          (768k + 96)
//   c  = ByteEncode10(Compress10(u)) ‖ ByteEncode4(Compress4(v))     (320k + 128)
//
// These are needed only at the external interface; the KEM keeps polynomials in
// its own representation internally. They are what the ACVP known-answer tests
// constrain.

/// ByteEncode12 of one polynomial: 2 coefficients -> 3 bytes, canonical [0, q).
fn poly_tobytes_i16(p: &Poly16, out: &mut [u8]) {
    for i in 0..128 {
        let mut t0 = p[2 * i] as i32;
        let mut t1 = p[2 * i + 1] as i32;
        t0 += (t0 >> 31) & KYBER_Q as i32;
        t1 += (t1 >> 31) & KYBER_Q as i32;
        out[3 * i] = t0 as u8;
        out[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        out[3 * i + 2] = (t1 >> 4) as u8;
    }
}

/// ByteDecode12 of one polynomial.
fn poly_frombytes_i16(bytes: &[u8]) -> Poly16 {
    let mut r = [0i16; 256];
    for i in 0..128 {
        let b0 = bytes[3 * i] as u16;
        let b1 = bytes[3 * i + 1] as u16;
        let b2 = bytes[3 * i + 2] as u16;
        r[2 * i] = (b0 | ((b1 & 0x0F) << 8)) as i16;
        r[2 * i + 1] = ((b1 >> 4) | (b2 << 4)) as i16;
    }
    r
}

fn ek_to_bytes<const K: usize>(pk: &PublicKey16<K>, out: &mut [u8]) {
    debug_assert_eq!(out.len(), ek_len(K));
    for i in 0..K {
        poly_tobytes_i16(&pk.t_hat[i], &mut out[384 * i..384 * (i + 1)]);
    }
    out[384 * K..].copy_from_slice(&pk.rho);
}

fn ek_from_bytes<const K: usize>(ek: &[u8]) -> PublicKey16<K> {
    let t_hat: [Poly16; K] =
        std::array::from_fn(|i| poly_frombytes_i16(&ek[384 * i..384 * (i + 1)]));
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * K..384 * K + 32]);
    let h_pk = sha3_256(&[ek]);
    PublicKey16 { t_hat, rho, h_pk }
}

/// Serialises `dk` into `out`, which the caller owns. No heap buffer holds
/// the secret key on the way.
fn dk_to_bytes<const K: usize>(sk: &SecretKey16<K>, out: &mut [u8]) {
    debug_assert_eq!(out.len(), dk_len(K));
    for i in 0..K {
        poly_tobytes_i16(&sk.s_hat[i], &mut out[384 * i..384 * (i + 1)]);
    }
    ek_to_bytes(&sk.pk, &mut out[384 * K..768 * K + 32]);
    out[768 * K + 32..768 * K + 64].copy_from_slice(&sk.pk.h_pk);
    out[768 * K + 64..].copy_from_slice(&sk.z);
}

fn dk_from_bytes<const K: usize>(dk: &[u8]) -> SecretKey16<K> {
    let s_hat: [Poly16; K] =
        std::array::from_fn(|i| poly_frombytes_i16(&dk[384 * i..384 * (i + 1)]));
    let pk = ek_from_bytes(&dk[384 * K..768 * K + 32]);
    let mut z = [0u8; 32];
    z.copy_from_slice(&dk[768 * K + 64..768 * K + 96]);
    SecretKey16 { s_hat, pk, z }
}

fn ct_to_bytes<const K: usize>(ct: &Ciphertext16<K>) -> Vec<u8> {
    let mut out = Vec::with_capacity(ct_len(K));
    for u in &ct.u_enc {
        out.extend_from_slice(u);
    }
    out.extend_from_slice(&ct.v_enc);
    out
}

fn ct_from_bytes<const K: usize>(c: &[u8]) -> Ciphertext16<K> {
    let mut u_enc = [[0u8; 320]; K];
    for (i, u) in u_enc.iter_mut().enumerate() {
        u.copy_from_slice(&c[320 * i..320 * (i + 1)]);
    }
    let mut v_enc = [0u8; 128];
    v_enc.copy_from_slice(&c[320 * K..]);
    Ciphertext16 { u_enc, v_enc }
}


// ── ARMv8.2 SHA3 two-way Keccak ──────────────────────────────────────────────
//
// The FEAT_SHA3 instructions (EOR3, RAX1, XAR, BCAX) operate on 128-bit vectors,
// which hold *two* 64-bit Keccak lanes. The `keccak` crate's asm path (what
// `sha3 = { features = ["asm"] }` uses) drives a single state through them and
// leaves the upper half of every register unused, which accounts for the earlier
// measurement of "no measurable advantage" from SHA3 hardware. Running two
// independent sponges, one per lane, doubles throughput:
//
//   scalar XKCP (this example's inline impl)  129.3 ns / permutation
//   sha3 crate, asm feature                   118.4 ns / permutation
//   this, two lanes                            56.5 ns / permutation
//
// Kyber has independent streams available to pair: the k² = 4 matrix polynomials
// and the k noise polynomials are each sampled from a separate SHAKE invocation.
#[cfg(target_arch = "aarch64")]
mod keccak_x2 {
    use std::arch::aarch64::*;

    const RC: [u64; 24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];

    /// Two independent Keccak-f1600 permutations, one per 64-bit lane.
    ///
    /// # Safety
    /// Requires the `sha3` target feature (FEAT_SHA3). Callers must have
    /// checked `is_aarch64_feature_detected!("sha3")`.
    #[target_feature(enable = "sha3")]
    pub unsafe fn f1600_x2(s: &mut [uint64x2_t; 25]) {
        for round in 0..24 {
        // theta: column parities
        let c0 = veor3q_u64(veor3q_u64(s[0], s[5], s[10]), s[15], s[20]);
        let c1 = veor3q_u64(veor3q_u64(s[1], s[6], s[11]), s[16], s[21]);
        let c2 = veor3q_u64(veor3q_u64(s[2], s[7], s[12]), s[17], s[22]);
        let c3 = veor3q_u64(veor3q_u64(s[3], s[8], s[13]), s[18], s[23]);
        let c4 = veor3q_u64(veor3q_u64(s[4], s[9], s[14]), s[19], s[24]);
        // d[x] = c[x-1] ^ rol(c[x+1], 1)   (RAX1)
        let d0 = vrax1q_u64(c4, c1);
        let d1 = vrax1q_u64(c0, c2);
        let d2 = vrax1q_u64(c1, c3);
        let d3 = vrax1q_u64(c2, c4);
        let d4 = vrax1q_u64(c3, c0);
        // theta-add + rho + pi fused: b[i] = rol(s[src] ^ d[src%5], ROT[src])   (XAR)
        let b0 = vxarq_u64::<0>(s[0], d0);
        let b1 = vxarq_u64::<20>(s[6], d1);
        let b2 = vxarq_u64::<21>(s[12], d2);
        let b3 = vxarq_u64::<43>(s[18], d3);
        let b4 = vxarq_u64::<50>(s[24], d4);
        let b5 = vxarq_u64::<36>(s[3], d3);
        let b6 = vxarq_u64::<44>(s[9], d4);
        let b7 = vxarq_u64::<61>(s[10], d0);
        let b8 = vxarq_u64::<19>(s[16], d1);
        let b9 = vxarq_u64::<3>(s[22], d2);
        let b10 = vxarq_u64::<63>(s[1], d1);
        let b11 = vxarq_u64::<58>(s[7], d2);
        let b12 = vxarq_u64::<39>(s[13], d3);
        let b13 = vxarq_u64::<56>(s[19], d4);
        let b14 = vxarq_u64::<46>(s[20], d0);
        let b15 = vxarq_u64::<37>(s[4], d4);
        let b16 = vxarq_u64::<28>(s[5], d0);
        let b17 = vxarq_u64::<54>(s[11], d1);
        let b18 = vxarq_u64::<49>(s[17], d2);
        let b19 = vxarq_u64::<8>(s[23], d3);
        let b20 = vxarq_u64::<2>(s[2], d2);
        let b21 = vxarq_u64::<9>(s[8], d3);
        let b22 = vxarq_u64::<25>(s[14], d4);
        let b23 = vxarq_u64::<23>(s[15], d0);
        let b24 = vxarq_u64::<62>(s[21], d1);
        // chi: a[i] = b[i] ^ (~b[i+1] & b[i+2])   (BCAX)
        s[0] = vbcaxq_u64(b0, b2, b1);
        s[1] = vbcaxq_u64(b1, b3, b2);
        s[2] = vbcaxq_u64(b2, b4, b3);
        s[3] = vbcaxq_u64(b3, b0, b4);
        s[4] = vbcaxq_u64(b4, b1, b0);
        s[5] = vbcaxq_u64(b5, b7, b6);
        s[6] = vbcaxq_u64(b6, b8, b7);
        s[7] = vbcaxq_u64(b7, b9, b8);
        s[8] = vbcaxq_u64(b8, b5, b9);
        s[9] = vbcaxq_u64(b9, b6, b5);
        s[10] = vbcaxq_u64(b10, b12, b11);
        s[11] = vbcaxq_u64(b11, b13, b12);
        s[12] = vbcaxq_u64(b12, b14, b13);
        s[13] = vbcaxq_u64(b13, b10, b14);
        s[14] = vbcaxq_u64(b14, b11, b10);
        s[15] = vbcaxq_u64(b15, b17, b16);
        s[16] = vbcaxq_u64(b16, b18, b17);
        s[17] = vbcaxq_u64(b17, b19, b18);
        s[18] = vbcaxq_u64(b18, b15, b19);
        s[19] = vbcaxq_u64(b19, b16, b15);
        s[20] = vbcaxq_u64(b20, b22, b21);
        s[21] = vbcaxq_u64(b21, b23, b22);
        s[22] = vbcaxq_u64(b22, b24, b23);
        s[23] = vbcaxq_u64(b23, b20, b24);
        s[24] = vbcaxq_u64(b24, b21, b20);
        // iota
        s[0] = veorq_u64(s[0], vdupq_n_u64(RC[round]));
        }
    }

    /// Two SHAKE sponges advancing in lockstep, one per vector lane.
    ///
    /// Only the short-absorb case is provided, which is all Kyber needs: every
    /// absorbed input (rho‖j‖i for the matrix, sigma‖nonce for the noise) is
    /// well under one rate block.
    pub struct ShakeX2 {
        s: [uint64x2_t; 25],
        rate: usize,
        /// The state holds an unconsumed block until the first squeeze; after
        /// that a permutation is owed before the next one. Deferring it avoids
        /// a wasted permutation when the caller stops squeezing.
        permute_pending: bool,
    }

    impl Drop for ShakeX2 {
        fn drop(&mut self) {
            for lane in self.s.iter_mut() {
                // SAFETY: an all-zero bit pattern is a valid uint64x2_t; the
                // volatile write is not elided.
                unsafe { core::ptr::write_volatile(lane, core::mem::zeroed()) };
            }
        }
    }

    impl ShakeX2 {
        /// Absorb one short message per lane and apply the padding rule.
        ///
        /// # Safety
        /// Requires FEAT_SHA3; `m0` and `m1` must be shorter than `rate`.
        #[target_feature(enable = "sha3")]
        pub unsafe fn new(rate: usize, m0: &[u8], m1: &[u8], domain: u8) -> Self {
            debug_assert!(m0.len() < rate && m1.len() < rate);

            let mut a0 = [0u64; 25];
            let mut a1 = [0u64; 25];
            for (a, m) in [(&mut a0, m0), (&mut a1, m1)] {
                for (i, b) in m.iter().enumerate() {
                    a[i >> 3] ^= (*b as u64) << ((i & 7) * 8);
                }
                a[m.len() >> 3] ^= (domain as u64) << ((m.len() & 7) * 8);
                a[(rate - 1) >> 3] ^= 0x80u64 << (((rate - 1) & 7) * 8);
            }

            let mut s: [uint64x2_t; 25] = [vdupq_n_u64(0); 25];
            for i in 0..25 {
                let pair = [a0[i], a1[i]];
                s[i] = vld1q_u64(pair.as_ptr());
            }
            zeroize::Zeroize::zeroize(&mut a0);
            zeroize::Zeroize::zeroize(&mut a1);
            f1600_x2(&mut s);

            Self { s, rate, permute_pending: false }
        }

        /// Emit the next `rate` bytes for each lane.
        ///
        /// # Safety
        /// Requires FEAT_SHA3; both buffers must be at least `rate` bytes.
        #[target_feature(enable = "sha3")]
        pub unsafe fn squeeze_block(&mut self, out0: &mut [u8], out1: &mut [u8]) {
            if self.permute_pending {
                f1600_x2(&mut self.s);
            }
            self.permute_pending = true;

            for i in 0..self.rate / 8 {
                let lo = vgetq_lane_u64::<0>(self.s[i]).to_le_bytes();
                let hi = vgetq_lane_u64::<1>(self.s[i]).to_le_bytes();
                out0[i * 8..i * 8 + 8].copy_from_slice(&lo);
                out1[i * 8..i * 8 + 8].copy_from_slice(&hi);
            }
        }
    }

    /// Cached FEAT_SHA3 probe.
    pub fn available() -> bool {
        use std::sync::atomic::{AtomicU8, Ordering};
        static CACHE: AtomicU8 = AtomicU8::new(0);
        match CACHE.load(Ordering::Relaxed) {
            0 => {
                let ok = std::arch::is_aarch64_feature_detected!("sha3");
                CACHE.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
                ok
            }
            1 => true,
            _ => false,
        }
    }
}

/// Consume 3-byte groups from `buf` as two 12-bit candidates each, keeping
/// those below q. Returns the updated accepted-coefficient count.
///
/// The SHAKE-128 rate (168) is a multiple of 3, so groups never straddle a
/// block boundary and block-at-a-time consumption yields exactly the same
/// coefficients as consuming one long buffer.
#[inline(always)]
fn absorb_uniform_candidates(buf: &[u8], r: &mut Poly16, mut count: usize) -> usize {
    let mut pos = 0usize;
    while pos + 3 <= buf.len() && count < 256 {
        let d1 = (buf[pos] as u16) | (((buf[pos + 1] as u16) & 0x0F) << 8);
        let d2 = ((buf[pos + 1] as u16) >> 4) | ((buf[pos + 2] as u16) << 4);
        pos += 3;
        if (d1 as i64) < KYBER_Q {
            r[count] = d1 as i16;
            count += 1;
        }
        if (d2 as i64) < KYBER_Q && count < 256 {
            r[count] = d2 as i16;
            count += 1;
        }
    }
    count
}

fn gen_poly_uniform_i16(rho: &[u8; 32], i: u8, j: u8) -> Poly16 {
    // Squeeze one 168-byte block at a time instead of a fixed 1024-byte buffer.
    // The previous version always ran 7 permutations; rejection sampling needs
    // ~3.3 on average. It also read out of bounds, and panicked, if 1024 bytes
    // were not enough.
    let mut sponge = ShakeStream::new(168, &[rho.as_slice(), &[j, i]], 0x1f);
    let mut r = [0i16; 256];
    let mut count = 0usize;
    let mut block = [0u8; 168];
    while count < 256 {
        sponge.squeeze_block(&mut block);
        count = absorb_uniform_candidates(&block, &mut r, count);
    }
    r
}

/// Sample two matrix entries at once through the two-lane SHA3 sponge.
#[cfg(target_arch = "aarch64")]
fn gen_poly_uniform_pair_i16(rho: &[u8; 32], a: (u8, u8), b: (u8, u8)) -> (Poly16, Poly16) {
    if !keccak_x2::available() {
        return (
            gen_poly_uniform_i16(rho, a.0, a.1),
            gen_poly_uniform_i16(rho, b.0, b.1),
        );
    }

    let mut m0 = [0u8; 34];
    let mut m1 = [0u8; 34];
    m0[..32].copy_from_slice(rho);
    m1[..32].copy_from_slice(rho);
    m0[32] = a.1;
    m0[33] = a.0;
    m1[32] = b.1;
    m1[33] = b.0;

    let (mut r0, mut r1) = ([0i16; 256], [0i16; 256]);
    let (mut c0, mut c1) = (0usize, 0usize);
    let (mut b0, mut b1) = ([0u8; 168], [0u8; 168]);

    // SAFETY: FEAT_SHA3 confirmed above; messages are 34 < 168 bytes.
    unsafe {
        let mut sponge = keccak_x2::ShakeX2::new(168, &m0, &m1, 0x1f);
        // Lanes advance together; each keeps only what it still needs.
        while c0 < 256 || c1 < 256 {
            sponge.squeeze_block(&mut b0, &mut b1);
            c0 = absorb_uniform_candidates(&b0, &mut r0, c0);
            c1 = absorb_uniform_candidates(&b1, &mut r1, c1);
        }
    }
    (r0, r1)
}

#[cfg(not(target_arch = "aarch64"))]
fn gen_poly_uniform_pair_i16(rho: &[u8; 32], a: (u8, u8), b: (u8, u8)) -> (Poly16, Poly16) {
    (
        gen_poly_uniform_i16(rho, a.0, a.1),
        gen_poly_uniform_i16(rho, b.0, b.1),
    )
}

fn gen_matrix_i16<const K: usize>(rho: &[u8; 32]) -> [[Poly16; K]; K] {
    // Entries are sampled two at a time in row-major order (the two-way
    // Keccak on aarch64; one at a time elsewhere). With k = 3 the ninth
    // entry is sampled alone.
    let mut a = [[[0i16; 256]; K]; K];
    let n = K * K;
    let mut idx = 0;
    while idx + 1 < n {
        let (i0, j0) = (idx / K, idx % K);
        let (i1, j1) = ((idx + 1) / K, (idx + 1) % K);
        let (p, q) = gen_poly_uniform_pair_i16(rho, (i0 as u8, j0 as u8), (i1 as u8, j1 as u8));
        a[i0][j0] = p;
        a[i1][j1] = q;
        idx += 2;
    }
    if idx < n {
        a[idx / K][idx % K] = gen_poly_uniform_i16(rho, (idx / K) as u8, (idx % K) as u8);
    }
    a
}

/// K polynomials from CBD(η) with nonces `nonce0 .. nonce0 + K`, sampled two
/// at a time where possible.
fn sample_vec_i16<const K: usize>(seed: &[u8; 32], nonce0: u8, eta: u32) -> [Poly16; K] {
    let mut out = [[0i16; 256]; K];
    let mut i = 0;
    while i + 1 < K {
        let (n0, n1) = (nonce0 + i as u8, nonce0 + i as u8 + 1);
        let (a, b) = if eta == 3 {
            prf_cbd3_pair_i16(seed, n0, n1)
        } else {
            prf_cbd_pair_i16(seed, n0, n1)
        };
        out[i] = a;
        out[i + 1] = b;
        i += 2;
    }
    if i < K {
        let n = nonce0 + i as u8;
        out[i] = if eta == 3 { prf_cbd3_i16(seed, n) } else { prf_cbd_i16(seed, n) };
    }
    out
}

// CBD(η=2): returns centered coefficients as i16.
fn cbd_eta2_i16(buf: &[u8; 128]) -> Poly16 {
    let mut r = [0i16; 256];
    for i in 0..32 {
        let t = u32::from_le_bytes([buf[4*i], buf[4*i+1], buf[4*i+2], buf[4*i+3]]);
        let d = (t & 0x55555555).wrapping_add((t >> 1) & 0x55555555);
        for j in 0..8 {
            let a = ((d >> (4*j))     & 0x3) as i16;
            let b = ((d >> (4*j + 2)) & 0x3) as i16;
            r[8*i + j] = a - b;
        }
    }
    r
}

// CBD(η=3), for ML-KEM-512's eta1. Consumes 3 bytes per 4 coefficients:
// 6 bits each, three for `a` and three for `b`, coefficient = popcount(a) - popcount(b).
fn cbd_eta3_i16(buf: &[u8; 192]) -> Poly16 {
    let mut r = [0i16; 256];
    for i in 0..64 {
        let t = (buf[3 * i] as u32) | ((buf[3 * i + 1] as u32) << 8) | ((buf[3 * i + 2] as u32) << 16);
        let mut d = t & 0x0024_9249;
        d += (t >> 1) & 0x0024_9249;
        d += (t >> 2) & 0x0024_9249;
        for j in 0..4 {
            let a = ((d >> (6 * j)) & 0x7) as i16;
            let b = ((d >> (6 * j + 3)) & 0x7) as i16;
            r[4 * i + j] = a - b;
        }
    }
    r
}

/// PRF + CBD with eta = 3 (ML-KEM-512 eta1: used for s, e in KeyGen and r in Encaps).
fn prf_cbd3_i16(sigma: &[u8; 32], nonce: u8) -> Poly16 {
    let mut buf = [0u8; 192];
    shake256(&[sigma.as_slice(), &[nonce]], &mut buf);
    cbd_eta3_i16(&buf)
}

/// PRF + CBD with eta = 2 (ML-KEM-512 eta2: used for e1, e2 in Encaps).
fn prf_cbd_i16(sigma: &[u8; 32], nonce: u8) -> Poly16 {
    let mut buf = [0u8; 128];
    shake256(&[sigma.as_slice(), &[nonce]], &mut buf);
    cbd_eta2_i16(&buf)
}

/// Sample two noise polynomials at once through the two-lane SHA3 sponge.
/// SHAKE-256's rate is 136 and CBD(η=2) needs 128 bytes, so one block per lane.
#[cfg(target_arch = "aarch64")]
fn prf_cbd_pair_i16(sigma: &[u8; 32], n0: u8, n1: u8) -> (Poly16, Poly16) {
    if !keccak_x2::available() {
        return (prf_cbd_i16(sigma, n0), prf_cbd_i16(sigma, n1));
    }

    let mut m0 = [0u8; 33];
    let mut m1 = [0u8; 33];
    m0[..32].copy_from_slice(sigma);
    m1[..32].copy_from_slice(sigma);
    m0[32] = n0;
    m1[32] = n1;

    let mut b0 = [0u8; 136];
    let mut b1 = [0u8; 136];
    // SAFETY: FEAT_SHA3 confirmed above; messages are 33 < 136 bytes.
    unsafe {
        let mut sponge = keccak_x2::ShakeX2::new(136, &m0, &m1, 0x1f);
        sponge.squeeze_block(&mut b0, &mut b1);
    }

    let mut c0 = [0u8; 128];
    let mut c1 = [0u8; 128];
    c0.copy_from_slice(&b0[..128]);
    c1.copy_from_slice(&b1[..128]);
    (cbd_eta2_i16(&c0), cbd_eta2_i16(&c1))
}

#[cfg(not(target_arch = "aarch64"))]
fn prf_cbd_pair_i16(sigma: &[u8; 32], n0: u8, n1: u8) -> (Poly16, Poly16) {
    (prf_cbd_i16(sigma, n0), prf_cbd_i16(sigma, n1))
}

/// Two-lane eta = 3 sampling. 192 bytes per lane spans two SHAKE-256 blocks.
#[cfg(target_arch = "aarch64")]
fn prf_cbd3_pair_i16(sigma: &[u8; 32], n0: u8, n1: u8) -> (Poly16, Poly16) {
    if !keccak_x2::available() {
        return (prf_cbd3_i16(sigma, n0), prf_cbd3_i16(sigma, n1));
    }

    let mut m0 = [0u8; 33];
    let mut m1 = [0u8; 33];
    m0[..32].copy_from_slice(sigma);
    m1[..32].copy_from_slice(sigma);
    m0[32] = n0;
    m1[32] = n1;

    let mut b0 = [0u8; 272]; // 2 x 136
    let mut b1 = [0u8; 272];
    // SAFETY: FEAT_SHA3 confirmed above; messages are 33 < 136 bytes.
    unsafe {
        let mut sponge = keccak_x2::ShakeX2::new(136, &m0, &m1, 0x1f);
        sponge.squeeze_block(&mut b0[..136], &mut b1[..136]);
        sponge.squeeze_block(&mut b0[136..], &mut b1[136..]);
    }

    let mut c0 = [0u8; 192];
    let mut c1 = [0u8; 192];
    c0.copy_from_slice(&b0[..192]);
    c1.copy_from_slice(&b1[..192]);
    (cbd_eta3_i16(&c0), cbd_eta3_i16(&c1))
}

#[cfg(not(target_arch = "aarch64"))]
fn prf_cbd3_pair_i16(sigma: &[u8; 32], n0: u8, n1: u8) -> (Poly16, Poly16) {
    (prf_cbd3_i16(sigma, n0), prf_cbd3_i16(sigma, n1))
}

// matvec: t_hat = A_hat * v_hat (NTT domain, Montgomery basemul).
fn matvec_i16<const K: usize>(a: &[[Poly16; K]; K], v: &[Poly16; K]) -> [Poly16; K] {
    std::array::from_fn(|i| {
        let mut acc = [0i16; 256];
        for j in 0..K { basemul_acc_i16(&mut acc, &a[i][j], &v[j]); }
        acc
    })
}

fn matvec_transpose_i16<const K: usize>(a: &[[Poly16; K]; K], v: &[Poly16; K]) -> [Poly16; K] {
    std::array::from_fn(|i| {
        let mut acc = [0i16; 256];
        for j in 0..K { basemul_acc_i16(&mut acc, &a[j][i], &v[j]); }
        acc
    })
}

fn inner_product_i16<const K: usize>(a: &[Poly16; K], b: &[Poly16; K]) -> Poly16 {
    let mut acc = [0i16; 256];
    for j in 0..K { basemul_acc_i16(&mut acc, &a[j], &b[j]); }
    acc
}

// Polynomial addition (wrapping) — operates on standard or NTT domain.
fn poly_add_i16(a: &Poly16, b: &Poly16) -> Poly16 {
    std::array::from_fn(|i| a[i].wrapping_add(b[i]))
}

fn poly_add_in_place_i16(a: &mut Poly16, b: &Poly16) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x = x.wrapping_add(*y);
    }
}

fn poly_sub_i16(a: &Poly16, b: &Poly16) -> Poly16 {
    std::array::from_fn(|i| a[i].wrapping_sub(b[i]))
}

// Encode 256 12-bit coefficients → 384 bytes.
// Reference C poly_tobytes: normalize negative with (t >> 15) & q trick.
fn poly_to_bytes_i16(p: &Poly16, out: &mut [u8; 384]) {
    for i in 0..128 {
        let mut t0 = p[2*i] as i32;     t0 += (t0 >> 15) & 3329; // make non-negative
        let mut t1 = p[2*i+1] as i32;   t1 += (t1 >> 15) & 3329;
        out[3*i]     = t0 as u8;
        out[3*i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        out[3*i + 2] = (t1 >> 4) as u8;
    }
}

// Compress a i16 polynomial (d bits/coeff) into packed bytes.
// Reference C poly_compress: normalize negative with (t >> 15) & q.
// Compression packs d-bit values back to back, little-endian within each byte.
// Packing a bit at a time costs a read-modify-write of the same output byte on
// every iteration: 2560 serially dependent memory operations for d=10, measured
// at 3.6 µs, which was the most expensive operation in the KEM. The d=10 and d=4
// cases used by Kyber-512 are handled a group at a time in registers instead,
// as in pq-crystals/kyber: 4 coefficients into 5 bytes, or 2 into 1.

/// Round c·2^d / q into d bits, for a possibly-negative centred coefficient.
///
/// The input is secret (it derives from the encapsulation randomness, and in
/// decapsulation from the decrypted message), so the rounding division by q
/// is a fixed-point multiply and shift, as in the pq-crystals reference after
/// KyberSlash: a `/ q` here compiles to a variable-time divide on some
/// targets and optimisation levels. `tests::compress_matches_division` checks
/// the two d values ML-KEM-512/768 use against the division for every input.
#[inline(always)]
fn compress_coeff(c: i16, d: u32) -> u16 {
    let q = KYBER_Q as i32;
    let mut t = c as i32;
    t += (t >> 31) & q; // canonicalise: if t < 0, t += q
    let t = t as u64;
    match d {
        10 => (((((t << 10) + 1665) * 1_290_167) >> 32) & 0x3ff) as u16,
        4 => (((((t << 4) + 1665) * 80_635) >> 28) & 0xf) as u16,
        // Not used by ML-KEM-512/768; kept for the generic encoder.
        _ => ((((t << d) + (q as u64 / 2)) / q as u64) & ((1u64 << d) - 1)) as u16,
    }
}

/// Bit-at-a-time reference packing, kept for `d` values outside Kyber-512's set
/// and as the oracle the equivalence test checks the fast paths against.
fn poly_compress_i16_generic(p: &Poly16, d: u32, out: &mut [u8]) {
    let mut bit_pos = 0usize;
    for &c in p.iter() {
        let compressed = compress_coeff(c, d) as u32;
        for b in 0..d {
            let bit = ((compressed >> b) & 1) as u8;
            out[bit_pos / 8] |= bit << (bit_pos % 8);
            bit_pos += 1;
        }
    }
}

fn poly_compress_i16(p: &Poly16, d: u32, out: &mut [u8]) {
    match d {
        10 => {
            // 4 coefficients -> 5 bytes
            for i in 0..64 {
                let t: [u16; 4] = core::array::from_fn(|k| compress_coeff(p[4 * i + k], 10));
                out[5 * i] = t[0] as u8;
                out[5 * i + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                out[5 * i + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                out[5 * i + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                out[5 * i + 4] = (t[3] >> 2) as u8;
            }
        }
        4 => {
            // 2 coefficients -> 1 byte
            for i in 0..128 {
                let t0 = compress_coeff(p[2 * i], 4);
                let t1 = compress_coeff(p[2 * i + 1], 4);
                out[i] = (t0 | (t1 << 4)) as u8;
            }
        }
        _ => poly_compress_i16_generic(p, d, out),
    }
}

fn poly_decompress_i16_generic(bytes: &[u8], d: u32) -> Poly16 {
    let mut r = [0i16; 256];
    let mut bit_pos = 0usize;
    for c in r.iter_mut() {
        let mut val = 0i32;
        for b in 0..d {
            let bit = ((bytes[bit_pos / 8] >> (bit_pos % 8)) & 1) as i32;
            val |= bit << b;
            bit_pos += 1;
        }
        *c = ((val * KYBER_Q as i32 + (1 << (d - 1))) >> d) as i16;
    }
    r
}

fn poly_decompress_i16(bytes: &[u8], d: u32) -> Poly16 {
    let q = KYBER_Q as u32;
    let mut r = [0i16; 256];
    match d {
        10 => {
            for i in 0..64 {
                let a = &bytes[5 * i..5 * i + 5];
                let t = [
                    (a[0] as u16) | ((a[1] as u16) << 8),
                    ((a[1] as u16) >> 2) | ((a[2] as u16) << 6),
                    ((a[2] as u16) >> 4) | ((a[3] as u16) << 4),
                    ((a[3] as u16) >> 6) | ((a[4] as u16) << 2),
                ];
                for k in 0..4 {
                    r[4 * i + k] = ((((t[k] & 0x3FF) as u32) * q + 512) >> 10) as i16;
                }
            }
        }
        4 => {
            for i in 0..128 {
                r[2 * i] = ((((bytes[i] & 15) as u32) * q + 8) >> 4) as i16;
                r[2 * i + 1] = ((((bytes[i] >> 4) as u32) * q + 8) >> 4) as i16;
            }
        }
        _ => return poly_decompress_i16_generic(bytes, d),
    }
    r
}

fn msg_encode_i16(msg: &[u8; 32]) -> Poly16 {
    let mut r = [0i16; 256];
    for i in 0..32 {
        for j in 0..8 {
            let bit = ((msg[i] >> j) & 1) as i16;
            r[8*i + j] = bit * ((KYBER_Q as i16 + 1) / 2);
        }
    }
    r
}

/// Decode the message bits from `v - s·u`. The input is secret, so there is
/// no division by q (see [`compress_coeff`]); `tests::msg_decode_matches_division`
/// checks every input value against the rounding division.
fn msg_decode_i16(p: &Poly16) -> [u8; 32] {
    let mut msg = [0u8; 32];
    for i in 0..32 {
        for j in 0..8 {
            // v is canonical and s·u is centred, so the difference lies in
            // (-q, 2q). Two masked steps bring it to [0, q) without a branch.
            let mut t = p[8 * i + j] as i32;
            t += (t >> 31) & 3329;
            t -= 3329;
            t += (t >> 31) & 3329;
            // round(2t / q) mod 2 as a fixed-point multiply (pq-crystals).
            let bit = (((((t as u32) << 1) + 1665) * 80_635) >> 28) & 1;
            msg[i] |= (bit as u8) << j;
        }
    }
    msg
}

// ── i16 ML-KEM, generic over the module rank k ──────────────────────────────

fn keygen<const K: usize>(d: &[u8; 32], z: &[u8; 32]) -> SecretKey16<K> {
    // FIPS 203 Alg. 13 (K-PKE.KeyGen): (rho, sigma) = G(d ‖ k). The parameter
    // byte k is the domain separation added in final FIPS 203; round-3 Kyber
    // omitted it. Omitting it produces a non-conformant key.
    let mut g = sha3_512(&[d.as_slice(), &[K as u8]]);
    let mut rho = [0u8; 32]; let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g[..32]); sigma.copy_from_slice(&g[32..]);
    g.zeroize();
    // ρ seeds the public matrix and is published in ek; its rejection
    // sampling is variable-time by design (FIPS 203 SampleNTT).
    declassify(&rho);

    let a_hat = gen_matrix_i16::<K>(&rho);

    // Nonces 0..k for s and k..2k for e, both with η₁. Transformed in place:
    // no copies of the noise polynomials.
    let mut s_hat = sample_vec_i16::<K>(&sigma, 0, eta1(K));
    let mut e_hat = sample_vec_i16::<K>(&sigma, K as u8, eta1(K));
    sigma.zeroize();
    for p in s_hat.iter_mut().chain(e_hat.iter_mut()) {
        ntt_i16(p);
        poly_reduce_i16(p);
    }

    let mut t_hat = matvec_i16(&a_hat, &s_hat);
    for i in 0..K {
        // poly_tomont: multiply each coeff by R mod q = fqmul(c, R²modq=1353)
        // Matches reference C poly_tomont(pkpv.vec[i]) after basemul_acc_montgomery.
        for c in t_hat[i].iter_mut() { *c = fqmul_s(*c, 1353); }
        t_hat[i] = poly_add_i16(&t_hat[i], &e_hat[i]);
        poly_reduce_i16(&mut t_hat[i]);
    }
    e_hat.zeroize();

    // ek is public; it is only hashed here.
    let mut pk_bytes: Vec<u8> = Vec::with_capacity(ek_len(K));
    for i in 0..K {
        let mut enc = [0u8; 384];
        poly_to_bytes_i16(&t_hat[i], &mut enc);
        pk_bytes.extend_from_slice(&enc);
    }
    pk_bytes.extend_from_slice(&rho);
    let h_pk = sha3_256(&[&pk_bytes]);

    // s_hat stays in the NTT domain, as the reference does.
    SecretKey16 {
        s_hat,
        pk: PublicKey16 { t_hat, rho, h_pk },
        z: *z,
    }
}

fn encaps<const K: usize>(pk: &PublicKey16<K>, m: &[u8; 32]) -> (Ciphertext16<K>, [u8; 32]) {
    // FIPS 203 Alg. 17 (ML-KEM.Encaps_internal): (K, r) = G(m ‖ H(ek)).
    // Round-3 Kyber hashed m first; FIPS 203 uses it directly.
    let mut g = sha3_512(&[m.as_slice(), pk.h_pk.as_slice()]);
    let mut k_bar = [0u8; 32]; let mut r_seed = [0u8; 32];
    k_bar.copy_from_slice(&g[..32]); r_seed.copy_from_slice(&g[32..]);
    g.zeroize();

    let a_hat = gen_matrix_i16::<K>(&pk.rho);
    // Nonces 0..k for r (η₁), k..2k for e1 (η₂ = 2), 2k for e2 (η₂).
    let mut r_hat = sample_vec_i16::<K>(&r_seed, 0, eta1(K));
    let mut e1_poly = sample_vec_i16::<K>(&r_seed, K as u8, 2);
    let mut e2 = prf_cbd_i16(&r_seed, 2 * K as u8);
    r_seed.zeroize();
    for p in r_hat.iter_mut() {
        ntt_i16(p);
        poly_reduce_i16(p);
    }

    // u = INTT(Aᵀ·r̂) + e1, computed in place in the accumulator.
    let mut u_poly = matvec_transpose_i16(&a_hat, &r_hat);
    for i in 0..K {
        poly_reduce_i16(&mut u_poly[i]);
        intt_i16(&mut u_poly[i]);
        poly_reduce_i16(&mut u_poly[i]);
        poly_add_in_place_i16(&mut u_poly[i], &e1_poly[i]);
        poly_reduce_i16(&mut u_poly[i]);
    }

    // v = INTT(t̂·r̂) + e2 + Decompress1(m), likewise in place.
    let mut v_poly = inner_product_i16(&pk.t_hat, &r_hat);
    poly_reduce_i16(&mut v_poly);
    intt_i16(&mut v_poly);
    poly_reduce_i16(&mut v_poly);
    poly_add_in_place_i16(&mut v_poly, &e2);
    let mut m_poly = msg_encode_i16(m);
    poly_add_in_place_i16(&mut v_poly, &m_poly);
    poly_reduce_i16(&mut v_poly);
    r_hat.zeroize();
    e1_poly.zeroize();
    e2.zeroize();
    m_poly.zeroize();

    let mut u_enc = [[0u8; 320]; K];
    for i in 0..K {
        poly_compress_i16(&u_poly[i], 10, &mut u_enc[i]);
    }
    let mut v_enc = [0u8; 128];
    poly_compress_i16(&v_poly, 4, &mut v_enc);
    // The uncompressed ciphertext carries more about r than the public
    // compressed one does.
    u_poly.zeroize();
    v_poly.zeroize();

    // FIPS 203: the shared secret is K as produced by G. Round-3 Kyber applied
    // a final KDF(K ‖ H(c)); FIPS 203 removed it.
    (Ciphertext16 { u_enc, v_enc }, k_bar)
}

fn decaps<const K: usize>(sk: &SecretKey16<K>, ct: &Ciphertext16<K>) -> [u8; 32] {
    let u_hat: [Poly16; K] = std::array::from_fn(|i| {
        let mut p = poly_decompress_i16(&ct.u_enc[i], 10);
        ntt_i16(&mut p); poly_reduce_i16(&mut p); p
    });
    let v_poly = poly_decompress_i16(&ct.v_enc, 4);

    let mut su_hat = inner_product_i16(&sk.s_hat, &u_hat);
    poly_reduce_i16(&mut su_hat);
    intt_i16(&mut su_hat);
    poly_reduce_i16(&mut su_hat);

    let mut w = poly_sub_i16(&v_poly, &su_hat);
    let mut m_prime = msg_decode_i16(&w);
    w.zeroize();
    su_hat.zeroize();
    let (ct_prime, mut ss_prime) = encaps(&sk.pk, &m_prime);
    m_prime.zeroize();

    // FIPS 203 Alg. 18 (ML-KEM.Decaps_internal), the implicit-rejection step:
    // the result is K' only if the re-encryption reproduces c byte for byte.
    //
    // The comparison and the selection go through `subtle`, so the compiler
    // cannot turn either into a branch, and the whole ciphertext contributes
    // to a single all-or-nothing choice. (An earlier version derived a mask
    // per byte with `!(a ^ b).wrapping_neg()`, which equals `(a ^ b) - 1` and
    // is only all-zero when the bytes differ in exactly bit 0; any other
    // difference blended bits of K' into the rejection key.)
    let mut same = Choice::from(1u8);
    for i in 0..K {
        same &= ct.u_enc[i].ct_eq(&ct_prime.u_enc[i]);
    }
    same &= ct.v_enc.ct_eq(&ct_prime.v_enc);

    // The implicit-rejection key is J(z ‖ c) = SHAKE256(z ‖ c, 32) over the
    // whole ciphertext — not a SHA3-256 of z with a hash of c, which is what
    // round-3 Kyber did.
    let ct_bytes = ct_to_bytes(ct);
    let mut ss_reject = [0u8; 32];
    shake256(&[sk.z.as_slice(), &ct_bytes], &mut ss_reject);

    let mut ss = [0u8; 32];
    for i in 0..32 {
        ss[i] = u8::conditional_select(&ss_reject[i], &ss_prime[i], same);
    }
    ss_prime.zeroize();
    ss_reject.zeroize();
    ss
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rounding division the fixed-point forms replace.
    fn compress_by_division(c: i16, d: u32) -> u16 {
        let mut t = c as i64;
        if t < 0 { t += KYBER_Q; }
        (((t << d) + KYBER_Q / 2) / KYBER_Q & ((1 << d) - 1)) as u16
    }

    #[test]
    fn compress_matches_division() {
        for d in [10u32, 4] {
            for c in -(KYBER_Q as i16) + 1..KYBER_Q as i16 {
                assert_eq!(compress_coeff(c, d), compress_by_division(c, d), "d = {d}, c = {c}");
            }
        }
    }

    #[test]
    fn msg_decode_matches_division() {
        // `v - s·u` lies in (-q, 2q). Check every value in that range by
        // placing it at coefficient 0 and reading bit 0 of the message.
        for v in -(KYBER_Q as i32) + 1..2 * KYBER_Q as i32 {
            let mut p = [0i16; 256];
            p[0] = v as i16;
            let got = msg_decode_i16(&p)[0] & 1;
            let mut t = v as i64;
            if t < 0 { t += KYBER_Q; }
            if t >= KYBER_Q { t -= KYBER_Q; }
            let want = (((2 * t + KYBER_Q / 2) / KYBER_Q) & 1) as u8;
            assert_eq!(got, want, "v = {v}");
        }
    }

    /// Any single-bit change to a ciphertext that still decrypts to the same
    /// message must give exactly J(z ‖ c'), with no bits of K' mixed in.
    /// This is the case the previous per-byte mask got wrong.
    #[test]
    fn implicit_rejection_is_all_or_nothing() {
        fn check<const K: usize>() {
            let d = [0x11u8; 32];
            let z = [0x22u8; 32];
            let m = [0x33u8; 32];
            let sk = keygen::<K>(&d, &z);
            let (ct, k_real) = encaps(&sk.pk, &m);
            assert_eq!(decaps(&sk, &ct), k_real);
            let c = ct_to_bytes(&ct);
            for pos in [0usize, 1, 7, 320 * K - 1, 320 * K, 320 * K + 127] {
                for bit in 0..8 {
                    let mut c2 = c.clone();
                    c2[pos] ^= 1 << bit;
                    let got = decaps(&sk, &ct_from_bytes::<K>(&c2));
                    let mut want = [0u8; 32];
                    shake256(&[&z, &c2], &mut want);
                    assert_eq!(got, want, "K = {K}, byte {pos}, bit {bit}");
                    assert_ne!(got, k_real);
                }
            }
        }
        check::<2>();
        check::<3>();
    }
}
