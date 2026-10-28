//! Keccak-f[1600], the SHA-3 hashes and the SHAKE XOFs (FIPS 202), shared by
//! [`crate::kem`] (ML-KEM, FIPS 203) and [`crate::dsa`] (ML-DSA, FIPS 204).
//!
//! The permutation is the inline XKCP translation that used to live in
//! `src/kem.rs`; moving it here changed no code. On AArch64 with FEAT_SHA3,
//! [`keccak_x2`] runs two independent sponges in the two lanes of each
//! vector register.
//!
//! Every sponge state is wiped when it goes out of scope: [`keccak_sponge`]
//! zeroizes its state before returning, and [`ShakeStream`] and
//! [`keccak_x2::ShakeX2`] zeroize theirs on drop.

// Some helpers are used only on aarch64 (NEON) or only on other targets.
#![allow(dead_code)]
#![allow(clippy::needless_range_loop)]

use zeroize::Zeroize;

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
#[rustfmt::skip]
pub(crate) fn keccak_f1600(s: &mut [u64; 25]) {

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
        s[i] ^= u64::from_le_bytes(data[8 * i..8 * i + 8].try_into().unwrap());
    }
}

#[inline]
fn extract_bytes(s: &[u64; 25], out: &mut [u8]) {
    let full = out.len() / 8;
    for i in 0..full {
        out[8 * i..8 * i + 8].copy_from_slice(&s[i].to_le_bytes());
    }
    let rem = out.len() & 7;
    if rem > 0 {
        let lane = s[full].to_le_bytes();
        out[full * 8..].copy_from_slice(&lane[..rem]);
    }
}

/// Absorb `inputs` into a fresh Keccak state, pad with `domain`, permute, squeeze.
pub(crate) fn keccak_sponge(rate: usize, inputs: &[&[u8]], domain: u8, output: &mut [u8]) {
    let mut s = [0u64; 25];
    let lane_rate = rate / 8; // rate is always a multiple of 8 for SHA3/SHAKE
    let mut pos = 0usize; // byte offset within current rate block

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
pub(crate) struct ShakeStream {
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
    pub(crate) fn new(rate: usize, inputs: &[&[u8]], domain: u8) -> Self {
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
        Self {
            s,
            rate,
            permute_pending: false,
        }
    }

    pub(crate) fn squeeze_block(&mut self, out: &mut [u8]) {
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

pub(crate) fn sha3_256(inputs: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    keccak_sponge(136, inputs, 0x06, &mut out);
    out
}

pub(crate) fn sha3_512(inputs: &[&[u8]]) -> [u8; 64] {
    let mut out = [0u8; 64];
    keccak_sponge(72, inputs, 0x06, &mut out);
    out
}

pub(crate) fn shake128(inputs: &[&[u8]], output: &mut [u8]) {
    keccak_sponge(168, inputs, 0x1f, output);
}

pub(crate) fn shake256(inputs: &[&[u8]], output: &mut [u8]) {
    keccak_sponge(136, inputs, 0x1f, output);
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
pub(crate) mod keccak_x2 {
    use std::arch::aarch64::*;

    #[rustfmt::skip]
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

            Self {
                s,
                rate,
                permute_pending: false,
            }
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
