//! Full Kyber-512 KEM Benchmark — end-to-end including hashing and encoding
//!
//! Uses an inline pure-Rust Keccak-f[1600] sponge translated from the XKCP plain-64bit
//! implementation (KeccakP-1600-opt64.c + KeccakP-1600-64.macros, public domain).
//!
//! The XKCP path was chosen because:
//! - LibOQS's Homebrew bottle uses the same OpenSSL EVP path we tried before — same cost.
//! - OpenSSL 3.x provider dispatch adds ~140 ns/call overhead (39 calls × 140 ns ≈ 5.5 µs).
//! - The sha3 Rust crate uses an external crate boundary that may limit LTO inlining.
//! - Inline Keccak in the same translation unit lets LLVM inline all 24 rounds, optimise
//!   across absorb/squeeze boundaries, and track register allocation across KEM operations.
//!
//! Operations performed (matching LibOQS ML-KEM-512):
//! - SHAKE-128 matrix A generation (k²=4 calls with rejection sampling)
//! - SHAKE-256 + CBD(η=2) for secrets s, e, r
//! - SHA3-512 for G() key derivation seed expansion
//! - SHA3-256 for H() (key hashing, ciphertext hashing, shared secret)
//! - Polynomial encoding (12-bit coefficients → 384 bytes)
//! - Polynomial compression (10-bit u, 4-bit v)
//! - Full keygen, encaps, decaps with re-encryption in decaps

use moduletto::ntt::{KyberCoeff, NTTConstants, NTTPoly, KYBER_N, KYBER_Q};
use sha3::digest::{ExtendableOutput, FixedOutput, Update, XofReader};
use sha3::{Sha3_256 as Sha3_256Hw, Sha3_512 as Sha3_512Hw, Shake128 as Shake128Hw, Shake256 as Shake256Hw};
use std::time::Instant;

const KYBER_K: usize = 2; // Kyber-512

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

// ── sha3 asm-accelerated hash wrappers (ARM64 SHA3 hardware path) ────────────

fn sha3_256_hw(inputs: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256Hw::default();
    for &d in inputs { h.update(d); }
    h.finalize_fixed().into()
}

fn sha3_512_hw(inputs: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha3_512Hw::default();
    for &d in inputs { h.update(d); }
    h.finalize_fixed().into()
}

fn shake128_hw(inputs: &[&[u8]], output: &mut [u8]) {
    let mut h = Shake128Hw::default();
    for &d in inputs { h.update(d); }
    h.finalize_xof().read(output);
}

fn shake256_hw(inputs: &[&[u8]], output: &mut [u8]) {
    let mut h = Shake256Hw::default();
    for &d in inputs { h.update(d); }
    h.finalize_xof().read(output);
}

// ── Kyber operations parameterized on hash backend ────────────────────────────

fn prf_cbd_hw(sigma: &[u8; 32], nonce: u8) -> NTTPoly {
    let mut buf = [0u8; 128];
    shake256_hw(&[sigma.as_slice(), &[nonce]], &mut buf);
    cbd_eta2(&buf)
}

fn gen_poly_uniform_hw(rho: &[u8; 32], i: u8, j: u8) -> NTTPoly {
    let mut buf = [0u8; 1024];
    shake128_hw(&[rho.as_slice(), &[j, i]], &mut buf);
    let mut coeffs = [KyberCoeff::zero(); KYBER_N];
    let mut count = 0;
    let mut pos = 0;
    while count < KYBER_N {
        let d1 = (buf[pos] as i64) | ((buf[pos + 1] as i64 & 0x0F) << 8);
        let d2 = (buf[pos + 1] as i64 >> 4) | ((buf[pos + 2] as i64) << 4);
        pos += 3;
        if d1 < KYBER_Q && count < KYBER_N { coeffs[count] = KyberCoeff::new(d1); count += 1; }
        if d2 < KYBER_Q && count < KYBER_N { coeffs[count] = KyberCoeff::new(d2); count += 1; }
    }
    NTTPoly::new(coeffs)
}

fn gen_matrix_hw(rho: &[u8; 32]) -> [[NTTPoly; KYBER_K]; KYBER_K] {
    std::array::from_fn(|i| std::array::from_fn(|j| gen_poly_uniform_hw(rho, i as u8, j as u8)))
}

fn kyber_keygen_hw(seed: &[u8; 32], consts: &NTTConstants) -> SecretKey {
    let g = sha3_512_hw(&[seed.as_slice()]);
    let mut rho = [0u8; 32]; let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g[..32]); sigma.copy_from_slice(&g[32..]);
    let a_hat = gen_matrix_hw(&rho);
    let mut nonce = 0u8;
    let s_poly: [NTTPoly; KYBER_K] = std::array::from_fn(|_| { let p = prf_cbd_hw(&sigma, nonce); nonce += 1; p });
    let e_poly: [NTTPoly; KYBER_K] = std::array::from_fn(|_| { let p = prf_cbd_hw(&sigma, nonce); nonce += 1; p });
    let s_hat: [NTTPoly; KYBER_K] = std::array::from_fn(|i| s_poly[i].ntt());
    let e_hat: [NTTPoly; KYBER_K] = std::array::from_fn(|i| e_poly[i].ntt());
    let mut t_hat = matvec(&a_hat, &s_hat, consts);
    for i in 0..KYBER_K { t_hat[i] = t_hat[i].add(&e_hat[i]); }
    let mut pk_bytes: Vec<u8> = Vec::with_capacity(KYBER_K * 384 + 32);
    for i in 0..KYBER_K { let mut enc = [0u8; 384]; poly_to_bytes(&t_hat[i], &mut enc); pk_bytes.extend_from_slice(&enc); }
    pk_bytes.extend_from_slice(&rho);
    let h_pk = sha3_256_hw(&[&pk_bytes]);
    SecretKey { s_hat, pk: PublicKey { t_hat, rho, h_pk }, z: [0u8; 32] }
}

fn kyber_encaps_hw(pk: &PublicKey, m: &[u8; 32], consts: &NTTConstants) -> (Ciphertext, [u8; 32]) {
    let h_m = sha3_256_hw(&[m.as_slice()]);
    let g = sha3_512_hw(&[h_m.as_slice(), pk.h_pk.as_slice()]);
    let mut k_bar = [0u8; 32]; let mut r_seed = [0u8; 32];
    k_bar.copy_from_slice(&g[..32]); r_seed.copy_from_slice(&g[32..]);
    let a_hat = gen_matrix_hw(&pk.rho);
    let mut nonce = 0u8;
    let r_poly: [NTTPoly; KYBER_K] = std::array::from_fn(|_| { let p = prf_cbd_hw(&r_seed, nonce); nonce += 1; p });
    let e1_poly: [NTTPoly; KYBER_K] = std::array::from_fn(|_| { let p = prf_cbd_hw(&r_seed, nonce); nonce += 1; p });
    let e2 = prf_cbd_hw(&r_seed, nonce);
    let r_hat: [NTTPoly; KYBER_K] = std::array::from_fn(|i| r_poly[i].ntt());
    let u_hat = matvec_transpose(&a_hat, &r_hat, consts);
    let u_poly: [NTTPoly; KYBER_K] = std::array::from_fn(|i| u_hat[i].intt().add(&e1_poly[i]));
    let v_hat = inner_product(&pk.t_hat, &r_hat, consts);
    let v_poly = v_hat.intt().add(&e2).add(&msg_encode(m));
    let u_enc: [[u8; 320]; KYBER_K] = std::array::from_fn(|i| { let mut buf = [0u8; 320]; poly_compress(&u_poly[i], 10, &mut buf); buf });
    let mut v_enc = [0u8; 128]; poly_compress(&v_poly, 4, &mut v_enc);
    let mut ct_bytes: Vec<u8> = Vec::with_capacity(KYBER_K * 320 + 128);
    for ue in &u_enc { ct_bytes.extend_from_slice(ue.as_slice()); }
    ct_bytes.extend_from_slice(&v_enc);
    let h_c = sha3_256_hw(&[&ct_bytes]);
    let ss = sha3_256_hw(&[k_bar.as_slice(), h_c.as_slice()]);
    (Ciphertext { u_enc, v_enc }, ss)
}

fn kyber_decaps_hw(sk: &SecretKey, ct: &Ciphertext, consts: &NTTConstants) -> [u8; 32] {
    let u_poly: [NTTPoly; KYBER_K] = std::array::from_fn(|i| poly_decompress(&ct.u_enc[i], 10));
    let v_poly = poly_decompress(&ct.v_enc, 4);
    let u_hat: [NTTPoly; KYBER_K] = std::array::from_fn(|i| u_poly[i].ntt());
    let su_hat = inner_product(&sk.s_hat, &u_hat, consts);
    let m_prime = msg_decode(&v_poly.sub(&su_hat.intt()));
    let (ct_prime, ss_prime) = kyber_encaps_hw(&sk.pk, &m_prime, consts);
    let mut eq: u8 = 0xFF;
    for i in 0..KYBER_K { for (a, b) in ct.u_enc[i].iter().zip(ct_prime.u_enc[i].iter()) { eq &= !(a ^ b).wrapping_neg(); } }
    for (a, b) in ct.v_enc.iter().zip(ct_prime.v_enc.iter()) { eq &= !(a ^ b).wrapping_neg(); }
    let mut ct_bytes: Vec<u8> = Vec::with_capacity(KYBER_K * 320 + 128);
    for ue in &ct.u_enc { ct_bytes.extend_from_slice(ue.as_slice()); }
    ct_bytes.extend_from_slice(&ct.v_enc);
    let h_c = sha3_256_hw(&[&ct_bytes]);
    let ss_reject = sha3_256_hw(&[sk.z.as_slice(), h_c.as_slice()]);
    let mask = eq;
    let mut ss = [0u8; 32];
    for i in 0..32 { ss[i] = (ss_prime[i] & mask) | (ss_reject[i] & !mask); }
    ss
}

// ── Basemul helpers (amortized NTT approach) ─────────────────────────────────

fn basemul_acc(acc: &mut [KyberCoeff; KYBER_N], a: &[KyberCoeff; KYBER_N], b: &[KyberCoeff; KYBER_N], consts: &NTTConstants) {
    for i in (0..KYBER_N).step_by(2) {
        let zeta = consts.zetas[128 + i / 2];
        let a0 = a[i];     let a1 = a[i + 1];
        let b0 = b[i];     let b1 = b[i + 1];
        acc[i]     = acc[i]     + a0 * b0 + zeta * a1 * b1;
        acc[i + 1] = acc[i + 1] + a0 * b1 + a1 * b0;
    }
}

fn matvec(a_hat: &[[NTTPoly; KYBER_K]; KYBER_K], v_hat: &[NTTPoly; KYBER_K], consts: &NTTConstants) -> [NTTPoly; KYBER_K] {
    let mut result: [NTTPoly; KYBER_K] = std::array::from_fn(|_| NTTPoly::zero());
    for i in 0..KYBER_K {
        for j in 0..KYBER_K {
            basemul_acc(&mut result[i].coeffs, &a_hat[i][j].coeffs, &v_hat[j].coeffs, consts);
        }
    }
    result
}

fn matvec_transpose(a_hat: &[[NTTPoly; KYBER_K]; KYBER_K], v_hat: &[NTTPoly; KYBER_K], consts: &NTTConstants) -> [NTTPoly; KYBER_K] {
    let mut result: [NTTPoly; KYBER_K] = std::array::from_fn(|_| NTTPoly::zero());
    for i in 0..KYBER_K {
        for j in 0..KYBER_K {
            basemul_acc(&mut result[i].coeffs, &a_hat[j][i].coeffs, &v_hat[j].coeffs, consts);
        }
    }
    result
}

fn inner_product(a_hat: &[NTTPoly; KYBER_K], b_hat: &[NTTPoly; KYBER_K], consts: &NTTConstants) -> NTTPoly {
    let mut acc = NTTPoly::zero();
    for j in 0..KYBER_K {
        basemul_acc(&mut acc.coeffs, &a_hat[j].coeffs, &b_hat[j].coeffs, consts);
    }
    acc
}

// ── SHAKE-128 matrix generation ───────────────────────────────────────────────

fn gen_poly_uniform(rho: &[u8; 32], i: u8, j: u8) -> NTTPoly {
    let mut buf = [0u8; 1024]; // 3× average needed; P(need more) ≈ 10^-200
    shake128(&[rho.as_slice(), &[j, i]], &mut buf);

    let mut coeffs = [KyberCoeff::zero(); KYBER_N];
    let mut count = 0;
    let mut pos = 0;

    while count < KYBER_N {
        assert!(pos + 2 < buf.len(), "SHAKE-128 buffer exhausted");
        let d1 = (buf[pos] as i64) | ((buf[pos + 1] as i64 & 0x0F) << 8);
        let d2 = (buf[pos + 1] as i64 >> 4) | ((buf[pos + 2] as i64) << 4);
        pos += 3;
        if d1 < KYBER_Q && count < KYBER_N { coeffs[count] = KyberCoeff::new(d1); count += 1; }
        if d2 < KYBER_Q && count < KYBER_N { coeffs[count] = KyberCoeff::new(d2); count += 1; }
    }
    NTTPoly::new(coeffs) // already in NTT domain
}

fn gen_matrix(rho: &[u8; 32]) -> [[NTTPoly; KYBER_K]; KYBER_K] {
    std::array::from_fn(|i| std::array::from_fn(|j| gen_poly_uniform(rho, i as u8, j as u8)))
}

// ── CBD(η=2) sampling ─────────────────────────────────────────────────────────

fn cbd_eta2(buf: &[u8; 128]) -> NTTPoly {
    let mut coeffs = [KyberCoeff::zero(); KYBER_N];
    for i in 0..(KYBER_N / 8) {
        let t = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
        let d = (t & 0x55555555) + ((t >> 1) & 0x55555555);
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i64;
            let b = ((d >> (4 * j + 2)) & 0x3) as i64;
            coeffs[8 * i + j] = KyberCoeff::new(((a - b) + KYBER_Q) % KYBER_Q);
        }
    }
    NTTPoly::new(coeffs)
}

fn prf_cbd(sigma: &[u8; 32], nonce: u8) -> NTTPoly {
    let mut buf = [0u8; 128];
    shake256(&[sigma.as_slice(), &[nonce]], &mut buf);
    cbd_eta2(&buf)
}

// ── Polynomial encoding / compression ────────────────────────────────────────

fn poly_to_bytes(p: &NTTPoly, out: &mut [u8; 384]) {
    for i in 0..128 {
        let t0 = p.coeffs[2 * i].value() as u16;
        let t1 = p.coeffs[2 * i + 1].value() as u16;
        out[3 * i]     = t0 as u8;
        out[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        out[3 * i + 2] = (t1 >> 4) as u8;
    }
}

fn poly_compress(p: &NTTPoly, d: u32, out: &mut [u8]) {
    let mut bit_pos = 0usize;
    for coeff in &p.coeffs {
        let x = coeff.value();
        let compressed = ((x * (1i64 << d) + KYBER_Q / 2) / KYBER_Q) & ((1i64 << d) - 1);
        for b in 0..d {
            let bit = ((compressed >> b) & 1) as u8;
            out[bit_pos / 8] |= bit << (bit_pos % 8);
            bit_pos += 1;
        }
    }
}

fn poly_decompress(bytes: &[u8], d: u32) -> NTTPoly {
    let mut coeffs = [KyberCoeff::zero(); KYBER_N];
    let mut bit_pos = 0usize;
    for coeff in &mut coeffs {
        let mut val = 0i64;
        for b in 0..d {
            let bit = ((bytes[bit_pos / 8] >> (bit_pos % 8)) & 1) as i64;
            val |= bit << b;
            bit_pos += 1;
        }
        *coeff = KyberCoeff::new((val * KYBER_Q + (1 << (d - 1))) >> d);
    }
    NTTPoly::new(coeffs)
}

fn msg_encode(msg: &[u8; 32]) -> NTTPoly {
    let mut coeffs = [KyberCoeff::zero(); KYBER_N];
    for i in 0..32 {
        for j in 0..8 {
            let bit = ((msg[i] >> j) & 1) as i64;
            coeffs[8 * i + j] = KyberCoeff::new(bit * ((KYBER_Q + 1) / 2));
        }
    }
    NTTPoly::new(coeffs)
}

fn msg_decode(p: &NTTPoly) -> [u8; 32] {
    let mut msg = [0u8; 32];
    for i in 0..32 {
        for j in 0..8 {
            let v = p.coeffs[8 * i + j].value();
            let bit = ((2 * v + KYBER_Q / 2) / KYBER_Q) & 1;
            msg[i] |= (bit as u8) << j;
        }
    }
    msg
}

// ── Key types ─────────────────────────────────────────────────────────────────

struct PublicKey {
    t_hat: [NTTPoly; KYBER_K],
    rho:   [u8; 32],
    h_pk:  [u8; 32],
}

struct SecretKey {
    s_hat: [NTTPoly; KYBER_K],
    pk:    PublicKey,
    z:     [u8; 32],
}

struct Ciphertext {
    u_enc: [[u8; 320]; KYBER_K],
    v_enc: [u8; 128],
}

// ── Key generation ────────────────────────────────────────────────────────────

fn kyber_keygen(seed: &[u8; 32], consts: &NTTConstants) -> SecretKey {
    let g = sha3_512(&[seed.as_slice()]);
    let mut rho   = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    sigma.copy_from_slice(&g[32..]);

    let a_hat = gen_matrix(&rho);

    let mut nonce = 0u8;
    let s_poly: [NTTPoly; KYBER_K] = std::array::from_fn(|_| { let p = prf_cbd(&sigma, nonce); nonce += 1; p });
    let e_poly: [NTTPoly; KYBER_K] = std::array::from_fn(|_| { let p = prf_cbd(&sigma, nonce); nonce += 1; p });

    let s_hat: [NTTPoly; KYBER_K] = std::array::from_fn(|i| s_poly[i].ntt());
    let e_hat: [NTTPoly; KYBER_K] = std::array::from_fn(|i| e_poly[i].ntt());

    let mut t_hat = matvec(&a_hat, &s_hat, consts);
    for i in 0..KYBER_K {
        t_hat[i] = t_hat[i].add(&e_hat[i]);
    }

    let mut pk_bytes: Vec<u8> = Vec::with_capacity(KYBER_K * 384 + 32);
    for i in 0..KYBER_K {
        let mut enc = [0u8; 384];
        poly_to_bytes(&t_hat[i], &mut enc);
        pk_bytes.extend_from_slice(&enc);
    }
    pk_bytes.extend_from_slice(&rho);
    let h_pk = sha3_256(&[&pk_bytes]);

    SecretKey {
        s_hat,
        pk: PublicKey { t_hat, rho, h_pk },
        z: [0u8; 32],
    }
}

// ── Encapsulation ─────────────────────────────────────────────────────────────

fn kyber_encaps_inner(pk: &PublicKey, m: &[u8; 32], consts: &NTTConstants) -> (Ciphertext, [u8; 32]) {
    let h_m = sha3_256(&[m.as_slice()]);
    let g   = sha3_512(&[h_m.as_slice(), pk.h_pk.as_slice()]);
    let mut k_bar  = [0u8; 32];
    let mut r_seed = [0u8; 32];
    k_bar.copy_from_slice(&g[..32]);
    r_seed.copy_from_slice(&g[32..]);

    let a_hat = gen_matrix(&pk.rho);

    let mut nonce = 0u8;
    let r_poly:  [NTTPoly; KYBER_K] = std::array::from_fn(|_| { let p = prf_cbd(&r_seed, nonce); nonce += 1; p });
    let e1_poly: [NTTPoly; KYBER_K] = std::array::from_fn(|_| { let p = prf_cbd(&r_seed, nonce); nonce += 1; p });
    let e2 = prf_cbd(&r_seed, nonce);

    let r_hat: [NTTPoly; KYBER_K] = std::array::from_fn(|i| r_poly[i].ntt());

    let u_hat  = matvec_transpose(&a_hat, &r_hat, consts);
    let u_poly: [NTTPoly; KYBER_K] = std::array::from_fn(|i| u_hat[i].intt().add(&e1_poly[i]));

    let v_hat  = inner_product(&pk.t_hat, &r_hat, consts);
    let v_poly = v_hat.intt().add(&e2).add(&msg_encode(m));

    let u_enc: [[u8; 320]; KYBER_K] = std::array::from_fn(|i| {
        let mut buf = [0u8; 320];
        poly_compress(&u_poly[i], 10, &mut buf);
        buf
    });
    let mut v_enc = [0u8; 128];
    poly_compress(&v_poly, 4, &mut v_enc);

    let mut ct_bytes: Vec<u8> = Vec::with_capacity(KYBER_K * 320 + 128);
    for ue in &u_enc { ct_bytes.extend_from_slice(ue.as_slice()); }
    ct_bytes.extend_from_slice(&v_enc);
    let h_c = sha3_256(&[&ct_bytes]);
    let ss  = sha3_256(&[k_bar.as_slice(), h_c.as_slice()]);

    (Ciphertext { u_enc, v_enc }, ss)
}

// ── Decapsulation ─────────────────────────────────────────────────────────────

fn kyber_decaps(sk: &SecretKey, ct: &Ciphertext, consts: &NTTConstants) -> [u8; 32] {
    let u_poly: [NTTPoly; KYBER_K] = std::array::from_fn(|i| poly_decompress(&ct.u_enc[i], 10));
    let v_poly = poly_decompress(&ct.v_enc, 4);

    let u_hat: [NTTPoly; KYBER_K] = std::array::from_fn(|i| u_poly[i].ntt());
    let su_hat = inner_product(&sk.s_hat, &u_hat, consts);
    let m_prime = msg_decode(&v_poly.sub(&su_hat.intt()));

    let (ct_prime, ss_prime) = kyber_encaps_inner(&sk.pk, &m_prime, consts);

    let mut eq: u8 = 0xFF;
    for i in 0..KYBER_K {
        for (a, b) in ct.u_enc[i].iter().zip(ct_prime.u_enc[i].iter()) {
            eq &= !(a ^ b).wrapping_neg();
        }
    }
    for (a, b) in ct.v_enc.iter().zip(ct_prime.v_enc.iter()) {
        eq &= !(a ^ b).wrapping_neg();
    }

    let mut ct_bytes: Vec<u8> = Vec::with_capacity(KYBER_K * 320 + 128);
    for ue in &ct.u_enc { ct_bytes.extend_from_slice(ue.as_slice()); }
    ct_bytes.extend_from_slice(&ct.v_enc);
    let h_c = sha3_256(&[&ct_bytes]);
    let ss_reject = sha3_256(&[sk.z.as_slice(), h_c.as_slice()]);

    let mask = eq;
    let mut ss = [0u8; 32];
    for i in 0..32 {
        ss[i] = (ss_prime[i] & mask) | (ss_reject[i] & !mask);
    }
    ss
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

    // Forward NTT with NEON for len ≥ 8, scalar for len < 8.
    #[target_feature(enable = "neon")]
    pub unsafe fn ntt_i16_neon_inner(r: &mut [i16; 256]) {
        let mut k: usize = 1;
        let mut len: usize = 128;
        while len >= 2 {
            let mut start = 0usize;
            while start < 256 {
                let zeta_val = ZETAS_I16[k]; k += 1;
                if len >= 8 {
                    let zeta_vec = vdupq_n_s16(zeta_val);
                    let mut j = start;
                    while j < start + len {
                        let top = vld1q_s16(r.as_ptr().add(j));
                        let bot = vld1q_s16(r.as_ptr().add(j + len));
                        let t = fqmul_vec(zeta_vec, bot);
                        vst1q_s16(r.as_mut_ptr().add(j + len), vsubq_s16(top, t));
                        vst1q_s16(r.as_mut_ptr().add(j), vaddq_s16(top, t));
                        j += 8;
                    }
                } else {
                    for j in start..start + len {
                        let t = super::fqmul_s(zeta_val, r[j + len]);
                        r[j + len] = r[j].wrapping_sub(t);
                        r[j] = r[j].wrapping_add(t);
                    }
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    // Inverse NTT with NEON for len ≥ 8, scalar for len < 8.
    #[target_feature(enable = "neon")]
    pub unsafe fn intt_i16_neon_inner(r: &mut [i16; 256]) {
        let mut k: usize = 127;
        let mut len: usize = 2;
        while len <= 128 {
            let mut start = 0usize;
            while start < 256 {
                let zeta_val = ZETAS_I16[k];
                if k > 0 { k -= 1; }
                if len >= 8 {
                    let zeta_vec = vdupq_n_s16(zeta_val);
                    let mut j = start;
                    while j < start + len {
                        let top = vld1q_s16(r.as_ptr().add(j));
                        let bot = vld1q_s16(r.as_ptr().add(j + len));
                        let sum   = barrett_vec(vaddq_s16(top, bot));
                        let diff  = vsubq_s16(bot, top);
                        let scaled = fqmul_vec(zeta_vec, diff);
                        vst1q_s16(r.as_mut_ptr().add(j), sum);
                        vst1q_s16(r.as_mut_ptr().add(j + len), scaled);
                        j += 8;
                    }
                } else {
                    for j in start..start + len {
                        let t = r[j];
                        r[j] = super::barrett_s(t.wrapping_add(r[j + len]));
                        r[j + len] = super::fqmul_s(zeta_val, r[j + len].wrapping_sub(t));
                    }
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

struct SecretKey16 {
    s_hat: [Poly16; KYBER_K],
    pk: PublicKey16,
    z: [u8; 32],
}

struct PublicKey16 {
    t_hat: [Poly16; KYBER_K],
    rho: [u8; 32],
    h_pk: [u8; 32],
}

struct Ciphertext16 {
    u_enc: [[u8; 320]; KYBER_K],
    v_enc: [u8; 128],
}

// ── i16 KEM helper functions ──────────────────────────────────────────────────

// Uniform sampling in NTT domain [0,q-1], stored as i16.
fn gen_poly_uniform_i16(rho: &[u8; 32], i: u8, j: u8) -> Poly16 {
    let mut buf = [0u8; 1024];
    shake128(&[rho.as_slice(), &[j, i]], &mut buf);
    let mut r = [0i16; 256];
    let mut count = 0;
    let mut pos = 0;
    while count < 256 {
        let d1 = (buf[pos] as u16) | (((buf[pos+1] as u16) & 0x0F) << 8);
        let d2 = (buf[pos+1] as u16 >> 4) | ((buf[pos+2] as u16) << 4);
        pos += 3;
        if (d1 as i64) < KYBER_Q { r[count] = d1 as i16; count += 1; }
        if (d2 as i64) < KYBER_Q && count < 256 { r[count] = d2 as i16; count += 1; }
    }
    r
}

fn gen_matrix_i16(rho: &[u8; 32]) -> [[Poly16; KYBER_K]; KYBER_K] {
    std::array::from_fn(|i| std::array::from_fn(|j| gen_poly_uniform_i16(rho, i as u8, j as u8)))
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

fn prf_cbd_i16(sigma: &[u8; 32], nonce: u8) -> Poly16 {
    let mut buf = [0u8; 128];
    shake256(&[sigma.as_slice(), &[nonce]], &mut buf);
    cbd_eta2_i16(&buf)
}

// matvec: t_hat = A_hat * v_hat (NTT domain, Montgomery basemul).
fn matvec_i16(a: &[[Poly16; KYBER_K]; KYBER_K], v: &[Poly16; KYBER_K]) -> [Poly16; KYBER_K] {
    std::array::from_fn(|i| {
        let mut acc = [0i16; 256];
        for j in 0..KYBER_K { basemul_acc_i16(&mut acc, &a[i][j], &v[j]); }
        acc
    })
}

fn matvec_transpose_i16(a: &[[Poly16; KYBER_K]; KYBER_K], v: &[Poly16; KYBER_K]) -> [Poly16; KYBER_K] {
    std::array::from_fn(|i| {
        let mut acc = [0i16; 256];
        for j in 0..KYBER_K { basemul_acc_i16(&mut acc, &a[j][i], &v[j]); }
        acc
    })
}

fn inner_product_i16(a: &[Poly16; KYBER_K], b: &[Poly16; KYBER_K]) -> Poly16 {
    let mut acc = [0i16; 256];
    for j in 0..KYBER_K { basemul_acc_i16(&mut acc, &a[j], &b[j]); }
    acc
}

// Polynomial addition (wrapping) — operates on standard or NTT domain.
fn poly_add_i16(a: &Poly16, b: &Poly16) -> Poly16 {
    std::array::from_fn(|i| a[i].wrapping_add(b[i]))
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
fn poly_compress_i16(p: &Poly16, d: u32, out: &mut [u8]) {
    let q = KYBER_Q as i32;
    let mut bit_pos = 0usize;
    for &c in p.iter() {
        let mut t = c as i32;
        t += (t >> 15) & q;  // make non-negative: if t < 0, t += q
        let compressed = ((((t as u32) << d) + (q as u32 / 2)) / q as u32) & ((1u32 << d) - 1);
        for b in 0..d {
            let bit = ((compressed >> b) & 1) as u8;
            out[bit_pos / 8] |= bit << (bit_pos % 8);
            bit_pos += 1;
        }
    }
}

fn poly_decompress_i16(bytes: &[u8], d: u32) -> Poly16 {
    let mut r = [0i16; 256];
    let mut bit_pos = 0usize;
    for c in r.iter_mut() {
        let mut val = 0i32;
        for b in 0..d {
            let bit = ((bytes[bit_pos / 8] >> (bit_pos % 8)) & 1) as i32;
            val |= bit << b;
            bit_pos += 1;
        }
        *c = ((val * KYBER_Q as i32 + (1 << (d-1))) >> d) as i16;
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

fn msg_decode_i16(p: &Poly16) -> [u8; 32] {
    let mut msg = [0u8; 32];
    for i in 0..32 {
        for j in 0..8 {
            let mut t = p[8*i + j] as i32;
            t += (t >> 15) & 3329;  // make non-negative
            let bit = ((((t << 1) + 3329/2) / 3329) & 1) as u8;
            msg[i] |= bit << j;
        }
    }
    msg
}

// ── i16 NEON Kyber KEM ───────────────────────────────────────────────────────

fn kyber_keygen_neon(seed: &[u8; 32]) -> SecretKey16 {
    let g = sha3_512(&[seed.as_slice()]);
    let mut rho = [0u8; 32]; let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g[..32]); sigma.copy_from_slice(&g[32..]);

    let a_hat = gen_matrix_i16(&rho);

    let mut nonce = 0u8;
    let s_hat: [Poly16; KYBER_K] = std::array::from_fn(|_| {
        let mut p = prf_cbd_i16(&sigma, nonce); nonce += 1;
        ntt_i16(&mut p); poly_reduce_i16(&mut p); p
    });
    let e_hat: [Poly16; KYBER_K] = std::array::from_fn(|_| {
        let mut p = prf_cbd_i16(&sigma, nonce); nonce += 1;
        ntt_i16(&mut p); poly_reduce_i16(&mut p); p
    });

    let mut t_hat = matvec_i16(&a_hat, &s_hat);
    for i in 0..KYBER_K {
        // poly_tomont: multiply each coeff by R mod q = fqmul(c, R²modq=1353)
        // Matches reference C poly_tomont(pkpv.vec[i]) after basemul_acc_montgomery.
        for c in t_hat[i].iter_mut() { *c = fqmul_s(*c, 1353); }
        t_hat[i] = poly_add_i16(&t_hat[i], &e_hat[i]);
        poly_reduce_i16(&mut t_hat[i]);
    }

    let mut pk_bytes: Vec<u8> = Vec::with_capacity(KYBER_K * 384 + 32);
    for i in 0..KYBER_K {
        let mut enc = [0u8; 384];
        poly_to_bytes_i16(&t_hat[i], &mut enc);
        pk_bytes.extend_from_slice(&enc);
    }
    pk_bytes.extend_from_slice(&rho);
    let h_pk = sha3_256(&[&pk_bytes]);

    // Invert NTT on s to store as coefficients (for decaps u*s computation)
    // Actually store s_hat directly (NTT domain) as the reference does
    SecretKey16 {
        s_hat,
        pk: PublicKey16 { t_hat, rho, h_pk },
        z: [0u8; 32],
    }
}

fn kyber_encaps_neon(pk: &PublicKey16, m: &[u8; 32]) -> (Ciphertext16, [u8; 32]) {
    let h_m = sha3_256(&[m.as_slice()]);
    let g = sha3_512(&[h_m.as_slice(), pk.h_pk.as_slice()]);
    let mut k_bar = [0u8; 32]; let mut r_seed = [0u8; 32];
    k_bar.copy_from_slice(&g[..32]); r_seed.copy_from_slice(&g[32..]);

    let a_hat = gen_matrix_i16(&pk.rho);
    let mut nonce = 0u8;
    let r_hat: [Poly16; KYBER_K] = std::array::from_fn(|_| {
        let mut p = prf_cbd_i16(&r_seed, nonce); nonce += 1;
        ntt_i16(&mut p); poly_reduce_i16(&mut p); p
    });
    let e1_poly: [Poly16; KYBER_K] = std::array::from_fn(|_| {
        let p = prf_cbd_i16(&r_seed, nonce); nonce += 1; p
    });
    let e2 = prf_cbd_i16(&r_seed, nonce);

    let mut u_hat = matvec_transpose_i16(&a_hat, &r_hat);
    let u_poly: [Poly16; KYBER_K] = std::array::from_fn(|i| {
        poly_reduce_i16(&mut u_hat[i]);
        let mut tmp = u_hat[i];
        intt_i16(&mut tmp);
        poly_reduce_i16(&mut tmp);
        let mut res = poly_add_i16(&tmp, &e1_poly[i]);
        poly_reduce_i16(&mut res);
        res
    });

    let mut v_hat = inner_product_i16(&pk.t_hat, &r_hat);
    poly_reduce_i16(&mut v_hat);
    let mut v_poly = v_hat;
    intt_i16(&mut v_poly);
    poly_reduce_i16(&mut v_poly);
    v_poly = poly_add_i16(&v_poly, &e2);
    v_poly = poly_add_i16(&v_poly, &msg_encode_i16(m));
    poly_reduce_i16(&mut v_poly);

    let u_enc: [[u8; 320]; KYBER_K] = std::array::from_fn(|i| {
        let mut buf = [0u8; 320];
        poly_compress_i16(&u_poly[i], 10, &mut buf); buf
    });
    let mut v_enc = [0u8; 128];
    poly_compress_i16(&v_poly, 4, &mut v_enc);

    let mut ct_bytes: Vec<u8> = Vec::with_capacity(KYBER_K * 320 + 128);
    for ue in &u_enc { ct_bytes.extend_from_slice(ue.as_slice()); }
    ct_bytes.extend_from_slice(&v_enc);
    let h_c = sha3_256(&[&ct_bytes]);
    let ss = sha3_256(&[k_bar.as_slice(), h_c.as_slice()]);

    (Ciphertext16 { u_enc, v_enc }, ss)
}

fn kyber_decaps_neon(sk: &SecretKey16, ct: &Ciphertext16) -> [u8; 32] {
    let u_hat: [Poly16; KYBER_K] = std::array::from_fn(|i| {
        let mut p = poly_decompress_i16(&ct.u_enc[i], 10);
        ntt_i16(&mut p); poly_reduce_i16(&mut p); p
    });
    let v_poly = poly_decompress_i16(&ct.v_enc, 4);

    let mut su_hat = inner_product_i16(&sk.s_hat, &u_hat);
    poly_reduce_i16(&mut su_hat);
    intt_i16(&mut su_hat);
    poly_reduce_i16(&mut su_hat);

    let m_prime = msg_decode_i16(&poly_sub_i16(&v_poly, &su_hat));
    let (ct_prime, ss_prime) = kyber_encaps_neon(&sk.pk, &m_prime);

    let mut eq: u8 = 0xFF;
    for i in 0..KYBER_K {
        for (a, b) in ct.u_enc[i].iter().zip(ct_prime.u_enc[i].iter()) {
            eq &= !(a ^ b).wrapping_neg();
        }
    }
    for (a, b) in ct.v_enc.iter().zip(ct_prime.v_enc.iter()) {
        eq &= !(a ^ b).wrapping_neg();
    }

    let mut ct_bytes: Vec<u8> = Vec::with_capacity(KYBER_K * 320 + 128);
    for ue in &ct.u_enc { ct_bytes.extend_from_slice(ue.as_slice()); }
    ct_bytes.extend_from_slice(&ct.v_enc);
    let h_c = sha3_256(&[&ct_bytes]);
    let ss_reject = sha3_256(&[sk.z.as_slice(), h_c.as_slice()]);

    let mask = eq;
    let mut ss = [0u8; 32];
    for i in 0..32 { ss[i] = (ss_prime[i] & mask) | (ss_reject[i] & !mask); }
    ss
}

// ── Timing helpers ────────────────────────────────────────────────────────────

fn measure_ns<F: FnMut()>(iters: usize, mut f: F) -> f64 {
    let start = Instant::now();
    for _ in 0..iters { f(); }
    start.elapsed().as_nanos() as f64 / iters as f64
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    println!("\n================================================================");
    println!("KYBER-512 FULL KEM BENCHMARK  (including hashing & encoding)");
    println!("================================================================\n");
    println!("  n = {KYBER_N},  q = {KYBER_Q},  k = {KYBER_K} (Kyber-512)");
    println!("  η = 2,  du = 10,  dv = 4");
    #[cfg(target_arch = "aarch64")]
    println!("  CPU: ARM64 (Apple Silicon)");
    println!();

    let consts = NTTConstants::new();
    let seed = [0u8; 32];
    let m    = [1u8; 32];

    // ── Debug: NTT round-trip check ──────────────────────────────────────────
    {
        let mut p = [0i16; 256];
        p[0] = 1; p[1] = 2; p[5] = 100; p[100] = 999;
        let orig = p;

        // invntt_tomont(ntt(p)) = p * R mod q where R = 2^16 mod q = 2285.
        // R mod q: 65536 mod 3329 = 65536 - 19*3329 = 65536 - 63251 = 2285.
        // In centered form: 2285 > 3329/2 = 1664, so 2285 - 3329 = -1044.
        // Expected: each coeff scaled by R mod q, centered in [-q/2, q/2).
        fn normalize_q(x: i16) -> i16 {
            let mut t = x as i32;
            t += (t >> 15) & 3329;
            if t >= 3329 { t -= 3329; }
            // center
            if t > 1664 { t -= 3329; }
            t as i16
        }
        // R mod q = 2285 (centered: -1044)
        // fqmul(orig, R) = orig * R * R^{-1} = orig. But we want orig * R:
        // Just multiply: (orig * 2285) mod q, centered.
        fn scale_by_r(x: i16) -> i16 {
            let r = 2285i32;
            let t = (x as i32) * r;
            let mut v = ((t % 3329) + 3329) % 3329;
            if v > 1664 { v -= 3329; }
            v as i16
        }

        // Scalar round-trip
        let mut ps = orig;
        ntt_i16_scalar(&mut ps); poly_reduce_i16(&mut ps);
        intt_i16_scalar(&mut ps); poly_reduce_i16(&mut ps);
        let mut ok_scalar = true;
        for i in 0..256 {
            let exp = scale_by_r(orig[i]);
            let got = normalize_q(ps[i]);
            if got != exp {
                println!("  Scalar NTT round-trip mismatch at [{}]: orig={} exp={} got={}", i, orig[i], exp, got);
                ok_scalar = false;
                if i > 5 { break; }
            }
        }
        if ok_scalar { println!("  Scalar NTT round-trip: PASSED (result = orig*R mod q)"); } else { println!("  Scalar NTT round-trip: FAILED"); }

        // NEON round-trip (only meaningful on aarch64)
        ntt_i16(&mut p); poly_reduce_i16(&mut p);
        intt_i16(&mut p); poly_reduce_i16(&mut p);
        let mut ok = true;
        for i in 0..256 {
            let exp = scale_by_r(orig[i]);
            let got = normalize_q(p[i]);
            if got != exp {
                println!("  NEON NTT round-trip mismatch at [{}]: orig={} exp={} got={}", i, orig[i], exp, got);
                ok = false;
                if i > 5 { break; }
            }
        }
        if ok { println!("  NEON NTT round-trip: PASSED (result = orig*R mod q)"); } else { println!("  NEON NTT round-trip: FAILED"); }

        // Test fqmul_vec for a single value
        #[cfg(target_arch = "aarch64")]
        {
            use std::arch::aarch64::*;
            let a_arr = [100i16, -200, 1000, -1000, 500, -500, 1664, 1665];
            let b_arr = [200i16, 300, -400, 500, -600, 700, -800, 900];
            let mut res_arr = [0i16; 8];
            unsafe {
                let a_v = vld1q_s16(a_arr.as_ptr());
                let b_v = vld1q_s16(b_arr.as_ptr());
                let r_v = neon_poly::fqmul_vec(a_v, b_v);
                vst1q_s16(res_arr.as_mut_ptr(), r_v);
            }
            let mut fqmul_ok = true;
            for i in 0..8 {
                let exp = fqmul_s(a_arr[i], b_arr[i]);
                if res_arr[i] != exp {
                    println!("  fqmul_vec[{}]: fqmul_s({},{})={} but vec gave {}", i, a_arr[i], b_arr[i], exp, res_arr[i]);
                    fqmul_ok = false;
                }
            }
            if fqmul_ok { println!("  fqmul_vec: PASSED"); } else { println!("  fqmul_vec: FAILED"); }
        }
    }
    println!();

    // Warmup all three variants
    for _ in 0..100 {
        let sk = kyber_keygen(&seed, &consts);
        let (ct, _) = kyber_encaps_inner(&sk.pk, &m, &consts);
        std::hint::black_box(kyber_decaps(&sk, &ct, &consts));
        let sk2 = kyber_keygen_hw(&seed, &consts);
        let (ct2, _) = kyber_encaps_hw(&sk2.pk, &m, &consts);
        std::hint::black_box(kyber_decaps_hw(&sk2, &ct2, &consts));
        let sk3 = kyber_keygen_neon(&seed);
        let (ct3, ss3e) = kyber_encaps_neon(&sk3.pk, &m);
        let ss3d = std::hint::black_box(kyber_decaps_neon(&sk3, &ct3));
        // Sanity check on first iteration: encaps and decaps must agree
        if ss3e != ss3d {
            eprintln!("NEON KEM correctness check FAILED: ss_encaps != ss_decaps");
            std::process::exit(1);
        }
    }
    println!("  NEON KEM correctness check: PASSED (encaps == decaps)");
    println!();

    const N: usize = 10_000;

    // Inline Keccak + i64 NTT variant
    let kg_ns  = measure_ns(N, || { std::hint::black_box(kyber_keygen(&seed, &consts)); });
    let sk     = kyber_keygen(&seed, &consts);
    let enc_ns = measure_ns(N, || { std::hint::black_box(kyber_encaps_inner(&sk.pk, &m, &consts)); });
    let (ct, _) = kyber_encaps_inner(&sk.pk, &m, &consts);
    let dec_ns = measure_ns(N, || { std::hint::black_box(kyber_decaps(&sk, &ct, &consts)); });
    let total_ns = kg_ns + enc_ns + dec_ns;

    // sha3 asm + i64 NTT variant
    let kg_hw  = measure_ns(N, || { std::hint::black_box(kyber_keygen_hw(&seed, &consts)); });
    let sk_hw  = kyber_keygen_hw(&seed, &consts);
    let enc_hw = measure_ns(N, || { std::hint::black_box(kyber_encaps_hw(&sk_hw.pk, &m, &consts)); });
    let (ct_hw, _) = kyber_encaps_hw(&sk_hw.pk, &m, &consts);
    let dec_hw = measure_ns(N, || { std::hint::black_box(kyber_decaps_hw(&sk_hw, &ct_hw, &consts)); });
    let total_hw = kg_hw + enc_hw + dec_hw;

    // NEON i16 NTT + sha3 (inline Keccak hashing) variant
    let kg_neon  = measure_ns(N, || { std::hint::black_box(kyber_keygen_neon(&seed)); });
    let sk_neon  = kyber_keygen_neon(&seed);
    let enc_neon = measure_ns(N, || { std::hint::black_box(kyber_encaps_neon(&sk_neon.pk, &m)); });
    let (ct_neon, _) = kyber_encaps_neon(&sk_neon.pk, &m);
    let dec_neon = measure_ns(N, || { std::hint::black_box(kyber_decaps_neon(&sk_neon, &ct_neon)); });
    let total_neon = kg_neon + enc_neon + dec_neon;

    let liboqs_total_us  = 22.44_f64;
    let kyber_c_total_us = 47.87_f64;
    let sha3_sw_us       = 57.61_f64;

    println!("KYBER-512 FULL KEM  (keygen + encaps + decaps)");
    println!("  {}", "=".repeat(65));
    println!();
    println!("  ── Inline pure-Rust Keccak (XKCP) + i64 NTT ──");
    println!("  Key Generation:   {:>7.2} µs", kg_ns / 1_000.0);
    println!("  Encapsulation:    {:>7.2} µs", enc_ns / 1_000.0);
    println!("  Decapsulation:    {:>7.2} µs  (includes re-encryption)", dec_ns / 1_000.0);
    println!("  TOTAL:            {:>7.2} µs  ({:.0} sessions/sec)",
             total_ns / 1_000.0, 1e9 / total_ns);
    println!();
    println!("  ── sha3 crate + asm + i64 NTT ──");
    println!("  Key Generation:   {:>7.2} µs", kg_hw / 1_000.0);
    println!("  Encapsulation:    {:>7.2} µs", enc_hw / 1_000.0);
    println!("  Decapsulation:    {:>7.2} µs  (includes re-encryption)", dec_hw / 1_000.0);
    println!("  TOTAL:            {:>7.2} µs  ({:.0} sessions/sec)",
             total_hw / 1_000.0, 1e9 / total_hw);
    println!();
    println!("  ── Inline Keccak + NEON i16 NTT (Montgomery) ──");
    println!("  Key Generation:   {:>7.2} µs", kg_neon / 1_000.0);
    println!("  Encapsulation:    {:>7.2} µs", enc_neon / 1_000.0);
    println!("  Decapsulation:    {:>7.2} µs  (includes re-encryption)", dec_neon / 1_000.0);
    println!("  TOTAL:            {:>7.2} µs  ({:.0} sessions/sec)",
             total_neon / 1_000.0, 1e9 / total_neon);
    println!();
    println!("  {}", "=".repeat(65));
    println!("  COMPARISON:");
    println!("  {}", "-".repeat(65));
    println!("  LibOQS 0.15.0 (ML-KEM-512):          {:>6.2} µs  ({:.0}/sec)  baseline",
             liboqs_total_us, 1e6 / liboqs_total_us);
    println!("  NEON i16 NTT + Keccak (this):         {:>6.2} µs  ({:.0}/sec)  {:.2}×",
             total_neon / 1_000.0, 1e9 / total_neon, total_neon / 1_000.0 / liboqs_total_us);
    println!("  sha3 asm + i64 NTT (this):            {:>6.2} µs  ({:.0}/sec)  {:.2}×",
             total_hw / 1_000.0, 1e9 / total_hw, total_hw / 1_000.0 / liboqs_total_us);
    println!("  inline Keccak + i64 NTT (this):       {:>6.2} µs  ({:.0}/sec)  {:.2}×",
             total_ns / 1_000.0, 1e9 / total_ns, total_ns / 1_000.0 / liboqs_total_us);
    println!("  sha3 crate sw + i64 NTT (previous):   {:>6.2} µs  ({:.0}/sec)  {:.2}×",
             sha3_sw_us, 1e6 / sha3_sw_us, sha3_sw_us / liboqs_total_us);
    println!("  Kyber C Reference:                    {:>6.2} µs  ({:.0}/sec)  {:.2}×",
             kyber_c_total_us, 1e6 / kyber_c_total_us, kyber_c_total_us / liboqs_total_us);
    println!("  {}", "-".repeat(65));
    println!();
    println!("================================================================\n");
}
