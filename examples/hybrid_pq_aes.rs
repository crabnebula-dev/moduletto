//! # Hybrid Post-Quantum Encryption: Kyber-512 + AES-256-GCM
//!
//! Demonstrates a complete hybrid encryption workflow where:
//!
//! 1. **Kyber-512 KEM** (via Moduletto) establishes a 256-bit shared secret
//! 2. **AES-256-GCM** encrypts/decrypts an arbitrary plaintext using that secret
//!
//! This is the standard pattern for post-quantum hybrid encryption as used in
//! TLS 1.3 (ML-KEM + AES-GCM), Signal's PQXDH, and similar protocols.
//!
//! ```text
//!   Alice (sender)                          Bob (receiver)
//!   ─────────────                          ───────────────
//!   1. Bob generates Kyber keypair
//!                                    ←──  pk
//!   2. Alice encapsulates:
//!      (ciphertext, shared_secret)
//!      = Kyber.Encaps(pk)
//!   3. Alice encrypts message:
//!      aes_ct = AES-256-GCM.Encrypt(
//!        key=shared_secret,
//!        plaintext=message)
//!   4. Alice sends:
//!      (kyber_ct, aes_ct, nonce)     ──→
//!                                          5. Bob decapsulates:
//!                                             shared_secret
//!                                             = Kyber.Decaps(sk, kyber_ct)
//!                                          6. Bob decrypts:
//!                                             message = AES-256-GCM.Decrypt(
//!                                               key=shared_secret,
//!                                               ciphertext=aes_ct)
//! ```
//!
//! Run with:
//!   cargo run --release --example hybrid_pq_aes

use moduletto::ntt::{KyberCoeff, NTTConstants, NTTPoly, KYBER_N, KYBER_Q};
use sha3::digest::{ExtendableOutput, FixedOutput, Update, XofReader};
use sha3::{Sha3_256, Sha3_512, Shake128, Shake256};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
    Aes256Gcm, AeadCore,
};

// ════════════════════════════════════════════════════════════════════
// Kyber-512 KEM (minimal implementation using Moduletto NTT)
// ════════════════════════════════════════════════════════════════════

const KYBER_K: usize = 2;

// ── Hashing helpers ────────────────────────────────────────────────

fn sha3_256(inputs: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::default();
    for input in inputs { h.update(input); }
    let mut out = [0u8; 32];
    FixedOutput::finalize_into(h, (&mut out).into());
    out
}

fn sha3_512(inputs: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha3_512::default();
    for input in inputs { h.update(input); }
    let mut out = [0u8; 64];
    FixedOutput::finalize_into(h, (&mut out).into());
    out
}

// ── Polynomial sampling ────────────────────────────────────────────

fn gen_poly_uniform(rho: &[u8; 32], i: u8, j: u8) -> NTTPoly {
    let mut h = Shake128::default();
    h.update(rho);
    h.update(&[j, i]);
    let mut reader = h.finalize_xof();
    let mut coeffs = [KyberCoeff::zero(); KYBER_N];
    let mut count = 0;
    while count < KYBER_N {
        let mut buf = [0u8; 3];
        reader.read(&mut buf);
        let d1 = ((buf[0] as i64) | ((buf[1] as i64 & 0x0F) << 8)) % (KYBER_Q + 1);
        let d2 = (((buf[1] as i64) >> 4) | ((buf[2] as i64) << 4)) % (KYBER_Q + 1);
        if d1 < KYBER_Q && count < KYBER_N { coeffs[count] = KyberCoeff::new(d1); count += 1; }
        if d2 < KYBER_Q && count < KYBER_N { coeffs[count] = KyberCoeff::new(d2); count += 1; }
    }
    NTTPoly::new(coeffs)
}

fn gen_matrix(rho: &[u8; 32]) -> [[NTTPoly; KYBER_K]; KYBER_K] {
    std::array::from_fn(|i| std::array::from_fn(|j| gen_poly_uniform(rho, i as u8, j as u8)))
}

fn prf_cbd(seed: &[u8; 32], nonce: u8) -> NTTPoly {
    let mut h = Shake256::default();
    h.update(seed);
    h.update(&[nonce]);
    let mut reader = h.finalize_xof();
    let mut buf = [0u8; 128]; // eta=2: 64*eta/4 = 128 bytes for n=256
    reader.read(&mut buf);
    let mut coeffs = [KyberCoeff::zero(); KYBER_N];
    for i in 0..KYBER_N {
        let byte = buf[i / 2];
        let bits = if i % 2 == 0 { byte & 0x0F } else { byte >> 4 };
        let a = (bits & 1) + ((bits >> 1) & 1);
        let b = ((bits >> 2) & 1) + ((bits >> 3) & 1);
        coeffs[i] = KyberCoeff::new((a as i64) - (b as i64));
    }
    NTTPoly::new(coeffs)
}

// ── Polynomial encoding/decoding ───────────────────────────────────

fn poly_to_bytes(p: &NTTPoly, out: &mut [u8; 384]) {
    for i in (0..KYBER_N).step_by(2) {
        let a = p.coeffs[i].value() as u16;
        let b = p.coeffs[i + 1].value() as u16;
        out[3 * (i / 2)]     = a as u8;
        out[3 * (i / 2) + 1] = ((a >> 8) | (b << 4)) as u8;
        out[3 * (i / 2) + 2] = (b >> 4) as u8;
    }
}

fn poly_compress(p: &NTTPoly, d: u32, out: &mut [u8]) {
    let mask = (1u32 << d) - 1;
    let mut bit_pos = 0usize;
    for c in &p.coeffs {
        let compressed = ((c.value() as u64 * ((1u64 << d) as u64) + KYBER_Q as u64 / 2) / KYBER_Q as u64) as u32 & mask;
        for b in 0..d {
            if (compressed >> b) & 1 == 1 {
                out[bit_pos / 8] |= 1 << (bit_pos % 8);
            }
            bit_pos += 1;
        }
    }
}

fn poly_decompress(data: &[u8], d: u32) -> NTTPoly {
    let mut coeffs = [KyberCoeff::zero(); KYBER_N];
    let mut bit_pos = 0usize;
    for c in &mut coeffs {
        let mut val = 0u32;
        for b in 0..d {
            if (data[bit_pos / 8] >> (bit_pos % 8)) & 1 == 1 { val |= 1 << b; }
            bit_pos += 1;
        }
        *c = KyberCoeff::new(((val as u64 * KYBER_Q as u64 + (1u64 << (d - 1))) >> d) as i64);
    }
    NTTPoly::new(coeffs)
}

fn msg_encode(m: &[u8; 32]) -> NTTPoly {
    let mut coeffs = [KyberCoeff::zero(); KYBER_N];
    for i in 0..256 {
        let bit = ((m[i / 8] >> (i % 8)) & 1) as i64;
        coeffs[i] = KyberCoeff::new(bit * ((KYBER_Q + 1) / 2));
    }
    NTTPoly::new(coeffs)
}

fn msg_decode(p: &NTTPoly) -> [u8; 32] {
    let mut m = [0u8; 32];
    for i in 0..256 {
        let v = p.coeffs[i].value();
        let bit = if (v as u64 * 2 + KYBER_Q as u64 / 2) / KYBER_Q as u64 % 2 == 1 { 1u8 } else { 0u8 };
        m[i / 8] |= bit << (i % 8);
    }
    m
}

// ── Matrix / vector operations ─────────────────────────────────────

fn basemul_acc(acc: &mut [KyberCoeff; KYBER_N], a: &[KyberCoeff; KYBER_N], b: &[KyberCoeff; KYBER_N], consts: &NTTConstants) {
    for i in (0..KYBER_N).step_by(2) {
        let zeta = consts.zetas[128 + i / 2];
        acc[i]     = acc[i]     + a[i] * b[i] + zeta * a[i + 1] * b[i + 1];
        acc[i + 1] = acc[i + 1] + a[i] * b[i + 1] + a[i + 1] * b[i];
    }
}

fn matvec(a: &[[NTTPoly; KYBER_K]; KYBER_K], v: &[NTTPoly; KYBER_K], c: &NTTConstants) -> [NTTPoly; KYBER_K] {
    let mut r: [NTTPoly; KYBER_K] = std::array::from_fn(|_| NTTPoly::zero());
    for i in 0..KYBER_K { for j in 0..KYBER_K { basemul_acc(&mut r[i].coeffs, &a[i][j].coeffs, &v[j].coeffs, c); } }
    r
}

fn matvec_t(a: &[[NTTPoly; KYBER_K]; KYBER_K], v: &[NTTPoly; KYBER_K], c: &NTTConstants) -> [NTTPoly; KYBER_K] {
    let mut r: [NTTPoly; KYBER_K] = std::array::from_fn(|_| NTTPoly::zero());
    for i in 0..KYBER_K { for j in 0..KYBER_K { basemul_acc(&mut r[i].coeffs, &a[j][i].coeffs, &v[j].coeffs, c); } }
    r
}

fn inner_product(a: &[NTTPoly; KYBER_K], b: &[NTTPoly; KYBER_K], c: &NTTConstants) -> NTTPoly {
    let mut acc = NTTPoly::zero();
    for i in 0..KYBER_K { basemul_acc(&mut acc.coeffs, &a[i].coeffs, &b[i].coeffs, c); }
    acc
}

// ── Kyber-512 KEM ──────────────────────────────────────────────────

struct KyberPublicKey {
    t_hat: [NTTPoly; KYBER_K],
    rho:   [u8; 32],
    h_pk:  [u8; 32],
}

struct KyberSecretKey {
    s_hat: [NTTPoly; KYBER_K],
    pk:    KyberPublicKey,
    z:     [u8; 32],
}

struct KyberCiphertext {
    u_enc: [[u8; 320]; KYBER_K],
    v_enc: [u8; 128],
}

fn kyber_keygen(seed: &[u8; 32]) -> KyberSecretKey {
    let consts = NTTConstants::new();
    let g = sha3_512(&[seed]);
    let (mut rho, mut sigma) = ([0u8; 32], [0u8; 32]);
    rho.copy_from_slice(&g[..32]);
    sigma.copy_from_slice(&g[32..]);

    let a_hat = gen_matrix(&rho);
    let mut nonce = 0u8;
    let s: [NTTPoly; KYBER_K] = std::array::from_fn(|_| { let p = prf_cbd(&sigma, nonce); nonce += 1; p });
    let e: [NTTPoly; KYBER_K] = std::array::from_fn(|_| { let p = prf_cbd(&sigma, nonce); nonce += 1; p });
    let s_hat: [NTTPoly; KYBER_K] = std::array::from_fn(|i| s[i].ntt());
    let e_hat: [NTTPoly; KYBER_K] = std::array::from_fn(|i| e[i].ntt());
    let mut t_hat = matvec(&a_hat, &s_hat, &consts);
    for i in 0..KYBER_K { t_hat[i] = t_hat[i].add(&e_hat[i]); }

    let mut pk_bytes = Vec::with_capacity(KYBER_K * 384 + 32);
    for i in 0..KYBER_K { let mut enc = [0u8; 384]; poly_to_bytes(&t_hat[i], &mut enc); pk_bytes.extend_from_slice(&enc); }
    pk_bytes.extend_from_slice(&rho);
    let h_pk = sha3_256(&[&pk_bytes]);

    // Random rejection secret for implicit rejection
    let z = sha3_256(&[&sigma, b"rejection"]);

    KyberSecretKey { s_hat, pk: KyberPublicKey { t_hat, rho, h_pk }, z }
}

fn kyber_encaps(pk: &KyberPublicKey, m: &[u8; 32]) -> (KyberCiphertext, [u8; 32]) {
    let consts = NTTConstants::new();
    let h_m = sha3_256(&[m]);
    let g = sha3_512(&[&h_m, &pk.h_pk]);
    let (mut k_bar, mut r_seed) = ([0u8; 32], [0u8; 32]);
    k_bar.copy_from_slice(&g[..32]);
    r_seed.copy_from_slice(&g[32..]);

    let a_hat = gen_matrix(&pk.rho);
    let mut nonce = 0u8;
    let r:  [NTTPoly; KYBER_K] = std::array::from_fn(|_| { let p = prf_cbd(&r_seed, nonce); nonce += 1; p });
    let e1: [NTTPoly; KYBER_K] = std::array::from_fn(|_| { let p = prf_cbd(&r_seed, nonce); nonce += 1; p });
    let e2 = prf_cbd(&r_seed, nonce);

    let r_hat: [NTTPoly; KYBER_K] = std::array::from_fn(|i| r[i].ntt());
    let u_hat = matvec_t(&a_hat, &r_hat, &consts);
    let u_poly: [NTTPoly; KYBER_K] = std::array::from_fn(|i| u_hat[i].intt().add(&e1[i]));
    let v_hat = inner_product(&pk.t_hat, &r_hat, &consts);
    let v_poly = v_hat.intt().add(&e2).add(&msg_encode(m));

    let u_enc: [[u8; 320]; KYBER_K] = std::array::from_fn(|i| {
        let mut buf = [0u8; 320];
        poly_compress(&u_poly[i], 10, &mut buf);
        buf
    });
    let mut v_enc = [0u8; 128];
    poly_compress(&v_poly, 4, &mut v_enc);

    let mut ct_bytes = Vec::with_capacity(KYBER_K * 320 + 128);
    for ue in &u_enc { ct_bytes.extend_from_slice(ue); }
    ct_bytes.extend_from_slice(&v_enc);
    let h_c = sha3_256(&[&ct_bytes]);
    let ss = sha3_256(&[&k_bar, &h_c]);

    (KyberCiphertext { u_enc, v_enc }, ss)
}

fn kyber_decaps(sk: &KyberSecretKey, ct: &KyberCiphertext) -> [u8; 32] {
    let consts = NTTConstants::new();
    let u_poly: [NTTPoly; KYBER_K] = std::array::from_fn(|i| poly_decompress(&ct.u_enc[i], 10));
    let v_poly = poly_decompress(&ct.v_enc, 4);
    let u_hat: [NTTPoly; KYBER_K] = std::array::from_fn(|i| u_poly[i].ntt());
    let su_hat = inner_product(&sk.s_hat, &u_hat, &consts);
    let m_prime = msg_decode(&v_poly.sub(&su_hat.intt()));

    // Re-encrypt to verify
    let (ct_prime, ss_prime) = kyber_encaps(&sk.pk, &m_prime);

    // Constant-time ciphertext comparison
    let mut eq: u8 = 0xFF;
    for i in 0..KYBER_K {
        for (a, b) in ct.u_enc[i].iter().zip(ct_prime.u_enc[i].iter()) {
            eq &= !(a ^ b).wrapping_neg();
        }
    }
    for (a, b) in ct.v_enc.iter().zip(ct_prime.v_enc.iter()) {
        eq &= !(a ^ b).wrapping_neg();
    }

    // Implicit rejection: return real key or rejection key
    let mut ct_bytes = Vec::with_capacity(KYBER_K * 320 + 128);
    for ue in &ct.u_enc { ct_bytes.extend_from_slice(ue); }
    ct_bytes.extend_from_slice(&ct.v_enc);
    let h_c = sha3_256(&[&ct_bytes]);
    let ss_reject = sha3_256(&[&sk.z, &h_c]);

    let mut ss = [0u8; 32];
    for i in 0..32 {
        ss[i] = (ss_prime[i] & eq) | (ss_reject[i] & !eq);
    }
    ss
}

// ════════════════════════════════════════════════════════════════════
// Hybrid encryption: Kyber-512 KEM + AES-256-GCM
// ════════════════════════════════════════════════════════════════════

/// Encrypted message: Kyber ciphertext + AES-GCM nonce + AES-GCM ciphertext
struct HybridCiphertext {
    kem_ct: KyberCiphertext,
    nonce:  [u8; 12],
    aes_ct: Vec<u8>,
}

/// Encrypt a plaintext message using hybrid Kyber-512 + AES-256-GCM.
///
/// 1. Encapsulate a fresh shared secret using the recipient's Kyber public key
/// 2. Use the 256-bit shared secret as the AES-256-GCM key
/// 3. Encrypt the plaintext with a random nonce
fn hybrid_encrypt(pk: &KyberPublicKey, plaintext: &[u8]) -> HybridCiphertext {
    // Step 1: Generate random message seed for Kyber encapsulation
    let mut m = [0u8; 32];
    aes_gcm::aead::OsRng.fill_bytes(&mut m);

    // Step 2: Kyber KEM — produces (ciphertext, 256-bit shared secret)
    let (kem_ct, shared_secret) = kyber_encaps(pk, &m);

    // Step 3: AES-256-GCM encrypt the plaintext
    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .expect("shared secret is 32 bytes");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let aes_ct = cipher.encrypt(&nonce, plaintext)
        .expect("AES-GCM encryption failed");

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce);

    HybridCiphertext { kem_ct, nonce: nonce_bytes, aes_ct }
}

/// Decrypt a hybrid ciphertext using the recipient's Kyber secret key.
///
/// 1. Decapsulate the shared secret from the Kyber ciphertext
/// 2. Use the 256-bit shared secret as the AES-256-GCM key
/// 3. Decrypt the AES-GCM ciphertext
fn hybrid_decrypt(sk: &KyberSecretKey, ct: &HybridCiphertext) -> Result<Vec<u8>, &'static str> {
    // Step 1: Kyber KEM decapsulation — recover shared secret
    let shared_secret = kyber_decaps(sk, &ct.kem_ct);

    // Step 2: AES-256-GCM decrypt
    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .expect("shared secret is 32 bytes");
    let nonce = aes_gcm::Nonce::from_slice(&ct.nonce);

    cipher.decrypt(nonce, ct.aes_ct.as_ref())
        .map_err(|_| "AES-GCM decryption failed (authentication tag mismatch)")
}

// ════════════════════════════════════════════════════════════════════

fn main() {
    let sep = "=".repeat(70);
    println!("{sep}");
    println!("  HYBRID POST-QUANTUM ENCRYPTION: Kyber-512 + AES-256-GCM");
    println!("{sep}\n");

    // ── Key generation ─────────────────────────────────────────────
    println!("1. Generating Kyber-512 keypair...");
    let mut seed = [0u8; 32];
    aes_gcm::aead::OsRng.fill_bytes(&mut seed);
    let start = std::time::Instant::now();
    let sk = kyber_keygen(&seed);
    let keygen_time = start.elapsed();
    println!("   Done in {:.1} us\n", keygen_time.as_nanos() as f64 / 1000.0);

    // ── Encryption ─────────────────────────────────────────────────
    let messages = [
        "Hello from the post-quantum world!",
        "This message is protected against both classical and quantum attackers.",
        "Kyber-512 provides IND-CCA2 security, AES-256-GCM provides authenticated encryption.",
        &"A".repeat(10_000), // 10 KB message
    ];

    for (i, msg) in messages.iter().enumerate() {
        let display = if msg.len() > 60 {
            format!("{}... ({} bytes)", &msg[..57], msg.len())
        } else {
            msg.to_string()
        };

        println!("2.{}. Encrypting: \"{}\"", i + 1, display);

        let start = std::time::Instant::now();
        let ct = hybrid_encrypt(&sk.pk, msg.as_bytes());
        let enc_time = start.elapsed();

        println!("     Kyber ciphertext: {} bytes", KYBER_K * 320 + 128);
        println!("     AES-GCM ciphertext: {} bytes (plaintext {} + tag 16)",
            ct.aes_ct.len(), msg.len());
        println!("     Total overhead: {} bytes",
            KYBER_K * 320 + 128 + 12 + 16); // KEM ct + nonce + GCM tag
        println!("     Encrypt time: {:.1} us", enc_time.as_nanos() as f64 / 1000.0);

        // ── Decryption ─────────────────────────────────────────────
        let start = std::time::Instant::now();
        let plaintext = hybrid_decrypt(&sk, &ct).expect("Decryption failed!");
        let dec_time = start.elapsed();

        assert_eq!(plaintext, msg.as_bytes(), "Roundtrip failed!");
        println!("     Decrypt time: {:.1} us", dec_time.as_nanos() as f64 / 1000.0);
        println!("     Roundtrip: OK\n");
    }

    // ── Tamper detection ───────────────────────────────────────────
    println!("3. Tamper detection test...");
    let ct = hybrid_encrypt(&sk.pk, b"secret data");

    // Flip a bit in the AES ciphertext
    let mut tampered = HybridCiphertext {
        kem_ct: KyberCiphertext {
            u_enc: ct.kem_ct.u_enc,
            v_enc: ct.kem_ct.v_enc,
        },
        nonce: ct.nonce,
        aes_ct: ct.aes_ct.clone(),
    };
    tampered.aes_ct[0] ^= 1;

    match hybrid_decrypt(&sk, &tampered) {
        Err(e) => println!("   Tampered ciphertext correctly rejected: {e}"),
        Ok(_)  => panic!("Tampered ciphertext was accepted!"),
    }

    // ── Summary ────────────────────────────────────────────────────
    println!("\n{sep}");
    println!("  SECURITY PROPERTIES:");
    println!("  - Post-quantum KEM: Kyber-512 (ML-KEM-512, NIST FIPS 203)");
    println!("  - Symmetric cipher: AES-256-GCM (NIST SP 800-38D)");
    println!("  - Key size: 256 bits (quantum security level ~128 bits)");
    println!("  - KEM overhead: {} bytes per message", KYBER_K * 320 + 128);
    println!("  - Authentication: AES-GCM 128-bit tag + Kyber IND-CCA2");
    println!("  - Implicit rejection: failed decapsulation yields random key");
    println!("{sep}");
}
