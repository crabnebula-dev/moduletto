//! # Hybrid Post-Quantum Encryption: ML-KEM-512 + AES-256-GCM
//!
//! Demonstrates the standard post-quantum hybrid pattern, as used in TLS 1.3
//! (ML-KEM + AES-GCM) and Signal's PQXDH:
//!
//! 1. **ML-KEM-512** (`moduletto::kem::ml_kem_512`, FIPS 203) establishes a
//!    256-bit shared secret.
//! 2. **AES-256-GCM** encrypts the plaintext under that secret.
//!
//! ```text
//!   Alice (sender)                          Bob (receiver)
//!   ─────────────                          ───────────────
//!   1. Bob generates an ML-KEM keypair
//!                                    ←──  ek
//!   2. Alice encapsulates:
//!      (c, shared_secret) = ML-KEM.Encaps(ek)
//!   3. Alice encrypts:
//!      aes_ct = AES-256-GCM.Encrypt(key = shared_secret, plaintext)
//!   4. Alice sends (c, nonce, aes_ct)  ──→
//!                                          5. Bob decapsulates:
//!                                             shared_secret = ML-KEM.Decaps(dk, c)
//!                                          6. Bob decrypts aes_ct
//! ```
//!
//! The KEM is the library's own, validated against the NIST ACVP vectors.
//! Randomness comes from the operating system through `OsRng` (`rand_core`,
//! pulled in by `aes-gcm`); with the crate's `getrandom` feature,
//! `ml_kem_512::keygen()` and `ml_kem_512::encaps(&ek)` do the same without
//! an extra dependency. Secrets are held in `Zeroizing` so they are wiped on
//! drop.
//!
//! Run with:
//!   cargo run --release --example hybrid_pq_aes

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm,
};
use moduletto::kem::ml_kem_512::{self, CT_BYTES, DK_BYTES, EK_BYTES};
use moduletto::kem::KemError;
use zeroize::Zeroizing;

/// A recipient's key pair. `dk` is wiped on drop.
struct KeyPair {
    ek: [u8; EK_BYTES],
    dk: Zeroizing<[u8; DK_BYTES]>,
}

fn keygen() -> KeyPair {
    let mut d = Zeroizing::new([0u8; 32]);
    let mut z = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *d);
    OsRng.fill_bytes(&mut *z);
    let (ek, dk) = ml_kem_512::keygen_derand(&d, &z);
    KeyPair { ek, dk: Zeroizing::new(dk) }
}

/// Encrypted message: ML-KEM ciphertext + AES-GCM nonce + AES-GCM ciphertext.
#[derive(Clone)]
struct HybridCiphertext {
    kem_ct: [u8; CT_BYTES],
    nonce: [u8; 12],
    aes_ct: Vec<u8>,
}

#[derive(Debug)]
enum HybridError {
    Kem(KemError),
    /// AES-GCM authentication failed: wrong key (tampered KEM ciphertext) or
    /// tampered AES ciphertext.
    Authentication,
}

impl From<KemError> for HybridError {
    fn from(e: KemError) -> Self {
        HybridError::Kem(e)
    }
}

impl std::fmt::Display for HybridError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HybridError::Kem(e) => write!(f, "ML-KEM: {e}"),
            HybridError::Authentication => f.write_str("AES-GCM authentication failed"),
        }
    }
}

/// Encrypt `plaintext` for the holder of `ek`.
fn hybrid_encrypt(ek: &[u8], plaintext: &[u8]) -> Result<HybridCiphertext, HybridError> {
    // Fresh encapsulation randomness; `encaps_derand` checks ek (FIPS 203 7.2).
    let mut m = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *m);
    let (kem_ct, shared_secret) = ml_kem_512::encaps_derand(ek, &m)?;
    let shared_secret = Zeroizing::new(shared_secret);

    let cipher = Aes256Gcm::new_from_slice(&*shared_secret).expect("32-byte key");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let aes_ct = cipher.encrypt(&nonce, plaintext).map_err(|_| HybridError::Authentication)?;

    Ok(HybridCiphertext { kem_ct, nonce: nonce.into(), aes_ct })
}

/// Decrypt with the recipient's decapsulation key.
///
/// A tampered KEM ciphertext does not produce an error from `decaps`: FIPS 203
/// implicit rejection returns a pseudorandom key instead, and the AES-GCM tag
/// check then fails. That is the intended way such tampering surfaces.
fn hybrid_decrypt(kp: &KeyPair, ct: &HybridCiphertext) -> Result<Vec<u8>, HybridError> {
    let shared_secret = Zeroizing::new(ml_kem_512::decaps(&*kp.dk, &ct.kem_ct)?);
    let cipher = Aes256Gcm::new_from_slice(&*shared_secret).expect("32-byte key");
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(&ct.nonce), ct.aes_ct.as_ref())
        .map_err(|_| HybridError::Authentication)
}

fn main() {
    let sep = "=".repeat(70);
    println!("{sep}");
    println!("  HYBRID POST-QUANTUM ENCRYPTION: ML-KEM-512 + AES-256-GCM");
    println!("{sep}\n");

    println!("1. Generating ML-KEM-512 keypair...");
    let start = std::time::Instant::now();
    let kp = keygen();
    println!("   Done in {:.1} us (ek {} bytes, dk {} bytes)\n",
        start.elapsed().as_nanos() as f64 / 1000.0, EK_BYTES, DK_BYTES);

    let messages = [
        "Hello from the post-quantum world!",
        "This message is protected against both classical and quantum attackers.",
        "ML-KEM-512 provides IND-CCA2 security, AES-256-GCM provides authenticated encryption.",
        &"A".repeat(10_000),
    ];

    for (i, msg) in messages.iter().enumerate() {
        let display = if msg.len() > 60 {
            format!("{}... ({} bytes)", &msg[..57], msg.len())
        } else {
            msg.to_string()
        };
        println!("2.{}. Encrypting: \"{}\"", i + 1, display);

        let start = std::time::Instant::now();
        let ct = hybrid_encrypt(&kp.ek, msg.as_bytes()).expect("encrypt");
        let enc_time = start.elapsed();
        println!("     ML-KEM ciphertext: {} bytes", CT_BYTES);
        println!("     AES-GCM ciphertext: {} bytes (plaintext {} + tag 16)", ct.aes_ct.len(), msg.len());
        println!("     Total overhead: {} bytes", CT_BYTES + 12 + 16);
        println!("     Encrypt time: {:.1} us", enc_time.as_nanos() as f64 / 1000.0);

        let start = std::time::Instant::now();
        let plaintext = hybrid_decrypt(&kp, &ct).expect("decrypt");
        let dec_time = start.elapsed();
        assert_eq!(plaintext, msg.as_bytes(), "roundtrip failed");
        println!("     Decrypt time: {:.1} us", dec_time.as_nanos() as f64 / 1000.0);
        println!("     Roundtrip: OK\n");
    }

    println!("3. Tamper detection...");
    let ct = hybrid_encrypt(&kp.ek, b"secret data").expect("encrypt");

    let mut tampered = ct.clone();
    tampered.aes_ct[0] ^= 1;
    match hybrid_decrypt(&kp, &tampered) {
        Err(e @ HybridError::Authentication) => println!("   Tampered AES ciphertext rejected: {e}"),
        other => panic!("tampered AES ciphertext was not rejected: {other:?}"),
    }

    // Flipping any bit of the KEM ciphertext must change the derived key
    // (implicit rejection), so the AES-GCM tag check fails.
    for bit in 0..8 {
        let mut tampered = ct.clone();
        tampered.kem_ct[0] ^= 1 << bit;
        match hybrid_decrypt(&kp, &tampered) {
            Err(HybridError::Authentication) => {}
            other => panic!("tampered KEM ciphertext (bit {bit}) was not rejected: {other:?}"),
        }
    }
    println!("   Tampered ML-KEM ciphertext rejected for every bit of byte 0");

    let mut short = ct.kem_ct.to_vec();
    short.pop();
    assert_eq!(ml_kem_512::decaps(&*kp.dk, &short), Err(KemError::Length));
    println!("   Wrong-length ML-KEM ciphertext rejected\n");

    println!("{sep}");
    println!("  SECURITY PROPERTIES:");
    println!("  - Post-quantum KEM: ML-KEM-512 (NIST FIPS 203), NIST ACVP-validated code path");
    println!("  - Symmetric cipher: AES-256-GCM (NIST SP 800-38D)");
    println!("  - Randomness: OS CSPRNG for d, z, m and the GCM nonce");
    println!("  - KEM overhead: {} bytes per message", CT_BYTES);
    println!("  - Authentication: AES-GCM 128-bit tag + ML-KEM implicit rejection");
    println!("  - Secrets wiped on drop (zeroize)");
    println!("{sep}");
}
