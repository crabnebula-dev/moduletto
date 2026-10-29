//! The library `dsa` module against the NIST ACVP ML-DSA vectors (FIPS 204)
//! for ML-DSA-65: 25 keyGen cases, 90 sigGen cases and 45 sigVer cases. The
//! sigGen cases cover the external (pure), internal and external-mu
//! interfaces, each deterministic and hedged. The sigVer cases cover the same
//! three interfaces, with 36 negative cases. HashML-DSA is out of scope.
//! `tests/kat/extract.mjs` regenerates the files from an ACVP-Server checkout.
//!
//! The API tests after the vectors check what ACVP does not. They cover the
//! context length limit and the input length checks (FIPS 204 section
//! 3.6.2). They also cover single-bit changes to signatures, keys, messages
//! and contexts, determinism, and the hash derivations of `tr` and μ
//! against an independent SHAKE256.

use ml_dsa_65::{PK_BYTES, SIG_BYTES, SK_BYTES};
use moduletto::dsa::{ml_dsa_65, DsaError, MAX_CONTEXT_BYTES, MU_BYTES, RND_BYTES, SEED_BYTES};
use sha3::digest::{ExtendableOutput, Update, XofReader};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn records(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().collect())
}

/// SHAKE256 with a 64-byte output: FIPS 204 H(str, 64).
fn h64(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = sha3::Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 64];
    h.finalize_xof().read(&mut out);
    out
}

/// FIPS 204 Algorithm 2 line 10: M' = 0 ‖ |ctx| ‖ ctx ‖ M.
fn m_prime(m: &[u8], ctx: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8, ctx.len() as u8];
    out.extend_from_slice(ctx);
    out.extend_from_slice(m);
    out
}

fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
    v.try_into().unwrap()
}

/// `(pk, sk, message, context, signature)`.
type Fixture = (
    [u8; PK_BYTES],
    [u8; SK_BYTES],
    Vec<u8>,
    Vec<u8>,
    [u8; SIG_BYTES],
);

/// A key pair and a deterministic signature over a fixed message and context.
fn fixture() -> Fixture {
    let (pk, sk) = ml_dsa_65::keygen_internal(&[0x5a; SEED_BYTES]);
    let m = b"moduletto ML-DSA-65 fixture message".to_vec();
    let ctx = b"fixture context".to_vec();
    let sig = ml_dsa_65::sign(&sk, &m, &ctx, &[0; RND_BYTES]).unwrap();
    assert!(
        ml_dsa_65::verify(&pk, &m, &ctx, &sig),
        "fixture signature must verify"
    );
    (pk, sk, m, ctx, sig)
}

/// ACVP keyGen: ML-DSA.KeyGen_internal (FIPS 204 Algorithm 6).
#[test]
fn acvp_ml_dsa_65_keygen() {
    let mut n = 0;
    for f in records(include_str!("kat/ml_dsa_65_keygen_fips204.txt")) {
        assert_eq!(f[0], "keygen");
        let (pk, sk) = ml_dsa_65::keygen_internal(&arr(&unhex(f[2])));
        assert_eq!(pk.as_slice(), unhex(f[3]), "keygen tc{} pk", f[1]);
        assert_eq!(sk.as_slice(), unhex(f[4]), "keygen tc{} sk", f[1]);
        // The in-place variant writes the same keys over any prior content.
        let mut pk2 = [0xffu8; ml_dsa_65::PK_BYTES];
        let mut sk2 = [0xffu8; ml_dsa_65::SK_BYTES];
        ml_dsa_65::keygen_internal_into(&arr(&unhex(f[2])), &mut pk2, &mut sk2);
        assert_eq!((pk2, sk2), (pk, sk), "keygen_internal_into tc{}", f[1]);
        n += 1;
    }
    assert_eq!(n, 25);
}

/// ACVP sigGen: ML-DSA.Sign (Algorithm 2), ML-DSA.Sign_internal (Algorithm 7)
/// and Algorithm 7 with an external μ, each deterministic and hedged. Every
/// produced signature must also verify under the matching interface, and the
/// three interfaces must agree on the external cases.
#[test]
fn acvp_ml_dsa_65_siggen() {
    let mut counts = std::collections::BTreeMap::new();
    for f in records(include_str!("kat/ml_dsa_65_siggen_fips204.txt")) {
        assert_eq!(f[0], "sign");
        let (tc, iface, mode) = (f[1], f[2], f[3]);
        let (ctx, msg, rnd) = (unhex(f[4]), unhex(f[5]), arr::<RND_BYTES>(&unhex(f[6])));
        let (pk, sk, want) = (unhex(f[7]), unhex(f[8]), unhex(f[9]));
        if mode == "det" {
            assert_eq!(rnd, [0; RND_BYTES], "sign tc{tc}: det rnd must be zero");
        }
        let got = match iface {
            "external" => {
                let sig = ml_dsa_65::sign(&sk, &msg, &ctx, &rnd);
                let mp = m_prime(&msg, &ctx);
                assert_eq!(
                    ml_dsa_65::sign_internal(&sk, &mp, &rnd),
                    sig,
                    "sign tc{tc}: internal"
                );
                let mu = ml_dsa_65::external_mu(&pk, &msg, &ctx).unwrap();
                assert_eq!(ml_dsa_65::sign_mu(&sk, &mu, &rnd), sig, "sign tc{tc}: mu");
                let sig = sig.unwrap();
                assert!(
                    ml_dsa_65::verify(&pk, &msg, &ctx, &sig),
                    "sign tc{tc}: verify"
                );
                sig
            }
            "internal" => {
                let sig = ml_dsa_65::sign_internal(&sk, &msg, &rnd).unwrap();
                assert!(
                    ml_dsa_65::verify_internal(&pk, &msg, &sig),
                    "sign tc{tc}: verify"
                );
                sig
            }
            "mu" => {
                let mu = arr::<MU_BYTES>(&msg);
                let sig = ml_dsa_65::sign_mu(&sk, &mu, &rnd).unwrap();
                assert!(ml_dsa_65::verify_mu(&pk, &mu, &sig), "sign tc{tc}: verify");
                sig
            }
            other => panic!("unknown interface {other}"),
        };
        assert_eq!(
            got.as_slice(),
            want,
            "sign tc{tc} {iface} {mode}: signature"
        );
        *counts.entry((iface, mode)).or_insert(0) += 1;
    }
    let want: Vec<_> = ["external", "internal", "mu"]
        .iter()
        .flat_map(|i| [((*i, "det"), 15), ((*i, "hedged"), 15)])
        .collect();
    assert_eq!(counts.into_iter().collect::<Vec<_>>(), want);
}

/// ACVP sigVer: ML-DSA.Verify (Algorithm 3), ML-DSA.Verify_internal
/// (Algorithm 8) and Algorithm 8 with an external μ, including every
/// negative case (modified message, commitment, response z and hint).
#[test]
fn acvp_ml_dsa_65_sigver() {
    let (mut pass, mut fail) = (0, 0);
    for f in records(include_str!("kat/ml_dsa_65_sigver_fips204.txt")) {
        assert_eq!(f[0], "verify");
        let (tc, iface, expect) = (f[1], f[2], f[3] == "pass");
        let (ctx, msg, pk, sig) = (unhex(f[4]), unhex(f[5]), unhex(f[6]), unhex(f[7]));
        let reason = f[8..].join(" ");
        let got = match iface {
            "external" => {
                let got = ml_dsa_65::verify(&pk, &msg, &ctx, &sig);
                let mp = m_prime(&msg, &ctx);
                assert_eq!(
                    ml_dsa_65::verify_internal(&pk, &mp, &sig),
                    got,
                    "verify tc{tc}: internal"
                );
                let mu = ml_dsa_65::external_mu(&pk, &msg, &ctx).unwrap();
                assert_eq!(
                    ml_dsa_65::verify_mu(&pk, &mu, &sig),
                    got,
                    "verify tc{tc}: mu"
                );
                got
            }
            "internal" => ml_dsa_65::verify_internal(&pk, &msg, &sig),
            "mu" => ml_dsa_65::verify_mu(&pk, &arr(&msg), &sig),
            other => panic!("unknown interface {other}"),
        };
        assert_eq!(got, expect, "verify tc{tc} {iface}: {reason}");
        if expect {
            pass += 1;
        } else {
            fail += 1;
        }
    }
    assert_eq!((pass, fail), (9, 36));
}

/// FIPS 204 Tables 1 and 2: the ML-DSA-65 sizes.
#[test]
fn sizes_match_fips_204_table_2() {
    assert_eq!((PK_BYTES, SK_BYTES, SIG_BYTES), (1952, 4032, 3309));
    assert_eq!(
        (SEED_BYTES, RND_BYTES, MU_BYTES, MAX_CONTEXT_BYTES),
        (32, 32, 64, 255)
    );
}

/// FIPS 204 Algorithms 2 and 3, line 1: a context string longer than 255
/// bytes is an error for signing and a failed verification.
#[test]
fn context_longer_than_255_bytes_is_refused() {
    let (pk, sk) = ml_dsa_65::keygen_internal(&[7; SEED_BYTES]);
    let m = b"context length";
    let ctx = [0xc7u8; MAX_CONTEXT_BYTES + 1];
    let at_limit = &ctx[..MAX_CONTEXT_BYTES];
    let sig = ml_dsa_65::sign(&sk, m, at_limit, &[0; RND_BYTES]).unwrap();
    assert!(ml_dsa_65::verify(&pk, m, at_limit, &sig));
    assert!(ml_dsa_65::external_mu(&pk, m, at_limit).is_ok());

    for len in [MAX_CONTEXT_BYTES + 1, 1000] {
        let long = vec![0xc7u8; len];
        assert_eq!(
            ml_dsa_65::sign(&sk, m, &long, &[0; RND_BYTES]),
            Err(DsaError::Context)
        );
        assert_eq!(
            ml_dsa_65::external_mu(&pk, m, &long),
            Err(DsaError::Context)
        );
        assert!(!ml_dsa_65::verify(&pk, m, &long, &sig));
    }
    // A 256-byte context must not be truncated to the 255-byte one that signed.
    assert!(!ml_dsa_65::verify(&pk, m, &ctx, &sig));
    #[cfg(feature = "getrandom")]
    assert_eq!(ml_dsa_65::sign_hedged(&sk, m, &ctx), Err(DsaError::Context));
}

/// Wrong-length keys are refused with `DsaError::Length`, and wrong-length
/// public keys or signatures fail verification (FIPS 204 section 3.6.2).
/// The lengths include the ML-DSA-44 and ML-DSA-87 sizes from Table 2.
#[test]
fn wrong_length_inputs_are_refused() {
    let (pk, sk, m, ctx, sig) = fixture();
    let mu = ml_dsa_65::external_mu(&pk, &m, &ctx).unwrap();
    let mp = m_prime(&m, &ctx);
    let rnd = [0; RND_BYTES];
    assert!(ml_dsa_65::verify_internal(&pk, &mp, &sig));
    assert!(ml_dsa_65::verify_mu(&pk, &mu, &sig));

    let resize = |v: &[u8], n: usize| {
        let mut w = v.to_vec();
        w.resize(n, 0);
        w
    };
    for n in [0, 1, 2560, 4896, SK_BYTES - 1, SK_BYTES + 1] {
        let bad = resize(&sk, n);
        assert_eq!(
            ml_dsa_65::sign(&bad, &m, &ctx, &rnd),
            Err(DsaError::Length),
            "sk {n}"
        );
        assert_eq!(
            ml_dsa_65::sign_internal(&bad, &mp, &rnd),
            Err(DsaError::Length),
            "sk {n}"
        );
        assert_eq!(
            ml_dsa_65::sign_mu(&bad, &mu, &rnd),
            Err(DsaError::Length),
            "sk {n}"
        );
        #[cfg(feature = "getrandom")]
        assert_eq!(
            ml_dsa_65::sign_hedged(&bad, &m, &ctx),
            Err(DsaError::Length),
            "sk {n}"
        );
    }
    for n in [0, 1, 32, 1312, 2592, PK_BYTES - 1, PK_BYTES + 1] {
        let bad = resize(&pk, n);
        assert_eq!(
            ml_dsa_65::external_mu(&bad, &m, &ctx),
            Err(DsaError::Length),
            "pk {n}"
        );
        assert!(!ml_dsa_65::verify(&bad, &m, &ctx, &sig), "pk {n}");
        assert!(!ml_dsa_65::verify_internal(&bad, &mp, &sig), "pk {n}");
        assert!(!ml_dsa_65::verify_mu(&bad, &mu, &sig), "pk {n}");
    }
    for n in [0, 1, 48, 2420, 4627, SIG_BYTES - 1, SIG_BYTES + 1] {
        let bad = resize(&sig, n);
        assert!(!ml_dsa_65::verify(&pk, &m, &ctx, &bad), "sig {n}");
        assert!(!ml_dsa_65::verify_internal(&pk, &mp, &bad), "sig {n}");
        assert!(!ml_dsa_65::verify_mu(&pk, &mu, &bad), "sig {n}");
    }
}

/// FIPS 204 Algorithm 8: changing any bit of the signature or the public key
/// makes verification fail. Debug builds flip one bit per byte (bit i mod 8)
/// to keep the run short; release builds flip all eight.
#[test]
fn flipped_bit_in_signature_or_public_key_fails_verification() {
    let (pk, _, m, ctx, sig) = fixture();
    let bits = |i: usize| {
        if cfg!(debug_assertions) {
            (i % 8)..(i % 8 + 1)
        } else {
            0..8
        }
    };
    for i in 0..SIG_BYTES {
        for b in bits(i) {
            let mut bad = sig;
            bad[i] ^= 1 << b;
            assert!(
                !ml_dsa_65::verify(&pk, &m, &ctx, &bad),
                "sig byte {i} bit {b}"
            );
        }
    }
    for i in 0..PK_BYTES {
        for b in bits(i) {
            let mut bad = pk;
            bad[i] ^= 1 << b;
            assert!(
                !ml_dsa_65::verify(&bad, &m, &ctx, &sig),
                "pk byte {i} bit {b}"
            );
        }
    }
}

/// Changing any bit of the message or the context makes verification fail,
/// as does moving bytes between them (M' binds |ctx|).
#[test]
fn flipped_bit_in_message_or_context_fails_verification() {
    let (pk, _, m, ctx, sig) = fixture();
    for i in 0..m.len() {
        for b in 0..8 {
            let mut bad = m.clone();
            bad[i] ^= 1 << b;
            assert!(
                !ml_dsa_65::verify(&pk, &bad, &ctx, &sig),
                "msg byte {i} bit {b}"
            );
        }
    }
    for i in 0..ctx.len() {
        for b in 0..8 {
            let mut bad = ctx.clone();
            bad[i] ^= 1 << b;
            assert!(
                !ml_dsa_65::verify(&pk, &m, &bad, &sig),
                "ctx byte {i} bit {b}"
            );
        }
    }
    let mut longer_ctx = ctx.clone();
    longer_ctx.push(m[0]);
    assert!(!ml_dsa_65::verify(&pk, &m[1..], &longer_ctx, &sig));
    assert!(!ml_dsa_65::verify(&pk, &m, &[], &sig));
    assert!(
        !ml_dsa_65::verify_internal(&pk, &m, &sig),
        "M must not verify as M'"
    );
}

/// FIPS 204 Algorithm 2 line 5: with rnd = {0}^32 signing is deterministic.
/// A different rnd gives a different signature that also verifies.
#[test]
fn deterministic_signing_is_reproducible() {
    let (pk, sk, m, ctx, sig) = fixture();
    let zero = [0; RND_BYTES];
    assert_eq!(ml_dsa_65::sign(&sk, &m, &ctx, &zero).unwrap(), sig);
    assert_eq!(
        ml_dsa_65::sign_internal(&sk, &m_prime(&m, &ctx), &zero).unwrap(),
        sig
    );
    let mu = ml_dsa_65::external_mu(&pk, &m, &ctx).unwrap();
    assert_eq!(ml_dsa_65::sign_mu(&sk, &mu, &zero).unwrap(), sig);

    let hedged = ml_dsa_65::sign(&sk, &m, &ctx, &[0x42; RND_BYTES]).unwrap();
    assert_ne!(hedged, sig);
    assert!(ml_dsa_65::verify(&pk, &m, &ctx, &hedged));
    assert_eq!(
        ml_dsa_65::sign(&sk, &m, &ctx, &[0x42; RND_BYTES]).unwrap(),
        hedged
    );

    let other_ctx = ml_dsa_65::sign(&sk, &m, b"another context", &zero).unwrap();
    assert_ne!(other_ctx, sig);

    // Key generation is a function of xi alone.
    let (pk2, sk2) = ml_dsa_65::keygen_internal(&[0x5a; SEED_BYTES]);
    assert_eq!((pk2, sk2), (pk, sk));
    let (pk3, _) = ml_dsa_65::keygen_internal(&[0x5b; SEED_BYTES]);
    assert_ne!(pk3, pk);
}

/// Empty message and empty context are valid inputs (ACVP has no empty
/// message case).
#[test]
fn empty_message_and_context_sign_and_verify() {
    let (pk, sk) = ml_dsa_65::keygen_internal(&[9; SEED_BYTES]);
    let sig = ml_dsa_65::sign(&sk, &[], &[], &[0; RND_BYTES]).unwrap();
    assert!(ml_dsa_65::verify(&pk, &[], &[], &sig));
    assert!(ml_dsa_65::verify_internal(&pk, &[0, 0], &sig));
    assert!(!ml_dsa_65::verify(&pk, &[0], &[], &sig));
}

/// Hash derivations against an independent SHAKE256 (the `sha3` crate):
/// pk and sk share ρ (Algorithms 22 and 24), sk holds tr = H(pk, 64)
/// (Algorithm 6 line 9), and μ = H(tr ‖ M', 64) (Algorithm 7 line 6).
#[test]
fn tr_and_mu_match_independent_shake256() {
    let (pk, sk, m, ctx, sig) = fixture();
    assert_eq!(&pk[..32], &sk[..32], "rho");
    let tr = h64(&[&pk]);
    assert_eq!(&sk[64..128], &tr, "tr");
    let mu = h64(&[&tr, &m_prime(&m, &ctx)]);
    assert_eq!(ml_dsa_65::external_mu(&pk, &m, &ctx).unwrap(), mu);
    assert!(ml_dsa_65::verify_mu(&pk, &mu, &sig));
    let mut bad = mu;
    bad[63] ^= 0x80;
    assert!(!ml_dsa_65::verify_mu(&pk, &bad, &sig));
}

/// FIPS 204 Algorithms 1 and 2 with the operating system's random source.
#[cfg(feature = "getrandom")]
#[test]
fn os_random_keygen_and_hedged_sign() {
    let (pk, sk) = ml_dsa_65::keygen().unwrap();
    let (pk2, _) = ml_dsa_65::keygen().unwrap();
    assert_ne!(pk, pk2);
    let m = b"hedged";
    let s1 = ml_dsa_65::sign_hedged(&sk, m, b"ctx").unwrap();
    let s2 = ml_dsa_65::sign_hedged(&sk, m, b"ctx").unwrap();
    assert_ne!(s1, s2);
    assert!(ml_dsa_65::verify(&pk, m, b"ctx", &s1));
    assert!(ml_dsa_65::verify(&pk, m, b"ctx", &s2));
    assert_ne!(
        s1,
        ml_dsa_65::sign(&sk, m, b"ctx", &[0; RND_BYTES]).unwrap()
    );
}

/// FIPS 204 Algorithm 1 into caller-owned storage: `keygen_into` fills both
/// arrays with a working key pair whose `pk` and `tr` match `sk`.
#[cfg(feature = "getrandom")]
#[test]
fn os_random_keygen_into() {
    let mut pk = Box::new([0u8; PK_BYTES]);
    let mut sk = Box::new([0u8; SK_BYTES]);
    ml_dsa_65::keygen_into(&mut pk, &mut sk).unwrap();
    assert_eq!(pk[..32], sk[..32], "ρ in pk and sk");
    assert_eq!(h64(&[&pk[..]])[..], sk[64..128], "tr = H(pk, 64)");
    let mut pk2 = Box::new([0u8; PK_BYTES]);
    let mut sk2 = Box::new([0u8; SK_BYTES]);
    ml_dsa_65::keygen_into(&mut pk2, &mut sk2).unwrap();
    assert_ne!(pk, pk2);
    let sig = ml_dsa_65::sign(&sk[..], b"into", b"", &[0; RND_BYTES]).unwrap();
    assert!(ml_dsa_65::verify(&pk[..], b"into", b"", &sig));
    assert!(!ml_dsa_65::verify(&pk2[..], b"into", b"", &sig));
}
