//! Fuzz target: ML-DSA-65 sign-then-verify round trip (FIPS 204)
//!
//! The input supplies the key generation seed ξ, the signing randomness rnd,
//! a context string of at most 255 bytes and the message. Key generation,
//! signing and verification must agree: the signature verifies through the
//! pure, internal and external-μ interfaces, all three signing interfaces
//! give the same signature, and a changed message, context or signature
//! bit fails verification.

#![no_main]

use libfuzzer_sys::fuzz_target;
use moduletto::dsa::ml_dsa_65::{self, SIG_BYTES};

fuzz_target!(|data: &[u8]| {
    if data.len() < 65 {
        return;
    }
    let xi: [u8; 32] = data[..32].try_into().unwrap();
    let rnd: [u8; 32] = data[32..64].try_into().unwrap();
    let rest = &data[65..];
    let ctx_len = (data[64] as usize).min(rest.len());
    let (ctx, msg) = rest.split_at(ctx_len);

    let (pk, sk) = ml_dsa_65::keygen_internal(&xi);
    let sig = ml_dsa_65::sign(&sk, msg, ctx, &rnd).unwrap();
    assert!(ml_dsa_65::verify(&pk, msg, ctx, &sig), "pure verify");

    // M' = 0 ‖ |ctx| ‖ ctx ‖ M (Algorithm 2 line 10).
    let mut m_prime = vec![0u8, ctx.len() as u8];
    m_prime.extend_from_slice(ctx);
    m_prime.extend_from_slice(msg);
    assert!(
        ml_dsa_65::verify_internal(&pk, &m_prime, &sig),
        "internal verify"
    );
    assert_eq!(ml_dsa_65::sign_internal(&sk, &m_prime, &rnd).unwrap(), sig);
    let mu = ml_dsa_65::external_mu(&pk, msg, ctx).unwrap();
    assert!(ml_dsa_65::verify_mu(&pk, &mu, &sig), "external-mu verify");
    assert_eq!(ml_dsa_65::sign_mu(&sk, &mu, &rnd).unwrap(), sig);

    // Changes that must fail.
    let mut longer = msg.to_vec();
    longer.push(0);
    assert!(
        !ml_dsa_65::verify(&pk, &longer, ctx, &sig),
        "longer message"
    );
    if !ctx.is_empty() {
        assert!(
            !ml_dsa_65::verify(&pk, msg, &ctx[1..], &sig),
            "shorter context"
        );
    }
    let bit = (xi[0] as usize | (xi[1] as usize) << 8) % (8 * SIG_BYTES);
    let mut flipped = sig;
    flipped[bit / 8] ^= 1 << (bit % 8);
    assert!(
        !ml_dsa_65::verify(&pk, msg, ctx, &flipped),
        "flipped signature bit {bit}"
    );
});
