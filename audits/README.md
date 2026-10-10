# Security audits of moduletto

Each review is recorded here with the commit it examined, the findings, what
was changed in response, and how the change was verified. Findings are fixed
in the tree before the review is published.

| Date | Reviewer | Reviewed commit | Findings | Status |
|---|---|---|---|---|
| 2026-10-10 | Claude Mythos 5.1 (Anthropic) | `7440768` | 1 critical, 3 medium, 4 low, 5 informational | All remediated in the commit that adds this file |

---

## 2026-10-10 — Review of the ML-KEM library and its constant-time layer

### Scope and method

The whole repository at commit `7440768854538b9e86657f9f66e407be1cef9b6b`
(`main`): the library (`src/`), both examples, the test suite and vectors, the
Coq proofs, the fuzz targets, CI, and the licensing and compliance documents.

Method: line-by-line reading of `src/kem.rs`, `src/modn_ct.rs`, `src/ntt.rs`,
`src/modn.rs` and `src/wasm.rs` against FIPS 203 and the pq-crystals reference;
a proof-of-concept program against the public API for the critical finding;
inspection of release-build assembly for hardware divide instructions;
`cargo audit` over the lock file; a check of commit signatures and repository
metadata. No machine-level timing measurement (dudect, ctgrind) was run.

### Findings

| # | Severity | Finding | Location (at reviewed commit) |
|---|---|---|---|
| 1 | **Critical** | Implicit-rejection mask leaks the real shared secret on tampered ciphertexts | `src/kem.rs` decaps, lines 1628–1642 |
| 2 | Medium | Hybrid example carries its own round-3 Kyber with variable-time secret arithmetic | `examples/hybrid_pq_aes.rs` |
| 3 | Medium | Secret material not wiped; serialized decapsulation key passes through a heap buffer | `src/kem.rs` |
| 4 | Medium | Documentation claims constant time is "formally verified"; one `Admitted` lemma | `README.md`, `src/lib.rs`, `src/modn_ct.rs`, `proofs/NTT.v` |
| 5 | Low | Secret-dependent division by q (KyberSlash pattern) in message decode and compression | `src/kem.rs` lines 1407, 1508; both examples |
| 6 | Low | No bound on the modulus of the generic `ModN<N>`; large N wraps silently in release | `src/modn.rs` |
| 7 | Low | `repository` field in the manifest names an unrelated project | `Cargo.toml` |
| 8 | Low | Compliance document says all commits are signed; one is not | `COMPLIANCE.md` |
| 9 | Info | Dependency audit clean (80 crates, no RustSec advisories) | `Cargo.lock` |
| 10 | Info | CI actions pinned by tag, no advisory audit, release-mode tests only | `.github/workflows/ci.yml` |
| 11 | Info | No `SECURITY.md` | repository root |
| 12 | Info | Compiled Coq artefacts and caches committed | `proofs/` |
| 13 | Info | No RNG-backed API; every integrator must wire a CSPRNG | `src/kem.rs` |

### 1. Critical — implicit rejection leaks the real shared secret

**What.** Decapsulation compared the input ciphertext with the re-encrypted
one byte by byte and accumulated a mask with `eq &= !(a ^ b).wrapping_neg()`.
That expression equals `(a ^ b) - 1`. It is all-zero only when the two bytes
differ in exactly bit 0. For any other single-byte difference the mask kept
some bits set, and the returned "rejection" key was a bit-wise blend of the
real shared secret K' and J(z ‖ c).

**Impact.** This is the oracle the Fujisaki–Okamoto transform exists to deny.
A proof of concept against ML-KEM-512 flipped one bit of ciphertext byte 0 and
observed decapsulation's output:

| Bit flipped | Output | Bits of real K leaked per byte |
|---|---|---|
| 0 | J(z ‖ c') | 0 |
| 1 | (K & 0x01) ‖ (J & 0xFE) | 1 |
| 2 | (K & 0x03) ‖ (J & 0xFC) | 2 |
| 3–6 | mask 0x07 … 0x3F | 3–6 |
| 7 | J(z ‖ c') (the flip changed the decrypted message, so rejection happened by luck) | 0 |

Two queries recover the whole session key. More seriously, an attacker who
can tell whether a derived key "works" learns the decryption of chosen
ciphertexts, which is the entry point to the published key-recovery attacks
on the underlying CPA-secure scheme. The NIST decapsulation vectors did not
catch it: their tampered ciphertexts differ in many bytes, and the AND of many
`(x − 1)` values collapses to zero. The existing test flipped bit 0, the one
value for which the idiom works.

**Fix.** The comparison and the selection now go through `subtle`:
`ConstantTimeEq::ct_eq` over each ciphertext component folds into one
`Choice`, and `u8::conditional_select` picks between K' and J(z ‖ c) with an
all-or-nothing choice behind an optimisation barrier. The same idiom in the
three backends of `examples/kyber_benchmark.rs` is replaced with an OR
accumulator and a widening negate (`((diff as u16).wrapping_neg() >> 8) as u8`).

**Verification.** `tests::implicit_rejection_is_all_or_nothing` in
`src/kem.rs` and `implicit_rejection_matches_shake256_for_every_bit` in
`tests/kem_kat.rs` flip every bit of seven byte positions, for both parameter
sets, and require the output to equal an independent SHAKE256(z ‖ c'). The
proof of concept now reports J(z ‖ c') for all eight bits. The NIST vectors
still pass for the library and for all three example backends.

### 2. Medium — hybrid example used its own round-3 Kyber

The example implemented key generation with G(seed) instead of G(d ‖ k),
hashed m before use, applied the round-3 KDF, sampled s and e with η = 2 where
ML-KEM-512 needs 3, derived z from sigma, multiplied the secret `s_hat`
through the variable-time `ModN` operators (whose multiply is a division), and
had finding 1. The README presented it as a complete hybrid system.

**Fix.** Rewritten on `moduletto::kem::ml_kem_512`. Randomness for d, z, m
and the GCM nonce comes from the OS; decapsulation keys and shared secrets are
held in `zeroize::Zeroizing`. The tamper test now flips every bit of a KEM
ciphertext byte as well as the AES ciphertext and expects an authentication
failure. The README section describes what the example now does.

### 3. Medium — secrets not wiped

**Fix.** `zeroize` added as a dependency (no default features).
`SecretKey16` wipes `s_hat` and `z` on drop. Key generation wipes the G
output, sigma and the error vector; encapsulation wipes the G output, the
randomness seed, r, e1, e2, the encoded message and the uncompressed
ciphertext; decapsulation wipes `v − s·u`, m', K' and the rejection key.
`dk_to_bytes` and `ek_to_bytes` now write into caller-owned arrays, so no
heap buffer holds the decapsulation key. Module and README documentation say
that the returned arrays are the caller's to wipe, and that compiler-made
stack copies are outside the crate's control.

### 4. Medium — overstated verification claims

**Fix.** README, `src/lib.rs` and `src/modn_ct.rs` now say the Coq proofs
establish functional correctness of the branchless formulas, that no
machine-level timing verification has been done, and that the multiply can
leak on cores without a fixed-latency multiplier. The `Admitted` lemma for NTT
additivity in `proofs/NTT.v` is now proved (induction over the index list with
generalised accumulators); `make coq` type-checks all four files with no
axioms and no `Admitted`, and the OCaml harness passes 27,185 checks.

### 5. Low — division by q on secret data

Release-build assembly for aarch64 contained no hardware divide, so LLVM was
strength-reducing the constant division at opt-level 3. That is not
guaranteed at `opt-level = "s"`/`"z"`, in debug builds, or on other backends.

**Fix.** `compress_coeff` and `msg_decode_i16` use the pq-crystals fixed-point
reciprocals (d = 10: `×1290167 >> 32`; d = 4 and message decoding:
`×80635 >> 28`). Message decoding first brings its (−q, 2q) input to [0, q)
with two masked steps. `tests::compress_matches_division` and
`tests::msg_decode_matches_division` check every input value against the
rounding division. The same change is applied in `examples/kyber_benchmark.rs`.

### 6–8. Low

- `ModN<N>` now carries a compile-time assertion that `0 < N < 2^31`,
  referenced from `new`, `zero` and `one`; a `compile_fail` doc test covers
  `N = 2^31`.
- `Cargo.toml` `repository` points at `crabnebula-dev/moduletto`.
- `COMPLIANCE.md` now says merge commits and releases are signed, and that
  contributor commits may not be.

### 9–13. Informational

- `cargo audit`: no advisories. Added dependencies: `zeroize`, optional
  `getrandom`.
- CI: actions pinned to commit SHAs; a separate `audit` job runs
  `cargo audit`; tests run in debug mode (overflow checks) as well as release,
  and with the `getrandom` feature; examples are built. `.github/dependabot.yml`
  proposes weekly dependency and action updates.
- `SECURITY.md` added, pointing to private reporting and the timelines in
  `COMPLIANCE.md`.
- Compiled Coq artefacts removed from version control and ignored; `make coq`
  regenerates them.
- `kem::*::keygen()` and `kem::*::encaps(ek)` added behind the `getrandom`
  feature, drawing d, z and m from the OS CSPRNG. `KemError::Randomness`
  reports a failed OS source.

### Residual risks and open items

- Constant-time behaviour is argued from code shape, not measured. A dudect
  or ctgrind run on the release build of `decaps` would close this.
- Stack copies of secret arrays made by the compiler are not wiped.
- The Coq proofs are not built in CI (no Rocq toolchain there).
- This review was carried out by an AI system. It found a real,
  reproducible flaw, but it is not a substitute for a human cryptographic
  review before the crate is relied on in production.

### Verification record

| Check | Result |
|---|---|
| `cargo test --release` (library, doc tests, NIST ACVP vectors, new regression tests) | pass |
| `cargo test` (debug, overflow checks on) | pass |
| `cargo test --release --features getrandom` | pass |
| no_std rlib builds, with and without `alloc` | pass |
| `cargo check --features wasm --target wasm32-unknown-unknown` | pass |
| `cargo run --release --example kyber_benchmark` (180 KAT cases over three backends, codec and sponge equivalence) | pass |
| `cargo run --release --example hybrid_pq_aes` | pass |
| `make -C proofs coq` and `make -C proofs ocaml` | pass, 0 `Admitted`, 27,185/27,185 |
| `cargo audit` | 0 advisories |
| Proof of concept (single-bit flips, ML-KEM-512) | J(z ‖ c') for all 8 bits |

---

## Seal

```
┌─────────────────────────────────────────────────────────────┐
│  AUDITED BY MYTHOS                                          │
│  Claude Mythos 5.1 · Anthropic                              │
│                                                             │
│  Reviewed commit  7440768854538b9e86657f9f66e407be1cef9b6b  │
│  Branch           main                                      │
│  Audit started    2026-10-10T06:01:40Z                      │
│  Audit sealed     2026-10-10T06:29:14Z                      │
│  Elapsed          27 minutes, review and remediation        │
│  Remediation      the commit that introduces this file      │
└─────────────────────────────────────────────────────────────┘
```

Operator: Daniel Thompson-Yvetot (CrabNebula Ltd), who selected the
remediation options (zeroize crate, getrandom feature, removal of proof
artefacts, single commit on a branch).
