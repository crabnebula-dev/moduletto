# moduletto vs LibOQS vs Kyber C Reference
## Benchmark Results

**Benchmark date**: 2026-08-11 (hashing + codec pass), 2026-08-10 (NTT pass)
**Platform**: macOS Darwin 25.5.0, Apple M5 (Mac17,2)
**Modulus**: q = 3329 (Kyber-512 / ML-KEM-512), degree n = 256

**Tools / versions**:
- moduletto: Criterion 0.7 for primitives; `examples/kyber_benchmark` (10,000 iterations, 100-iteration warmup) for the full KEM
- LibOQS 0.16.0: built from source at tag `0.16.0`, `cmake -DCMAKE_BUILD_TYPE=Release -DOQS_MINIMAL_BUILD=KEM_ml_kem_512 -DCMAKE_C_FLAGS="-O3 -march=native"`
- LibOQS 0.15.0: Homebrew bottle, same harness
- Kyber C Reference: pq-crystals/kyber `ref/`, `gcc -O3 -march=native -DKYBER_K=2` — **carried over from 2026-03-19, not re-measured**

Both LibOQS versions were re-measured on this machine in the same session as the
moduletto figures, through an identical harness (10,000 iterations, best of 5
repeats, keygen + encaps + decaps, shared-secret agreement asserted).

---

## Full ML-KEM-512 session

| Phase | moduletto NEON i16 | LibOQS 0.16.0 | LibOQS 0.15.0 | Kyber C Ref |
|-------|:------------------:|:-------------:|:-------------:|:-----------:|
| Key generation | **4.07 µs** | 4.72 µs | 5.80 µs | 14.93 µs |
| Encapsulation | **3.84 µs** | 5.25 µs | 6.60 µs | 14.57 µs |
| Decapsulation | **5.80 µs** | 6.22 µs | 8.03 µs | 18.37 µs |
| **Total / session** | **13.7–14.1 µs** | 16.19 µs | 20.43 µs | 47.87 µs |
| Sessions / sec | **~72,000** | 61,800 | 48,900 | 20,900 |
| vs LibOQS 0.16.0 | **0.85×** | baseline | 1.26× | 2.96× |

Both implementations pass the same NIST ACVP ML-KEM-512 vectors, so this is a
like-for-like comparison of the same algorithm.

**LibOQS 0.16.0 (released 2026-07-09) is itself 1.26× faster than 0.15.0.**
Earlier revisions of this document compared against 0.15.0 at 22.44 µs;
re-measuring 0.15.0 here gives 20.43 µs, so that figure was also pessimistic.
Both corrections cut against us.

moduletto's other two backends, for reference:

| Backend | Total |
|---------|------:|
| sha3 crate + asm + i64 NTT | 34.6 µs |
| inline Keccak + i64 NTT | 36.6 µs |

---

## Conformance: FIPS 203 known-answer tests

`examples/kyber_benchmark.rs` runs the official NIST ACVP ML-KEM-512 vectors on
every invocation — 25 keyGen (AFT), 25 encapsulation (AFT), 10 decapsulation
(VAL, including modified-ciphertext cases that must return the implicit-rejection
key). Vectors live in `tests/kat/ml_kem_512_fips203.txt`, extracted verbatim from
[usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server).

Introducing them found that the implementation was **not ML-KEM**. The previous
self-check — encapsulate, decapsulate, confirm the shared secrets match — is
satisfied by any internally coherent scheme, so it had never been in a position
to notice:

| Deviation | Was | FIPS 203 |
|-----------|-----|----------|
| KeyGen domain separation | `G(d)` | `G(d ‖ k)` |
| Encaps hash input | `G(H(m) ‖ H(ek))` | `G(m ‖ H(ek))` |
| Shared secret | `KDF(K ‖ H(c))` (round-3) | `K` |
| Implicit rejection | `SHA3-256(z ‖ H(c))` | `J(z ‖ c)` = `SHAKE256(z ‖ c, 32)` |
| Rejection seed `z` | **hardcoded to zero** | random, stored in `dk` |
| Noise parameter | η₁ = 2 | η₁ = 3 (η₂ = 2) |

The zeroed `z` is the one that is a security bug rather than a conformance nit:
implicit rejection is supposed to return a key the attacker cannot predict, and
a constant `z` makes it computable by anyone holding the ciphertext.

Fixing all six made the KEM **faster**, 16.2 → 13.9 µs. Round-3's final KDF hashes
the entire 768-byte ciphertext with SHA3-256 — six Keccak permutations per
encapsulation, and again during decapsulation's re-encryption — and FIPS 203 does
not have it. That saving outweighs the wider η₁ = 3 noise sampling (192 bytes per
polynomial instead of 128, so two SHAKE-256 blocks instead of one).

---

## History: where the time went

| Date | Total | What changed |
|------|------:|--------------|
| 2026-03-19 | 45.8 µs | NEON i16 NTT added (len ≥ 8 layers only) |
| 2026-08-10 | 43.6 µs | NTT pass: lazy reduction, all NTT layers vectorised |
| 2026-08-11 | 27.7 µs | Bit-packing codecs replaced with grouped packing |
| 2026-08-11 | 16.1 µs | Two-lane SHA3 Keccak + right-sized SHAKE squeezing |
| 2026-08-11 | **13.9 µs** | FIPS 203 conformance (net saving: round-3 KDF removed) |

### 1. The NTT pass (2026-08-10)

Criterion, before → after, same machine and session:

| Benchmark | Before | After | Speedup |
|-----------|-------:|------:|--------:|
| `ntt/forward_ntt` | 579 ns | **176 ns** | 3.3× |
| `ntt/inverse_ntt` | 787 ns | **239 ns** | 3.3× |
| `ntt/mul_ntt` | 2288 ns | **503 ns** | 4.5× |
| `ntt/mul_schoolbook` | 27.3 µs | **8.8 µs** | 3.1× |
| `ntt/poly_sub` | 74.1 ns | 63 ns | 1.2× |
| `ntt_ct/ct_forward_ntt` | 2810 ns | **177 ns** | 15.9× |
| `ntt_ct/ct_inverse_ntt` | 3014 ns | **239 ns** | 12.6× |
| `ntt_ct/ct_mul_ntt` | 11338 ns | **504 ns** | 22.5× |
| `ntt_ct/ct_poly_add` | 244.6 ns | **63 ns** | 3.9× |
| `ntt_ct/ct_poly_sub` | 178.5 ns | **63 ns** | 2.8× |

- **`subtle` built with `core_hint_black_box`** (one line in `Cargo.toml`). The
  default barrier is `read_volatile`, which forces a stack round-trip on every
  `Choice` and blocks vectorisation; `core::hint::black_box` is a register
  fence. 30–44% on every constant-time path on its own.
- **Lazy reduction.** With q = 3329 in a 64-bit register there are ~50 spare
  bits, so coefficients stay in a redundant centred representation through all
  seven layers and are canonicalised once at the end. Only multiplies are
  reduced, by a branchless rounding Barrett step — proved correct in
  `proofs/BarrettReduction.v` (`fq_reduce_bound`, `fq_reduce_kyber`).
- **Constant-time became branchless rather than barrier-guarded.** The old
  `ct_ntt` paid a `subtle` barrier per operation — three per butterfly, 2688 per
  transform — to stop the compiler folding a `select` into a branch. The lazy
  kernel contains no `select`, so the barriers protected nothing while costing
  ~4×. The `ct_*` transforms are now the same code as their variable-time
  counterparts. The per-scalar `modn_ct` primitives are unchanged.
- **All seven NTT layers vectorised.** AArch64 has no 64-bit SIMD multiply, so
  an i64 NTT can never vectorise its multiplies; the library narrows to i16 and
  runs eight Montgomery butterflies per instruction. Critically the two
  narrowest layers (len = 4, len = 2) must be vectorised too — left scalar, as
  in the original prototype, they cost ~250 ns of a ~300 ns transform while the
  five wide layers together take only ~53 ns. They need `uzp`/`zip`
  deinterleaving because both halves of a butterfly share a vector.
- Compile-time twiddle tables (was `OnceLock`), lazy accumulation in
  `mul_schoolbook`, branchless polynomial add/sub.

### 2. Bit-packing codecs (2026-08-11): 43.6 → 27.7 µs

Profiling one encapsulation showed `poly_compress_i16(d=10)` at **3627 ns** —
more than the four SHAKE-128 matrix streams put together, and encapsulation runs
two of them. The cause was packing d-bit values one bit at a time:

```rust
out[bit_pos / 8] |= bit << (bit_pos % 8);
```

2560 iterations for one polynomial, each a read-modify-write of the same output
byte, so the whole loop is one serial store→load dependency chain. Replacing it
with the reference's grouped packing (4 coefficients into 5 bytes for d = 10, 2
into 1 for d = 4) took it to **103 ns — a 35× improvement on that function**:

| Codec | Before | After |
|-------|-------:|------:|
| `poly_compress_i16` (d=10) | 3627 ns | **103 ns** |
| `poly_compress_i16` (d=4) | 335 ns | **51 ns** |
| `poly_decompress_i16` (d=10) | 792 ns | **41 ns** |
| `poly_decompress_i16` (d=4) | 222 ns | **21 ns** |

The bit-at-a-time versions are retained as `*_generic` and serve as the oracle
the fast paths are checked against.

### 3. Hashing (2026-08-11): 27.7 → 16.1 µs

After the codec fix, hashing was ~65% of the session. Two problems, both worth
more than the earlier note about "hashing overhead" suggested:

**The SHA3 instructions were half idle.** ARMv8.2 FEAT_SHA3 (EOR3, RAX1, XAR,
BCAX) operates on 128-bit vectors, which hold *two* 64-bit Keccak lanes. The
`keccak` crate's asm path — what `sha3 = { features = ["asm"] }` selects — drives
a single state through them and leaves the upper half of every register unused.
That is why the 2026-03-19 session concluded "SHA3 hardware gives no measurable
advantage": it was buying a 2× and immediately throwing it away.

| Keccak-f1600 implementation | ns / permutation |
|-----------------------------|-----------------:|
| inline XKCP (this example, scalar) | 129.3 |
| `sha3` crate, `asm` feature | 118.4 |
| **two lanes, FEAT_SHA3 intrinsics** | **56.5** |

Kyber has ample independent streams to pair: the k² = 4 matrix polynomials and
the k noise polynomials each come from a separate SHAKE invocation.

**The matrix sampler over-squeezed.** `gen_poly_uniform_i16` always squeezed a
fixed 1024-byte buffer — 7 permutations — where rejection sampling needs ~3.3 on
average. It also read out of bounds, and panicked, in the (vanishingly unlikely)
case that 1024 bytes were not enough; the streaming replacement has no bound.

Combined effect on one encapsulation:

| | Before | After |
|--|------:|------:|
| `gen_matrix_i16` (4 SHAKE-128 streams) | 4645 ns | **1402 ns** |
| noise sampling (5 × SHAKE-256 + CBD) | 1140 ns | **~590 ns** |
| Keccak permutations per session | 130 | 34 scalar + paired |

Single-lane use of the SHA3 instructions for the remaining unpairable hashes
(H(pk), H(ct), G, KDF — each one sequential stream) was tried and measured no
faster: the per-call state conversion cancels the ~16 ns instruction advantage.
It was reverted rather than kept as unearned complexity.

### Correctness

- 39 library unit tests, including cross-backend tests checking the NEON int16
  backend against the portable i64 kernel coefficient-by-coefficient on random
  full-degree polynomials.
- **FIPS 203 KATs**: 60 official NIST ACVP ML-KEM-512 vectors, run on every
  invocation of the example, non-zero exit on any mismatch.
- The example self-checks on every run: NTT round-trip, `fqmul_vec`, KEM
  encaps == decaps, **codec equivalence** (grouped vs bit-at-a-time, bit for
  bit, over 2000 random polynomials in both canonical and centred form), and
  **sponge conformance** (the streaming sampler and the two-lane sponge against
  serial single-stream references, over 200 random seeds). The last one matters
  specifically because encaps == decaps would still pass if the two-lane sponge
  swapped its lanes — the same blind spot that hid the FIPS 203 deviations above.
- Fuzzing: 5.8M executions on `fuzz_ntt_roundtrip`, 306K on `fuzz_poly_mul`,
  50M on `fuzz_barrett`, 58M on `fuzz_ct_arith`. No findings.
- All four Coq developments compile, with a new section in
  `proofs/BarrettReduction.v` covering the rounding-Barrett kernel.

### Remaining gap

Decapsulation is the one phase where LibOQS is still clearly ahead (6.22 vs
7.13 µs). The unpairable long-message hashes — H(pk) over 800 bytes, H(ct) over
768 bytes, 6 permutations each and inherently sequential — are close to a floor
for a single stream. LibOQS also batches four Keccak lanes where the ISA allows
and interleaves four polynomials per NTT call.

---

## Full Kyber-512 Session

> **Historical — superseded by the tables above.** These are the 2026-03-19
> measurements, kept as a record of how the implementation looked then: the NEON
> i16 NTT vectorised only the len ≥ 8 layers, the codecs packed bit at a time,
> and Keccak ran single-lane. The LibOQS figures quoted here (22.44 µs) are both
> an older release and, as re-measurement showed, pessimistic for that release.

End-to-end KEM timing: keygen + encapsulation + decapsulation.
All figures are **measured end-to-end** on the same machine, including SHAKE-128/256 hashing, SHA3-512/256 key derivation, CBD sampling, and polynomial encoding/compression. Decapsulation includes re-encryption (implicit rejection check).

| Phase | moduletto NEON i16 NTT | moduletto (sha3+asm) | moduletto (inline Keccak) | LibOQS 0.15.0 (ML-KEM-512) | Kyber C Reference |
|-------|:------------------------:|:----------------------:|:---------------------------:|:--------------------------:|:-----------------:|
| Key generation | **8.42 µs** | 11.06 µs | 12.38 µs | **7.19 µs** | 14.93 µs |
| Encapsulation | **16.79 µs** | 20.40 µs | 20.92 µs | **6.98 µs** | 14.57 µs |
| Decapsulation | **20.58 µs** | 25.66 µs | 26.73 µs | **8.27 µs** | 18.37 µs |
| **Total / session** | **45.79 µs** | **57.13 µs** | **60.03 µs** | **22.44 µs** | **47.87 µs** |
| Sessions / sec | 21,841 | 17,505 | 16,658 | **44,563** | 20,891 |
| vs LibOQS | **2.04× slower** | 2.55× slower | 2.68× slower | baseline | 2.13× slower |

**NEON i16 NTT (2026-03-19 addition)**: 45.79 µs — ARM64 NEON `int16x8_t` NTT with Montgomery multiplication (`vmull_s16`, `vmovn_s32`, `vshrn_n_s32`). Processes 8 coefficients per butterfly for NTT layers with len ≥ 8, scalar for len < 8. Uses Inline pure-Rust Keccak for hashing.

Three i64 NTT hashing backends benchmarked (prior run):
- **sha3 Rust crate, no asm** (prior result): 57.61 µs — software Keccak via `sha3 = "0.10"` default features
- **sha3 + asm feature** (ARM64 SHA3 hardware): 57.13 µs — `sha3 = { version = "0.10", features = ["asm"] }` using ARM64 EOR3/RAX1/XAR/BCAX NEON instructions via `cpufeatures` runtime detection
- **Inline pure-Rust Keccak** (XKCP plain-64-bit translation): 60.03 µs — Keccak-f[1600] translated directly from XKCP `KeccakP-1600-64.macros`, inlined into the same compilation unit

**Key findings** (updated after NEON i16 NTT implementation):

1. **NEON i16 NTT closes the gap from 2.56× to 2.04×.** The int16 Montgomery NTT (processing 8 i16 coefficients per NEON instruction via `vmull_s16`) reduces the full session from 57.13 µs to 45.79 µs — a 20% improvement. moduletto is now **faster than the Kyber C Reference** (47.87 µs) for the full KEM session.

2. **SHA3 hardware gives no measurable advantage for Kyber inputs.** The ARM64 SHA3 NEON instructions (EOR3/RAX1/XAR/BCAX) are correctly detected (`hw.optional.armv8_2_sha3: 1`) and used, but the speedup is within measurement noise (57.5 vs 57.6 µs). The NEON path loads/stores the full 200-byte Keccak state into 25 vector registers; for the 32–34 byte inputs used in Kyber, the memory overhead dominates.

3. **Inline Keccak is ~5% slower than the sha3 crate's software implementation.** The cause is register pressure: the fully unrolled XKCP round uses 50+ named local variables simultaneously; ARM64 has ~28 usable integer registers so LLVM spills ~22 values to stack per round, adding ~165 ns per Keccak call (~6.4 µs per session for 39 calls). The sha3 crate uses a smaller per-step temporary set that fits in registers.

4. **The remaining gap vs LibOQS is primarily hashing overhead.** With the NEON i16 NTT, the polynomial arithmetic is now competitive. LibOQS uses `OQS_USE_SHA3_OPENSSL` + `EVP_MD_CTX_new` per hash call, but its NEON NTT (`kyber_ntt_s16_x4_neon`) operates on 4 polynomials simultaneously. The remaining ~23 µs gap between our 45.79 µs and LibOQS's 22.44 µs is split between hashing (~29 µs overhead) and remaining polynomial arithmetic differences.

### Arithmetic-only projection (for reference)

Isolating polynomial operations from hashing: Criterion-measured NTT primitives projected into a session model.

| Phase | moduletto (NTT arithmetic only) | LibOQS full KEM |
|-------|:---------------------------------:|:---------------:|
| Key generation | 9.44 µs | 7.19 µs |
| Encapsulation | 14.02 µs | 6.98 µs |
| Decapsulation | 4.70 µs | 8.27 µs |
| **Total** | **28.17 µs** | **22.44 µs** |

At the arithmetic level, moduletto is within 1.26× of LibOQS. Both the sha3 crate and our inline Keccak add ~29–33 µs per session of hashing overhead. Closing the full session gap requires an int16 NEON NTT (now implemented) combined with a faster hashing backend.

---

## Polynomial Primitive Operations

These are the operations that compose a Kyber session.
moduletto figures are from Criterion; LibOQS and Kyber C reference poly-op figures are
estimated from timing breakdowns in the existing literature for this CPU family —
they are not directly Criterion-measured and are labelled (est.).

### Addition and Subtraction (256 coefficients)

moduletto figures are Criterion-measured. LibOQS and Kyber C Reference are estimated from published breakdowns for this CPU family.

| Operation | moduletto (VT) | moduletto (CT) | LibOQS (NEON) (est.) | Kyber C Ref (est.) |
|-----------|:--------------:|:--------------:|:--------------------:|:------------------:|
| poly_add | **63 ns** | **63 ns** | ~180 ns | ~450 ns |
| poly_sub | **63 ns** | **63 ns** | ~190 ns | ~470 ns |

> The example measures ~82 ns vs Criterion's ~63 ns due to benchmark harness differences (warmup, loop structure, black_box placement). Criterion is the more reliable measurement.

- moduletto poly_add is **~2.9× faster** than LibOQS (estimated).

### NTT Transforms (256 coefficients)

| Operation | moduletto (VT) | moduletto (CT) | LibOQS (est.) | CT overhead |
|-----------|:----------------:|:----------------:|:-------------:|:-----------:|
| forward NTT | **670 ns** | 1,096 ns | ~1,200 ns | 1.64× |
| inverse NTT | **728 ns** | 1,095 ns | ~1,400 ns | 1.50× |

- Variable-time forward NTT is ~1.8× faster than the LibOQS estimate.
- Constant-time NTT is within ~9% of LibOQS (forward) and ~22% faster (inverse).

### Polynomial Multiplication

| Operation | Time | Notes |
|-----------|-----:|-------|
| **mul_ntt (VT)** | **2.34 µs** | NTT-based, O(n log n) |
| mul_ntt (CT) | 3.85 µs | Constant-time NTT path |
| mul_schoolbook (VT) | 29.4 µs | O(n²) — reference only |
| LibOQS NTT mul (est.) | ~3.8 µs | From published breakdowns |
| Kyber C Ref NTT mul (est.) | ~8–14 µs | From published breakdowns |

- Variable-time NTT mul is ~1.6× faster than LibOQS (estimated).
- Constant-time NTT mul is within ~1.4× of LibOQS (estimated).
- NTT mul is **12.6× faster than schoolbook** on this machine.

---

## Scalar Coefficient Operations — ModN\<3329\>

Single-coefficient operations. The building blocks; not the bottleneck in practice.

### Variable-Time

| Operation | moduletto (VT) |
|-----------|:----------------:|
| add | 420 ps |
| sub | 411 ps |
| mul | 520 ps |
| neg | 302 ps |
| inverse | 11.4 ns |
| pow(e = 100) | 13.1 ns |
| pow(e ≈ 2⁶³) | 188 ns |

### Constant-Time vs Variable-Time

| Operation | VT | CT | CT/VT ratio |
|-----------|:--:|:--:|:-----------:|
| add | 420 ps | 418 ps | 1.00× |
| sub | 411 ps | 402 ps | 0.98× |
| mul | 520 ps | 536 ps | 1.03× |
| neg | 302 ps | 307 ps | 1.02× |
| ct_eq | — | 408 ps | — |
| ct_lt | — | 433 ps | — |
| ct_select | — | 594 ps | — |

Constant-time scalar ops carry essentially zero overhead. The security guarantee is free at the coefficient level.

---

## VT vs CT Overhead Across All Levels

| Operation | VT | CT | CT/VT |
|-----------|:--:|:--:|:-----:|
| scalar add | 420 ps | 418 ps | 1.00× |
| scalar sub | 411 ps | 402 ps | 0.98× |
| scalar mul | 520 ps | 536 ps | 1.03× |
| poly_add (n=256) | 63 ns | 63 ns | 1.00× |
| poly_sub (n=256) | 72 ns | 83 ns | 1.15× |
| forward NTT | 670 ns | 1,096 ns | 1.64× |
| inverse NTT | 728 ns | 1,095 ns | 1.50× |
| mul_ntt | 2.34 µs | 3.85 µs | 1.64× |

The CT penalty grows as operations compose: scalar ops pay nothing, poly add/sub pay ≤15%, NTT pays ~1.5–1.6×. This is expected: NTT contains ~1,792 multiplications (256 × log₂256 / 2), and Barrett reduction adds ~3% per multiply, compounding across butterfly layers.

---

## Summary

```
Full Kyber-512 session (lower = faster):

LibOQS 0.15.0 (ML-KEM-512)              22.44 µs  ████████████
moduletto (NTT, projected) 28.17 µs  ███████████████  ← arithmetic only
moduletto NEON i16 NTT (full KEM)      45.79 µs  █████████████████████████
Kyber C Reference                         47.87 µs  ██████████████████████████
moduletto (sha3+asm)      57.13 µs  ███████████████████████████████
moduletto (inline Keccak) 60.03 µs  █████████████████████████████████


NTT Polynomial Multiplication (lower = faster):

moduletto VT      2.34 µs  ████████
moduletto CT      3.85 µs  █████████████
LibOQS (est.)      ~3.80 µs  █████████████
Kyber C Ref (est.) ~8–14 µs  ████████████████████████████████████████████████


Polynomial Addition — 256 coefficients (lower = faster):

moduletto VT/CT    63 ns  ████
LibOQS (est.)       180 ns  ████████████
Kyber C Ref (est.) ~450 ns  ██████████████████████████████
```

---

## Interpretation

**NEON i16 NTT result (2026-03-19)**: moduletto with ARM64 NEON int16 Montgomery NTT achieves 45.79 µs per Kyber-512 session, which is **faster than the Kyber C Reference (47.87 µs)** and reduces the LibOQS gap from 2.56× to 2.04×. The NEON NTT processes 8 i16 coefficients per butterfly via `vmull_s16` / `vmovn_s32` / `vshrn_n_s32`, implementing the Montgomery butterfly `t = fqmul_neon(zeta, bot); top+t, top-t` in NEON for all NTT layers with len ≥ 8.

**Full session (with hashing)**: moduletto is 2.04× slower than LibOQS with the NEON i16 NTT. The NEON i16 path reduces arithmetic cost significantly vs the i64 path (45.79 µs vs 57.13 µs = 20% improvement).

**SHA3 hardware investigation summary**: The LibOQS Homebrew bottle (`OQS_USE_SHA3_OPENSSL`) uses `EVP_MD_CTX_new` per hash call — the same EVP path we tried earlier. ARM64 SHA3 hardware instructions (EOR3/RAX1/XAR/BCAX) are available (`hw.optional.armv8_2_sha3: 1`) and the sha3+asm path does use them, but they offer no measurable speedup for Kyber inputs. Reason: loading and storing a 200-byte Keccak state into 25 NEON registers dominates the cost for the 32–34 byte inputs used in each hash call.

**Root cause of remaining LibOQS gap**: The ~23 µs gap between 45.79 µs and 22.44 µs is dominated by hashing overhead (~29 µs per session for ~39 Keccak/SHA3 calls). LibOQS's additional advantage comes from processing 4 polynomials simultaneously in its `kyber_ntt_s16_x4_neon`, which amortizes load/store overhead further.

**Arithmetic-only projection**: Isolating polynomial operations from hashing (Criterion-measured NTT primitives projected into a session model), moduletto is within 1.26× of LibOQS. The Rust polynomial arithmetic is competitive at the primitive level.

**NTT primitives**: moduletto's variable-time NTT mul (2.34 µs) is comparable to LibOQS (~3.8 µs estimated). The Criterion-measured forward NTT (670 ns) is faster than the LibOQS estimate (~1.2 µs).

**Polynomial add/sub**: moduletto is the clear winner (~63–72 ns vs ~180–190 ns estimated for LibOQS). These map to tight auto-vectorised loops over `i64` values.

**Kyber C Reference**: moduletto NEON i16 NTT full KEM is now **4% faster** than the Kyber C Reference. The i64 NTT path remains ~19% slower than the C Reference.

**Path to parity with LibOQS**: The primary remaining gap is hashing (~29 µs/session for ~39 Keccak calls). A NEON-optimized Keccak-f[1600] that operates on the 200-byte state using 64-bit lane permutations without full NEON register load/store overhead could cut hashing to ~15 µs, bringing the total within ~10% of LibOQS. Further gains from a 4-way parallel NEON NTT (processing 4 polynomials simultaneously like LibOQS) would provide additional speedup.

---

## Platform Notes

| Item | Value |
|------|-------|
| OS | Darwin 25.0.0 (macOS Sequoia) |
| CPU | Apple Silicon (ARM64) |
| Compiler (C) | Apple clang 17.0.0 |
| Compiler (Rust) | rustc (release, `opt-level=3`, `lto=true`, `codegen-units=1`) |
| LibOQS | 0.15.0 (Homebrew bottle, arm64_tahoe) |
| Kyber C Reference | pq-crystals/kyber `ref/` HEAD 2026-03-19 |
| moduletto | 0.1.0 (this repo) |
| sha3 crate (sw) | 0.10.8 (software Keccak, `keccak` crate) |
| sha3 crate (asm) | 0.10.8 + `features = ["asm"]` (ARM64 EOR3/RAX1/XAR/BCAX via `keccak/asm`) |
| Inline Keccak | pure-Rust Keccak-f[1600], translated from XKCP plain-64-bit, inlined in `kyber_benchmark.rs` |
| NEON i16 NTT | ARM64 `int16x8_t` Montgomery NTT, `vmull_s16`/`vmovn_s32`/`vshrn_n_s32` butterflies |

---

*All benchmarks run on 2026-03-19 on the same machine.*
