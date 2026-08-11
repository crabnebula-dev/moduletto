# Moduletto Native Smart

Optimized rust-based modular arithmetic and NTT for lattice cryptography. Includes a full Kyber-512 (ML-KEM-512) implementation with ARM64 NEON-accelerated int16 NTT in constant time, as WASM, and with optional no_std.

## Conformance

The Kyber-512 implementation in `examples/kyber_benchmark.rs` is validated against
the **official NIST ACVP known-answer tests for ML-KEM-512 (FIPS 203)** —
60 cases covering all three operations:

| Operation | Cases | Checks |
|-----------|------:|--------|
| `keyGen` (AFT) | 25 | `(d, z)` → encapsulation and decapsulation keys, byte for byte |
| `encapsulation` (AFT) | 25 | `(ek, m)` → ciphertext and shared secret |
| `decapsulation` (VAL) | 10 | `(dk, c)` → shared secret, including modified-ciphertext cases that must yield the implicit-rejection key |

Vectors are in [tests/kat/](tests/kat/), extracted verbatim from
[usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server). The harness runs
on every `cargo run --release --example kyber_benchmark` and exits non-zero on any
mismatch.

**All three backends are validated** — 180 cases per run — through a shared
byte-level interface, so the NEON int16 path and both i64 paths are held to the
same standard rather than only the one that gets benchmarked:

```
FIPS 203 KATs (NIST ACVP ML-KEM-512), all backends:
    NEON i16 NTT + inline Keccak: PASSED (25 keygen, 25 encaps, 10 decaps)
    i64 NTT + inline Keccak:      PASSED (25 keygen, 25 encaps, 10 decaps)
    i64 NTT + sha3 crate (asm):   PASSED (25 keygen, 25 encaps, 10 decaps)
```

This matters more than it sounds. The self-consistency check the example previously
relied on — encapsulate, decapsulate, confirm the shared secrets agree — passes for
*any* internally coherent scheme. Running the official vectors showed this code was
implementing round-3 Kyber rather than FIPS 203 ML-KEM, and with a parameter error
on top:

- `G(d)` instead of `G(d ‖ k)` — FIPS 203's key-generation domain separation
- encapsulation hashed `m` before use; FIPS 203 feeds it in directly
- round-3's final `KDF(K ‖ H(c))`; FIPS 203 uses `K` as the shared secret
- implicit rejection via `SHA3-256(z ‖ H(c))` instead of `J(z ‖ c)`
- **the implicit-rejection seed `z` was hardcoded to zero**, which is a real
  weakness rather than a conformance nit: a predictable `z` makes the rejection
  key computable by anyone
- η₁ = 2 where ML-KEM-512 requires η₁ = 3

All are fixed, and the KATs now pass. Correcting them also made the KEM *faster*:
dropping round-3's KDF removes a SHA3-256 over the full 768-byte ciphertext — six
Keccak permutations — from every encapsulation, which more than pays for the wider
η₁ = 3 noise sampling.

## Performance

Full ML-KEM-512 KEM session (keygen + encaps + decaps) on Apple M5. LibOQS was
rebuilt and re-measured on the same machine, in the same session, with the same
10,000-iteration methodology. Both implementations pass the same NIST ACVP vectors:

| Phase | Moduletto NEON i16 | LibOQS 0.16.0 | LibOQS 0.15.0 | Kyber C Reference |
|-------|:------------------:|:-------------:|:-------------:|:-----------------:|
| Key generation | **4.07 us** | 4.72 us | 5.80 us | 14.93 us |
| Encapsulation | **3.84 us** | 5.25 us | 6.60 us | 14.57 us |
| Decapsulation | **5.80 us** | 6.22 us | 8.03 us | 18.37 us |
| **Total** | **13.7–14.1 us** | 16.19 us | 20.43 us | 47.87 us |
| Sessions/sec | **~72,000** | 61,800 | 48,900 | 20,900 |

moduletto is **~1.18x faster than LibOQS 0.16.0** and ahead in all three phases.

> LibOQS 0.16.0 (released 2026-07-09) is itself 1.26x faster than 0.15.0 at
> ML-KEM-512, so comparisons against the older release overstate our lead.
> The Kyber C Reference column is carried over from an earlier session and was
> not re-measured.

Library primitives (Criterion, q = 3329, n = 256):

| Operation | Variable-time | Constant-time |
|-----------|--------------:|--------------:|
| `forward_ntt` | 176 ns | 177 ns |
| `inverse_ntt` | 239 ns | 239 ns |
| `mul_ntt` | 503 ns | 504 ns |
| `poly_add` / `poly_sub` | 63 ns | 63 ns |

The constant-time transforms cost the same as the variable-time ones because
they *are* the same code: the kernel is branchless straight-line arithmetic with
no data-dependent branch and no conditional move, so there is nothing a barrier
would protect. See [BENCHMARKS.md](BENCHMARKS.md) for the full picture and the
history behind these numbers.

## What's Inside

### Core (`src/`)

- **`modn.rs`** -- Generic `ModN<N>` type for modular arithmetic over any modulus < 2^31. Variable-time operations using i64 native register arithmetic (3x faster than i128).
- **`modn_ct.rs`** -- Constant-time variant of `ModN` with side-channel resistant operations, backed by `subtle` optimisation barriers (built with `core_hint_black_box`, so the barrier is a register fence rather than a stack round-trip).
- **`ntt.rs`** -- Number Theoretic Transform for `ModN<N>` polynomials (degree 256). Cooley-Tukey/Gentleman-Sande butterflies over a lazy, redundant coefficient representation, with a fully vectorised ARM64 NEON int16 backend and a portable i64 fallback. Both backends are cross-checked against each other in the test suite.
- **`wasm.rs`** -- Optional WebAssembly bindings via `wasm-bindgen`.

### Kyber Benchmark (`examples/kyber_benchmark.rs`)

A standalone Kyber-512 KEM implementation featuring:
- **ARM64 NEON int16 NTT** -- Montgomery multiplication via `vmull_s16`/`vmovn_s32`/`vshrn_n_s32`, processing 8 coefficients per butterfly
- **Inline Keccak-f[1600]** -- Pure-Rust implementation translated from XKCP
- **SHA3-256/512, SHAKE-128/256** -- Complete hash suite for Kyber key derivation and sampling
- **Full KEM flow** -- keygen, encapsulation, decapsulation with implicit rejection (FO transform)

### Hybrid Post-Quantum Encryption (`examples/hybrid_pq_aes.rs`)

A complete Kyber-512 + AES-256-GCM hybrid encryption system demonstrating the standard post-quantum key encapsulation pattern used in TLS 1.3 and Signal's PQXDH:

```bash
cargo run --release --example hybrid_pq_aes
```

1. Kyber-512 KEM establishes a 256-bit shared secret (768-byte ciphertext)
2. AES-256-GCM encrypts arbitrary plaintext with the shared secret
3. Tamper detection via GCM authentication tag + Kyber IND-CCA2 implicit rejection

## Usage

```rust
use moduletto::ModN;

// Kyber-512 modulus
type Mod3329 = ModN<3329>;

let a = Mod3329::new(1234);
let b = Mod3329::new(5678);
let c = a.ct_mul(b);

// Polynomial operations
use moduletto::ntt;
let mut poly = [Mod3329::zero(); 256];
// ... populate poly ...
// NTT-based polynomial multiplication available via ntt module
```

### Constant-time operations

```rust
use moduletto::modn_ct::ModN as ModNCT;

type F = ModNCT<3329>;
let a = F::new(42);
let b = F::new(99);

// No data-dependent branches or memory access
let sum = a.ct_add(b);
let selected = F::ct_select(a, b, true); // constant-time conditional
```

## Running Benchmarks

```bash
# Full Kyber-512 KEM benchmark (NEON i16 NTT on ARM64)
cargo run --release --example kyber_benchmark

# Criterion microbenchmarks for polynomial primitives
cargo bench

# no_std compatibility check
cargo test --lib --no-default-features --release
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `std` (default) | Standard library support |
| `alloc` | Heap allocation + `libm` for no_std math |
| `wasm` | WebAssembly bindings via `wasm-bindgen` |

```toml
# Default (std)
moduletto = "0.1"

# no_std without allocator
moduletto = { version = "0.1", default-features = false }

# no_std with allocator
moduletto = { version = "0.1", default-features = false, features = ["alloc"] }

# WebAssembly
moduletto = { version = "0.1", features = ["wasm"] }
```

## Architecture

- **ARM64 (Apple Silicon, Cortex-A)**: NEON int16 NTT for Kyber, i64 scalar for generic ModN
- **x86-64**: i64 scalar (no SIMD NTT yet)
- **WebAssembly**: Supported via `wasm` feature flag

### Why i64 for generic ModN

For moduli < 2^31, i64 is 3x faster than i128 on 64-bit platforms. i64 maps to native register width -- add/sub/mul are single instructions. i128 requires register pairs and multi-instruction sequences.

| Operation (n=256) | i64 (this) | i128 | Speedup |
|-------------------|:----------:|:----:|:-------:|
| poly_add | 63 ns | ~295 ns | 3.2x |
| poly_sub | 72 ns | ~370 ns | 3.5x |

### Why int16 for Kyber NTT

Kyber's modulus q=3329 fits in 12 bits. Using i16 coefficients with ARM64 NEON intrinsics (`int16x8_t`) processes 8 coefficients per vector instruction. Montgomery multiplication (`fqmul`) uses `vmull_s16` -> `vmovn_s32` -> `vshrn_n_s32` to compute `a*b*R^{-1} mod q` entirely in NEON registers.

## Formal Verification (`proofs/`)

The constant-time arithmetic is formally verified using Coq (Rocq 9.1) with an accompanying OCaml test harness.

### Prerequisites

```bash
# macOS (Homebrew)
brew install rocq opam

# Linux (apt) — install opam, then use it for Rocq
sudo apt install opam
opam init
opam install rocq-prover
```

Requires Rocq/Coq >= 9.0 and OCaml >= 5.0.

### Running

```bash
# Compile all Coq proofs and run OCaml tests
cd proofs && make

# Coq proofs only (type-checks all theorems)
make coq

# OCaml runtime tests only (27,000+ test cases)
make ocaml

# Clean build artifacts
make clean
```

A successful `make coq` means every theorem has been machine-checked by the Rocq kernel -- no axioms are used except one `Admitted` lemma for NTT linearity (the inductive list proof is mechanical but lengthy; it is covered by the OCaml runtime tests instead).

### Coq proofs

- **`ModularArithmetic.v`** -- Correctness of branchless CT add/sub/neg (equivalence to branching versions, correctness mod N, range closure, algebraic properties)
- **`BarrettReduction.v`** -- Barrett reduction produces `x mod N` for inputs < N^2, with quotient approximation bounds and Kyber-3329 instantiation
- **`ConstantTime.v`** -- ct_select, ct_swap (XOR swap), ct_lt, ct_is_zero: functional correctness of all branchless primitives
- **`NTT.v`** -- Kyber parameter verification: zeta=17 is a primitive 256th root of unity mod 3329, 128^(-1) = 3303 mod 3329, primality of 3329

### OCaml test harness

- **`test_moduletto.ml`** -- 27,000+ runtime tests validating VT/CT agreement, Barrett reduction, CT primitives, and NTT root-of-unity properties across sampled Kyber coefficient ranges

## Fuzzing (`fuzz/`)

Coverage-guided fuzzing via [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). Requires a nightly toolchain.

### Prerequisites

```bash
cargo install cargo-fuzz
rustup toolchain install nightly
```

### Running

```bash
# Run a specific target (runs until stopped with Ctrl-C)
cargo +nightly fuzz run fuzz_ct_arith

# Run for a fixed duration
cargo +nightly fuzz run fuzz_barrett -- -max_total_time=60

# List all available targets
cargo +nightly fuzz list

# Run all targets for 30 seconds each
for target in $(cargo +nightly fuzz list); do
  echo "=== $target ==="
  cargo +nightly fuzz run "$target" -- -max_total_time=30
done
```

### Fuzz targets

| Target | What it tests |
|--------|---------------|
| `fuzz_ct_arith` | CT vs VT equivalence for add/sub/mul/neg, range invariants, algebraic properties (identity, inverse, roundtrip) |
| `fuzz_barrett` | Barrett reduction correctness across six different moduli (7, 127, 251, 257, 3329, 65537) |
| `fuzz_ntt_roundtrip` | NTT -> INTT roundtrip for arbitrary polynomials, CT vs VT NTT agreement |
| `fuzz_ct_primitives` | ct_select, ct_swap, ct_eq, ct_lt: specification compliance, reflexivity, double-swap identity |
| `fuzz_poly_mul` | NTT polynomial multiplication vs schoolbook (ground truth), CT vs VT agreement |

Crash artifacts are saved to `fuzz/artifacts/<target>/` and can be replayed with:

```bash
cargo +nightly fuzz run fuzz_ct_arith fuzz/artifacts/fuzz_ct_arith/<crash-file>
```

## License

Polyform-Noncommercial-1.0.0
