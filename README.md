# Moduletto Native Smart

Optimized modular arithmetic and NTT for lattice cryptography. Includes a full Kyber-512 (ML-KEM-512) implementation with ARM64 NEON-accelerated int16 NTT in constant time, as WASM, and with optional no_std.

## Performance

Full Kyber-512 KEM session on Apple Silicon (M5 Pro):

| Phase | Moduletto NEON i16 | LibOQS 0.15.0 | Kyber C Reference |
|-------|:--------------------:|:-------------:|:-----------------:|
| Key generation | 8.42 us | 7.19 us | 14.93 us |
| Encapsulation | 16.79 us | 6.98 us | 14.57 us |
| Decapsulation | 20.58 us | 8.27 us | 18.37 us |
| **Total** | **45.79 us** | **22.44 us** | **47.87 us** |

moduletto is **faster than the Kyber C Reference** and within 2.04x of LibOQS. The remaining gap is primarily hashing overhead (~29 us/session for ~39 Keccak calls). Polynomial arithmetic alone is within 1.26x of LibOQS.

## What's Inside

### Core (`src/`)

- **`modn.rs`** -- Generic `ModN<N>` type for modular arithmetic over any modulus < 2^31. Variable-time operations using i64 native register arithmetic (3x faster than i128).
- **`modn_ct.rs`** -- Constant-time variant of `ModN` with side-channel resistant operations (bitwise masks, no data-dependent branches). Zero overhead at the scalar level.
- **`ntt.rs`** -- Number Theoretic Transform for `ModN<N>` polynomials (degree 256). Forward/inverse NTT with Cooley-Tukey/Gentleman-Sande butterflies.
- **`wasm.rs`** -- Optional WebAssembly bindings via `wasm-bindgen`.

### Kyber Benchmark (`examples/kyber_benchmark.rs`)

A standalone Kyber-512 KEM implementation featuring:
- **ARM64 NEON int16 NTT** -- Montgomery multiplication via `vmull_s16`/`vmovn_s32`/`vshrn_n_s32`, processing 8 coefficients per butterfly
- **Inline Keccak-f[1600]** -- Pure-Rust implementation translated from XKCP
- **SHA3-256/512, SHAKE-128/256** -- Complete hash suite for Kyber key derivation and sampling
- **Full KEM flow** -- keygen, encapsulation, decapsulation with implicit rejection (FO transform)

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
