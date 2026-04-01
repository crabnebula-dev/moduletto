# Moduletto Native Smart WebAssembly Demo

This example demonstrates how to compile Moduletto Native Smart to WebAssembly and use it in a web browser for high-performance modular arithmetic and post-quantum cryptography operations.

## What's in this folder

- `index.html` - Interactive demo website showcasing Moduletto WASM
- `build.sh` - Script to build the WASM package
- `serve.sh` - Script to run a local HTTP server
- `README.md` - This file
- `pkg/` - Generated WASM build artifacts (created after building)

## Prerequisites

1. **Rust toolchain** - Install from https://rustup.rs
2. **wasm-pack** - Install with:
   ```bash
   cargo install wasm-pack
   ```
3. **WebAssembly target** - Add with:
   ```bash
   rustup target add wasm32-unknown-unknown
   ```

## Quick Start

### Build and Run

```bash
# Build the WASM package
./build.sh

# Start the web server
./serve.sh
```

Then open http://localhost:8080 in your browser.

## Building the WASM Package

### Option 1: Use the build script (recommended)

```bash
./build.sh
```

This script will:
- Build the WASM package with size optimizations
- Show the bundle size
- Create a symlink to the pkg directory
- Display instructions for running the demo

### Option 2: Manual build

Navigate to the library root and run:

```bash
# For web (ES modules) - recommended for browsers
wasm-pack build --target web --features wasm

# For Node.js
wasm-pack build --target nodejs --features wasm

# For bundlers (webpack, rollup, etc.)
wasm-pack build --target bundler --features wasm
```

This will create a `pkg/` directory containing:
- `moduletto_bg.wasm` - The WebAssembly binary
- `moduletto.js` - JavaScript bindings
- `moduletto.d.ts` - TypeScript type definitions
- `package.json` - NPM package configuration

## Running the Demo

### Option 1: Use the serve script (recommended)

```bash
./serve.sh
```

### Option 2: Python HTTP Server

```bash
python3 -m http.server 8080
```

### Option 3: Node.js http-server

```bash
npx http-server -p 8080
```

### Option 4: VS Code Live Server

If you use VS Code with the Live Server extension:
1. Right-click on `index.html`
2. Select "Open with Live Server"

Then open http://localhost:8080 in your browser.

## Demo Features

The included `index.html` demo showcases:

1. **Interactive Calculator** - Perform modular arithmetic operations with Kyber-512 modulus (3329)
2. **Performance Comparison** - See i64 vs i128 performance differences
3. **Key Generation** - Simulate Kyber-512 key generation components
4. **NTT Transform** - Number Theoretic Transform for fast polynomial multiplication
5. **Performance Test** - Benchmark modular operations in your browser

## Using Moduletto WASM in Your Project

### For Web (ES Modules)

```html
<!DOCTYPE html>
<html>
<head>
    <title>Moduletto Demo</title>
</head>
<body>
    <script type="module">
        // Import and initialize the WASM module
        import init, * as moduletto from './pkg/moduletto.js';

        async function run() {
            // Initialize WASM
            await init();

            // Now you can use Moduletto functions
            console.log('=== Moduletto WASM Demo ===');

            // Modular arithmetic with Kyber-512 modulus
            const mod = 3329;
            const a = 1234;
            const b = 5678;

            // These would be exposed via wasm-bindgen
            console.log(`${a} + ${b} mod ${mod} =`, (a + b) % mod);
            console.log(`${a} * ${b} mod ${mod} =`, (a * b) % mod);
        }

        run();
    </script>
</body>
</html>
```

### For Node.js

1. Install the package:
```bash
npm install /path/to/moduletto/pkg
```

2. Use in your code:
```javascript
const moduletto = require('moduletto');

// Use modular arithmetic functions
// (functions would be exposed via wasm-bindgen)
```

## Performance

Moduletto Native Smart provides high-performance modular arithmetic:

| Operation | Performance (ARM M3 Max) |
|-----------|--------------------------|
| Coefficient Addition | ~2 ns |
| Coefficient Multiplication | ~5 ns |
| Polynomial Addition (256) | ~91 ns |
| Polynomial Subtraction (256) | ~107 ns |

**3x faster than i128** for moduli < 2³¹

## Use Cases

- **Post-quantum cryptography** - Kyber-512, Dilithium
- **Lattice-based encryption** - LWE, Ring-LWE
- **Zero-knowledge proofs** - zkSNARKs, zkSTARKs
- **Secure multiparty computation** - MPC protocols

## Technical Details

### Why i64 is 3x Faster

1. **Native register size** - ARM64 and x86-64 both use 64-bit registers
2. **Single-instruction operations** - Add, sub, mul are single instructions
3. **i128 overhead** - Requires register pairs and multi-instruction sequences
4. **Branch prediction** - Simpler control flow with i64

### Constant-Time Guarantees

All operations use constant-time algorithms:
- Conditional moves via bitwise masks
- No data-dependent branches
- No secret-dependent memory access
- Barrett reduction for multiplication

## Browser Compatibility

Works in all modern browsers supporting WebAssembly:
- ✅ Chrome 57+
- ✅ Firefox 52+
- ✅ Safari 11+
- ✅ Edge 16+

## Troubleshooting

### CORS errors when opening HTML directly

**Problem:** Opening `index.html` directly with `file://` protocol causes CORS errors.

**Solution:** Always use an HTTP server (see "Running the Demo" section).

### "Failed to fetch" or "Module not found"

**Problem:** The WASM files aren't in the right location.

**Solution:** Make sure you've built the WASM package and either:
- Copied `pkg/` into the `wasm_demo` folder, or
- Created a symlink to `../../pkg` (done automatically by `build.sh`)

### "wasm-pack: command not found"

**Solution:** Install wasm-pack:
```bash
cargo install wasm-pack
```

### Build fails with "crate-type must be cdylib"

**Solution:** This is already configured in `Cargo.toml`. Verify it contains:
```toml
[lib]
crate-type = ["rlib", "cdylib"]
```

## Further Development

### Customizing the Demo

Edit `index.html` to add your own examples or modify the UI. The demo is self-contained with inline CSS and JavaScript.

### Adding WASM Bindings

To expose Rust functions to JavaScript, use `wasm-bindgen` in `src/lib.rs`:

```rust
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn mod_add(a: i64, b: i64, modulus: i64) -> i64 {
    type Mod = ModN<{modulus}>;  // Note: const generics limitation
    let x = Mod::new(a);
    let y = Mod::new(b);
    x.ct_add(y).value()
}
```

### Optimizing Bundle Size

To further reduce size:

1. Use `wasm-opt` (included with wasm-pack):
```bash
wasm-pack build --target web --features wasm -- --release
```

2. Enable link-time optimization (already in `Cargo.toml`):
```toml
[profile.release]
lto = true
opt-level = "z"  # Optimize for size
```

3. Strip debug symbols (already in build script):
```bash
RUSTFLAGS="-C opt-level=z -C strip=symbols" wasm-pack build
```

## License

Polyform-Noncommercial-1.0.0

## Links

- Main Repository: https://github.com/denjell/circlecimal
- Report Issues: https://github.com/denjell/circlecimal/issues
- wasm-pack Documentation: https://rustwasm.github.io/wasm-pack/
