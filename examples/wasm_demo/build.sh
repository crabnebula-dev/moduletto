#!/bin/bash
# Build script for Moduletto Native Smart WASM demo
set -e

echo "🔧 Building Moduletto Native Smart for WebAssembly..."
echo ""

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "❌ Error: wasm-pack is not installed"
    echo ""
    echo "Install it with:"
    echo "  cargo install wasm-pack"
    echo ""
    exit 1
fi

# Navigate to the library root (two directories up)
cd "$(dirname "$0")/../.."

# Build for web target with size optimizations
echo "📦 Running wasm-pack build with size optimizations..."
RUSTFLAGS="-C opt-level=z -C strip=symbols" \
wasm-pack build --target web --features wasm

# Check if build succeeded
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Build successful!"
    echo ""
    echo "Generated files in pkg/:"
    ls -lh pkg/ | grep -E '\.(wasm|js|ts)$'
    echo ""
    echo "📊 WASM bundle size:"
    echo "  Raw: $(du -h pkg/moduletto_bg.wasm | cut -f1)"
    if command -v gzip &> /dev/null; then
        echo "  Gzipped: $(gzip -c pkg/moduletto_bg.wasm | wc -c | awk '{print int($1/1024) "K"}')"
    fi
    echo ""

    # Copy or symlink pkg to demo folder
    DEMO_DIR="examples/wasm_demo"
    if [ -L "$DEMO_DIR/pkg" ]; then
        echo "✓ Symlink to pkg/ already exists in demo folder"
    elif [ -d "$DEMO_DIR/pkg" ]; then
        echo "✓ pkg/ directory already exists in demo folder"
    else
        echo "🔗 Creating symlink to pkg/ in demo folder..."
        ln -s ../../pkg "$DEMO_DIR/pkg"
        echo "✓ Symlink created"
    fi

    echo ""
    echo "🌐 To run the demo:"
    echo "  cd $DEMO_DIR"
    echo "  python3 -m http.server 8080"
    echo ""
    echo "Or use the serve script:"
    echo "  cd $DEMO_DIR"
    echo "  ./serve.sh"
    echo ""
    echo "Then open: http://localhost:8080"
else
    echo ""
    echo "❌ Build failed!"
    exit 1
fi
