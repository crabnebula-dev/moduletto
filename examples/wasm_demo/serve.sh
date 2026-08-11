#!/bin/bash
# Simple HTTP server for WASM demo

# pkg/ is a wasm-pack build artifact and is gitignored, so a fresh clone (or a
# cleaned tree) has no moduletto.js and the page 404s with no useful explanation.
# Check for it up front rather than serving a broken demo.
cd "$(dirname "$0")"
if [ ! -f pkg/moduletto.js ]; then
    echo "❌ pkg/moduletto.js is missing — the WASM package has not been built."
    echo ""
    echo "Build it first:"
    echo "  ./build.sh"
    echo ""
    echo "(build.sh needs wasm-pack and the wasm32 target:"
    echo "   brew install wasm-pack   # or: cargo install wasm-pack"
    echo "   rustup target add wasm32-unknown-unknown)"
    exit 1
fi

echo "🌐 Starting HTTP server for Moduletto WASM demo..."
echo ""
echo "Server will be available at:"
echo "  http://localhost:8080"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Try python3 first, then python, then node
if command -v python3 &> /dev/null; then
    python3 -m http.server 8080
elif command -v python &> /dev/null; then
    python -m http.server 8080
elif command -v npx &> /dev/null; then
    npx http-server -p 8080
else
    echo "❌ Error: No HTTP server found!"
    echo ""
    echo "Install one of the following:"
    echo "  • Python 3: https://python.org"
    echo "  • Node.js: https://nodejs.org"
    exit 1
fi
