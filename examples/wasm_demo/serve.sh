#!/bin/bash
# Simple HTTP server for WASM demo

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
