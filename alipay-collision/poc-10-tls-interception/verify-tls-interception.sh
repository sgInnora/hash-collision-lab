#!/bin/bash
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  TLS Interception Analysis — Factored RSA Key Exploitation  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"
python3 "$DIR/tls-interception-analysis.py"
