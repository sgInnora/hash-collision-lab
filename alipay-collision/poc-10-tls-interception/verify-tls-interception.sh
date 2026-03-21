#!/bin/bash
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  TLS Interception Analysis — Impact of Factored RSA Keys    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"
python3 "$DIR/tls-interception-analysis.py"
