#!/bin/bash
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Weak Randomness & Key Quality Analysis — Alipay Ecosystem  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"

echo "━━━ Running Comprehensive Analysis ━━━"
python3 "$DIR/weak-random-analysis.py"
