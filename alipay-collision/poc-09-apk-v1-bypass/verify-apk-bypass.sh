#!/bin/bash
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  APK V1 Signature Verification Bypass — Complete Analysis   ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"

# If an APK path is provided, analyze it
if [ -n "$1" ]; then
  python3 "$DIR/apk-signature-bypass.py" "$1"
else
  python3 "$DIR/apk-signature-bypass.py"
fi
