#!/bin/bash
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  Janus Vulnerability (CVE-2017-13156) — PoC             ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"

echo "━━━ Running Janus PoC ━━━"
python3 "$DIR/janus-poc.py"

if [ -f "$DIR/janus-demo.bin" ]; then
  echo "━━━ Binary Verification ━━━"
  echo "  File: janus-demo.bin"
  echo "  Size: $(wc -c < "$DIR/janus-demo.bin") bytes"
  echo ""
  echo "  First 8 bytes (should be DEX magic 'dex\\n035\\0'):"
  echo "  $(xxd -l 8 "$DIR/janus-demo.bin")"
  echo ""
  echo "  ZIP detection (should find PK signatures):"
  echo "  Local File Headers:"
  grep -c "PK" "$DIR/janus-demo.bin" 2>/dev/null | xargs echo "    PK signatures found:"
  echo ""
  echo "  python3 -c to verify ZIP:"
  python3 -c "
import zipfile, sys
try:
    with zipfile.ZipFile('$DIR/janus-demo.bin') as zf:
        print(f'    ZIP valid: YES, entries: {zf.namelist()}')
except Exception as e:
    print(f'    ZIP valid: NO ({e})')
"
fi
