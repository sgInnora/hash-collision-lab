#!/bin/bash
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  APK v1 Signature Forgery — DEX Replacement PoC         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"

echo "━━━ DEX File Comparison ━━━"
echo "  Legitimate DEX: dex-legit.bin ($(wc -c < "$DIR/dex-legit.bin" | tr -d ' ') bytes)"
echo "  Rogue DEX:      dex-rogue.bin ($(wc -c < "$DIR/dex-rogue.bin" | tr -d ' ') bytes)"

DIFF=$(cmp -l "$DIR/dex-legit.bin" "$DIR/dex-rogue.bin" 2>/dev/null | wc -l | tr -d ' ')
echo "  Binary differences: $DIFF bytes"
echo ""

echo "━━━ DEX Headers ━━━"
echo "  Legit magic: $(xxd -l 8 "$DIR/dex-legit.bin" | awk '{print $2, $3, $4, $5}')"
echo "  Rogue magic: $(xxd -l 8 "$DIR/dex-rogue.bin" | awk '{print $2, $3, $4, $5}')"

echo ""
echo "━━━ Attack Principle ━━━"
echo "  APK v1 (JAR) signature scheme:"
echo "  1. Signs individual ZIP entries via SHA-1 digests in MANIFEST.MF"
echo "  2. Does NOT sign the APK file as a whole"
echo "  3. Replacing classes.dex content with same-digest DEX = valid signature"
echo ""
echo "  With MD5 collision (poc-01) + DEX replacement:"
echo "  An attacker can craft a rogue DEX that passes v1 verification"
echo "  while executing completely different code."
echo ""
echo "  ⚠️  Alipay APK uses v1 signing → vulnerable to DEX substitution."
