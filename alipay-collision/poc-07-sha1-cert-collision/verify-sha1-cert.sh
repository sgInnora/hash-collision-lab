#!/bin/bash
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  SHA-1 Certificate Collision Analysis — Alipay APK Cert     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DER="$DIR/../poc-01-md5-cert/alipay-original-cert.der"

echo "━━━ Certificate Fingerprints ━━━"
echo "  SHA-1:   $(shasum "$CERT_DER" | cut -d' ' -f1)"
echo "  SHA-256: $(shasum -a 256 "$CERT_DER" | cut -d' ' -f1)"
echo "  MD5:     $(md5 -q "$CERT_DER" 2>/dev/null || md5sum "$CERT_DER" | cut -d' ' -f1)"
echo ""

echo "━━━ Running SHA-1 Collision Analysis ━━━"
python3 "$DIR/sha1-cert-analysis.py"

echo "━━━ Attack Cost Timeline ━━━"
echo "  Year  | Attack Type          | Cost"
echo "  ------|----------------------|----------"
echo "  2017  | Identical-prefix     | \$110,000"
echo "  2020  | Chosen-prefix        | \$45,000"
echo "  2023  | Optimized            | ~\$11,000"
echo "  2026  | Current estimate     | \$5K-\$8K"
echo ""
echo "  ⚠️  SHA-1 cert collision is now within individual attacker budget."
echo "  Defense: APK Signature Scheme v2/v3 (SHA-256)."
