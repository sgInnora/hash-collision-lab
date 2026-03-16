#!/bin/bash
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   MD5 Length Extension Attack — Proof of Concept          ║"
echo "║   Target: Alipay APK Certificate (md5WithRSAEncryption)   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$DIR/md5-length-extension.py"

if [ ! -f "$SCRIPT" ]; then
    echo "  ERROR: $SCRIPT not found"
    exit 1
fi

python3 "$SCRIPT"
EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "━━━ Attack Significance ━━━"
    echo ""
    echo "  The MD5 length extension vulnerability stems from MD5's"
    echo "  Merkle-Damgard construction: the output IS the internal"
    echo "  compression state, which can be resumed by anyone."
    echo ""
    echo "  Real-world impact on systems like Alipay (2009-era):"
    echo ""
    echo "  1. Certificate forgery (demonstrated in poc-01):"
    echo "     Attacker creates a cert with the same MD5 fingerprint."
    echo ""
    echo "  2. MAC forgery (demonstrated here):"
    echo "     If a server validates requests with MD5(secret||data),"
    echo "     an attacker who intercepts ONE valid token can forge"
    echo "     arbitrary extended requests — no secret key required."
    echo "     Attack complexity: O(max_secret_length) attempts."
    echo ""
    echo "  3. Digest chain corruption:"
    echo "     Any protocol that chains MD5 outputs without HMAC"
    echo "     is potentially vulnerable to state injection."
    echo ""
    echo "  Why HMAC is safe:"
    echo "     HMAC(k, m) = MD5(k XOR opad || MD5(k XOR ipad || m))"
    echo "     The outer hash wraps the inner, so extending the inner"
    echo "     message does NOT produce a valid HMAC output."
    echo ""
    echo "  APK context:"
    echo "     Android APK v1 signing (JAR signing) uses the certificate's"
    echo "     declared algorithm. Alipay's cert declares md5WithRSAEncryption."
    echo "     APK Signature Scheme v2/v3 uses SHA-256 and signs the entire"
    echo "     APK file, rendering this and all MD5-based attacks moot."
    echo ""
else
    echo "  Attack verification FAILED (exit code: $EXIT_CODE)"
    exit $EXIT_CODE
fi
