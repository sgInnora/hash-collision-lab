#!/bin/bash
echo "╔═══════════════════════════════════════════════════════╗"
echo "║     Hash Collision Verification - Innora AI Lab      ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

echo "━━━ SHA-1 Collision ━━━"
echo "File A: sha1-collision/innora-doc-A.pdf"
echo "File B: sha1-collision/innora-doc-B.pdf"
SHA1_A=$(shasum sha1-collision/innora-doc-A.pdf | cut -d' ' -f1)
SHA1_B=$(shasum sha1-collision/innora-doc-B.pdf | cut -d' ' -f1)
echo "SHA-1 A: $SHA1_A"
echo "SHA-1 B: $SHA1_B"
if [ "$SHA1_A" = "$SHA1_B" ]; then
  echo "✅ SHA-1 MATCH — Collision confirmed!"
else
  echo "❌ SHA-1 differ"
fi
SHA256_A=$(shasum -a 256 sha1-collision/innora-doc-A.pdf | cut -d' ' -f1)
SHA256_B=$(shasum -a 256 sha1-collision/innora-doc-B.pdf | cut -d' ' -f1)
echo "SHA-256 A: $SHA256_A"
echo "SHA-256 B: $SHA256_B"
if [ "$SHA256_A" != "$SHA256_B" ]; then
  echo "✅ SHA-256 differ — Files are genuinely different"
fi
DIFF=$(cmp -l sha1-collision/innora-doc-A.pdf sha1-collision/innora-doc-B.pdf | wc -l)
echo "Binary differences: $DIFF bytes"

echo ""
echo "━━━ MD5 Collision ━━━"
echo "File A: md5-collision/innora-doc-A.pdf"
echo "File B: md5-collision/innora-doc-B.pdf"
MD5_A=$(md5sum md5-collision/innora-doc-A.pdf 2>/dev/null || md5 -q md5-collision/innora-doc-A.pdf)
MD5_B=$(md5sum md5-collision/innora-doc-B.pdf 2>/dev/null || md5 -q md5-collision/innora-doc-B.pdf)
echo "MD5 A: $MD5_A"
echo "MD5 B: $MD5_B"
if [ "$MD5_A" = "$MD5_B" ]; then
  echo "✅ MD5 MATCH — Collision confirmed!"
else
  echo "❌ MD5 differ"
fi
SHA1_MA=$(shasum md5-collision/innora-doc-A.pdf | cut -d' ' -f1)
SHA1_MB=$(shasum md5-collision/innora-doc-B.pdf | cut -d' ' -f1)
echo "SHA-1 A: $SHA1_MA"
echo "SHA-1 B: $SHA1_MB"
if [ "$SHA1_MA" != "$SHA1_MB" ]; then
  echo "✅ SHA-1 differ — Files are genuinely different"
fi
DIFF2=$(cmp -l md5-collision/innora-doc-A.pdf md5-collision/innora-doc-B.pdf | wc -l)
echo "Binary differences: $DIFF2 bytes"

echo ""
echo "━━━ Conclusion ━━━"
echo "Both MD5 and SHA-1 are cryptographically broken."
echo "Use SHA-256 or SHA-3 for integrity verification."
