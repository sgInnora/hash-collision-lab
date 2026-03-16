#!/bin/bash
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  RSA-1024 Key Strength Analysis — Alipay APK Cert       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"

echo "━━━ Certificate Key Details ━━━"
echo "  Algorithm: RSA-1024 (md5WithRSAEncryption)"
echo "  Issued: 2009-12-16"
echo "  Expires: 2051-01-10"
echo ""

echo "━━━ Analysis Report ━━━"
cat "$DIR/analysis-report.txt"
echo ""

echo "━━━ Risk Assessment ━━━"
echo "  RSA-1024 is considered insecure since 2013 (NIST deprecation)."
echo "  Estimated factoring cost: \$50K-\$100K (academic), less with nation-state resources."
echo "  RSA-768 was factored in 2009 by Lenstra et al."
echo "  RSA-1024 factoring is projected feasible by well-funded adversaries."
echo ""
echo "  ⚠️  Alipay continues using a 2009-era RSA-1024 key for APK signing."
