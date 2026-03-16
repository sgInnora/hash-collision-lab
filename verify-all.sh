#!/bin/bash
# Master verification script — runs all PoCs in the Hash Collision Lab
set -e

cd "$(dirname "$0")"

PASS=0
FAIL=0
TOTAL=0

run_poc() {
  local name="$1"
  local script="$2"
  TOTAL=$((TOTAL + 1))
  echo ""
  echo "╔═══════════════════════════════════════════════════════════════╗"
  echo "║  [$TOTAL] $name"
  echo "╚═══════════════════════════════════════════════════════════════╝"
  if bash "$script" 2>&1; then
    PASS=$((PASS + 1))
    echo "  → RESULT: ✅ PASS"
  else
    FAIL=$((FAIL + 1))
    echo "  → RESULT: ❌ FAIL"
  fi
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║           Hash Collision Lab — Full Verification Suite           ║"
echo "║                    Innora AI Security Research                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Running all PoCs in attacker kill-chain order..."
echo ""

# Phase 1: Reconnaissance — Hash collision fundamentals
echo "═══ PHASE 1: RECONNAISSANCE — Hash Collision Fundamentals ═══"
run_poc "MD5 PDF Collision (FastColl)" "verify.sh"

# Phase 2: Target Analysis — Certificate weakness discovery
echo "═══ PHASE 2: TARGET ANALYSIS — Certificate Weakness Discovery ═══"
run_poc "Alipay Cert MD5 Collision" "alipay-collision/poc-01-md5-cert/verify-alipay-collision.sh"
run_poc "RSA-1024 Key Analysis" "alipay-collision/poc-02-rsa1024-analysis/verify-rsa1024.sh"
run_poc "DES Key Extraction (Hardcoded)" "alipay-collision/poc-03-des-bruteforce/verify-des.sh"
run_poc "Weak Randomness Analysis" "alipay-collision/poc-08-weak-random/verify-weak-random.sh"

# Phase 3: Exploitation — Active attack demonstrations
echo "═══ PHASE 3: EXPLOITATION — Active Attack Demonstrations ═══"
run_poc "MD5 Length Extension Attack" "alipay-collision/poc-04-md5-length-extension/verify-length-extension.sh"
run_poc "APK v1 Janus Attack (CVE-2017-13156)" "alipay-collision/poc-05-apk-v1-janus/verify-janus.sh"
run_poc "APK v1 Signature Forgery" "alipay-collision/poc-05-apk-v1-signature-forgery/verify-sig-forgery.sh"
run_poc "Rogue Certificate Forgery" "alipay-collision/poc-06-rogue-cert-forgery/verify-rogue-cert.sh"

# Phase 4: Full Compromise — Large-scale and chain attacks
echo "═══ PHASE 4: FULL COMPROMISE — Large-Scale & Chain Attacks ═══"
run_poc "Batch GCD (RSA Key Factoring)" "alipay-collision/poc-07-batch-gcd/verify-batch-gcd.sh"
run_poc "SHA-1 Certificate Collision" "alipay-collision/poc-07-sha1-cert-collision/verify-sha1-cert.sh"

# Summary
echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                        FINAL SUMMARY                            ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║  Total PoCs:  $TOTAL                                               ║"
echo "║  Passed:      $PASS                                               ║"
echo "║  Failed:      $FAIL                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
if [ $FAIL -eq 0 ]; then
  echo "✅ ALL POCS PASSED — Full attack chain verified."
else
  echo "⚠️  $FAIL PoC(s) failed. Check output above for details."
fi
echo ""
echo "Conclusion: Alipay's APK signing infrastructure uses md5WithRSAEncryption"
echo "with RSA-1024 (2009-era), presenting a comprehensive attack surface across"
echo "hash collisions, key management, signature scheme, and cryptographic design."
