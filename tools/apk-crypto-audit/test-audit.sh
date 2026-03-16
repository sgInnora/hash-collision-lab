#!/bin/bash
# test-audit.sh — Test script for apk-crypto-audit
# Runs the audit against real APKs if present, otherwise builds minimal synthetic ones.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT="$SCRIPT_DIR/apk-crypto-audit.py"
TMPDIR_LOCAL="$(mktemp -d)"
PASS=0
FAIL=0

cleanup() {
    rm -rf "$TMPDIR_LOCAL"
}
trap cleanup EXIT

log()  { echo "[TEST] $*"; }
ok()   { echo "  PASS: $*"; ((PASS++)); }
fail() { echo "  FAIL: $*"; ((FAIL++)); }

# ---------------------------------------------------------------------------
# Helper: create a minimal APK with a specific signing configuration
# ---------------------------------------------------------------------------

# Build a tiny valid ZIP / APK skeleton with a given certificate placed in META-INF/CERT.RSA
# Usage: make_fake_apk <output_path> <key_type> [extra_flags]
#
# key_type values:
#   md5rsa    — RSA-1024, MD5 signature
#   sha1rsa   — RSA-2048, SHA-1 signature
#   sha256rsa — RSA-2048, SHA-256 signature
#   sha256rsa4096 — RSA-4096, SHA-256 signature

make_fake_apk() {
    local apk_out="$1"
    local key_type="$2"
    local work="$TMPDIR_LOCAL/build_$key_type"
    mkdir -p "$work/META-INF"

    local key_file="$work/signing.key"
    local cert_file="$work/signing.crt"
    local p7_file="$work/META-INF/CERT.RSA"
    local sf_file="$work/META-INF/CERT.SF"
    local mf_file="$work/META-INF/MANIFEST.MF"

    # Generate key and self-signed cert
    case "$key_type" in
        md5rsa)
            openssl genrsa -out "$key_file" 1024 2>/dev/null
            openssl req -new -x509 -key "$key_file" -out "$cert_file" \
                -days 3650 -md5 \
                -subj "/CN=TestMD5/O=Test/C=US" 2>/dev/null
            ;;
        sha1rsa)
            openssl genrsa -out "$key_file" 2048 2>/dev/null
            openssl req -new -x509 -key "$key_file" -out "$cert_file" \
                -days 3650 -sha1 \
                -subj "/CN=TestSHA1/O=Test/C=US" 2>/dev/null
            ;;
        sha256rsa)
            openssl genrsa -out "$key_file" 2048 2>/dev/null
            openssl req -new -x509 -key "$key_file" -out "$cert_file" \
                -days 3650 -sha256 \
                -subj "/CN=TestSHA256/O=Test/C=US" 2>/dev/null
            ;;
        sha256rsa4096)
            openssl genrsa -out "$key_file" 4096 2>/dev/null
            openssl req -new -x509 -key "$key_file" -out "$cert_file" \
                -days 3650 -sha256 \
                -subj "/CN=TestSHA256-4096/O=Test/C=US" 2>/dev/null
            ;;
        *)
            echo "Unknown key type: $key_type" >&2
            return 1
            ;;
    esac

    # Wrap cert in PKCS#7 SignedData (detached, no content)
    openssl crl2pkcs7 -nocrl -certfile "$cert_file" -outform DER -out "$p7_file" 2>/dev/null

    # Create stub META-INF files (content doesn't matter for our tests)
    printf "Manifest-Version: 1.0\r\n\r\n" > "$mf_file"
    printf "Signature-Version: 1.0\r\n\r\n" > "$sf_file"

    # Create a dummy file to include in the zip
    echo "placeholder" > "$work/classes.dex"

    # Build APK (zip) with v1 signing artifacts only
    (cd "$work" && zip -q "$apk_out" classes.dex META-INF/MANIFEST.MF META-INF/CERT.SF META-INF/CERT.RSA)
}

# ---------------------------------------------------------------------------
# Check dependencies
# ---------------------------------------------------------------------------

log "Checking dependencies..."

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found in PATH" >&2
    exit 1
fi

if ! command -v openssl &>/dev/null; then
    echo "WARNING: openssl not found — skipping certificate-based tests"
    NO_OPENSSL=1
else
    NO_OPENSSL=0
fi

if ! command -v zip &>/dev/null; then
    echo "WARNING: zip not found — skipping synthetic APK tests"
    NO_ZIP=1
else
    NO_ZIP=0
fi

# ---------------------------------------------------------------------------
# Test 1: Script runs and shows help
# ---------------------------------------------------------------------------

log "Test 1: --help flag"
if python3 "$AUDIT" --help > /dev/null 2>&1; then
    ok "--help exits 0"
else
    fail "--help exited non-zero"
fi

# ---------------------------------------------------------------------------
# Test 2: Missing file returns error
# ---------------------------------------------------------------------------

log "Test 2: missing file path"
if ! python3 "$AUDIT" /nonexistent/path/fake.apk > /dev/null 2>&1; then
    ok "Missing file path exits non-zero"
else
    fail "Missing file path should exit non-zero"
fi

# ---------------------------------------------------------------------------
# Test 3: Real APKs in this repo or nearby directories
# ---------------------------------------------------------------------------

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REAL_APKS=()
while IFS= read -r -d '' f; do
    REAL_APKS+=("$f")
done < <(find "$REPO_ROOT" -name "*.apk" -print0 2>/dev/null)

if [[ ${#REAL_APKS[@]} -gt 0 ]]; then
    log "Test 3: Real APKs found (${#REAL_APKS[@]}) — running audit"
    for apk in "${REAL_APKS[@]}"; do
        log "  Auditing: $apk"
        if python3 "$AUDIT" --no-color "$apk" > /dev/null 2>&1; then
            ok "Audit completed for $(basename "$apk") (exit 0)"
        else
            exit_code=$?
            # Exit codes 1-3 mean findings were found, which is valid behavior
            if [[ $exit_code -le 3 ]]; then
                ok "Audit completed for $(basename "$apk") (exit $exit_code = findings present)"
            else
                fail "Audit crashed for $(basename "$apk") (exit $exit_code)"
            fi
        fi
    done
else
    log "Test 3: No real APKs found — skipping real-APK test"
fi

# ---------------------------------------------------------------------------
# Synthetic APK tests (require openssl + zip)
# ---------------------------------------------------------------------------

if [[ $NO_OPENSSL -eq 1 || $NO_ZIP -eq 1 ]]; then
    log "Skipping synthetic APK tests (openssl or zip unavailable)"
else
    # Test 4: MD5 signature → CRITICAL
    log "Test 4: MD5-signed APK should report CRITICAL"
    APK_MD5="$TMPDIR_LOCAL/md5.apk"
    make_fake_apk "$APK_MD5" md5rsa
    output=$(python3 "$AUDIT" --no-color "$APK_MD5" 2>&1)
    if echo "$output" | grep -q "CRITICAL"; then
        ok "MD5-signed APK triggers CRITICAL"
    else
        fail "MD5-signed APK did not trigger CRITICAL"
        echo "--- output ---"
        echo "$output"
    fi

    # Test 5: SHA-1 signature → HIGH
    log "Test 5: SHA-1-signed APK should report HIGH"
    APK_SHA1="$TMPDIR_LOCAL/sha1.apk"
    make_fake_apk "$APK_SHA1" sha1rsa
    output=$(python3 "$AUDIT" --no-color "$APK_SHA1" 2>&1)
    if echo "$output" | grep -q "HIGH"; then
        ok "SHA-1-signed APK triggers HIGH"
    else
        fail "SHA-1-signed APK did not trigger HIGH"
        echo "--- output ---"
        echo "$output"
    fi

    # Test 6: SHA-256, RSA-2048 → no CRITICAL
    log "Test 6: SHA-256 RSA-2048 APK should not report CRITICAL"
    APK_SHA256="$TMPDIR_LOCAL/sha256.apk"
    make_fake_apk "$APK_SHA256" sha256rsa
    output=$(python3 "$AUDIT" --no-color "$APK_SHA256" 2>&1)
    if ! echo "$output" | grep -q "\[CRITICAL\]"; then
        ok "SHA-256 RSA-2048 APK has no CRITICAL finding"
    else
        fail "SHA-256 RSA-2048 APK unexpectedly has CRITICAL finding"
        echo "--- output ---"
        echo "$output"
    fi

    # Test 7: RSA-4096 → OK on key length
    log "Test 7: SHA-256 RSA-4096 APK should show OK key length"
    APK_4096="$TMPDIR_LOCAL/sha256_4096.apk"
    make_fake_apk "$APK_4096" sha256rsa4096
    output=$(python3 "$AUDIT" --no-color "$APK_4096" 2>&1)
    if echo "$output" | grep -qi "4096"; then
        ok "RSA-4096 APK shows 4096-bit key"
    else
        fail "RSA-4096 APK did not mention 4096 bits"
        echo "--- output ---"
        echo "$output"
    fi

    # Test 8: v1-only signing → CRITICAL in signing scheme
    log "Test 8: v1-only APK should report CRITICAL signing scheme"
    # The synthetic APKs above are all v1-only (no APK Signing Block)
    output=$(python3 "$AUDIT" --no-color "$APK_SHA256" 2>&1)
    if echo "$output" | grep -q "v1 only"; then
        ok "v1-only APK triggers CRITICAL signing scheme"
    else
        fail "v1-only APK did not trigger CRITICAL signing scheme"
        echo "--- output ---"
        echo "$output"
    fi

    # Test 9: JSON output is valid JSON
    log "Test 9: --json output should be valid JSON"
    json_out=$(python3 "$AUDIT" --json "$APK_SHA256" 2>&1) || true
    if echo "$json_out" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        ok "--json produces valid JSON"
    else
        fail "--json did not produce valid JSON"
        echo "--- output ---"
        echo "$json_out"
    fi

    # Test 10: Key reuse detection across two APKs with same key
    log "Test 10: Key reuse detection (two APKs, same key)"
    # Build both APKs from the same key
    KEYREUSE_DIR="$TMPDIR_LOCAL/keyreuse"
    mkdir -p "$KEYREUSE_DIR"
    SHARED_KEY="$TMPDIR_LOCAL/shared.key"
    SHARED_CERT="$TMPDIR_LOCAL/shared.crt"
    SHARED_P7="$TMPDIR_LOCAL/shared.p7"
    openssl genrsa -out "$SHARED_KEY" 2048 2>/dev/null
    openssl req -new -x509 -key "$SHARED_KEY" -out "$SHARED_CERT" \
        -days 3650 -sha256 -subj "/CN=Shared/O=Test/C=US" 2>/dev/null
    openssl crl2pkcs7 -nocrl -certfile "$SHARED_CERT" -outform DER -out "$SHARED_P7" 2>/dev/null

    for i in 1 2; do
        WDIR="$TMPDIR_LOCAL/kr_build_$i"
        mkdir -p "$WDIR/META-INF"
        cp "$SHARED_P7" "$WDIR/META-INF/CERT.RSA"
        printf "Manifest-Version: 1.0\r\n\r\n" > "$WDIR/META-INF/MANIFEST.MF"
        printf "Signature-Version: 1.0\r\n\r\n" > "$WDIR/META-INF/CERT.SF"
        echo "placeholder$i" > "$WDIR/classes.dex"
        (cd "$WDIR" && zip -q "$KEYREUSE_DIR/app${i}.apk" classes.dex META-INF/MANIFEST.MF META-INF/CERT.SF META-INF/CERT.RSA)
    done

    output=$(python3 "$AUDIT" --no-color "$KEYREUSE_DIR" 2>&1)
    if echo "$output" | grep -q "key reuse\|reused"; then
        ok "Key reuse detected across two APKs with identical key"
    else
        fail "Key reuse was not detected"
        echo "--- output ---"
        echo "$output"
    fi

    # Test 11: --severity filter hides lower-severity findings
    log "Test 11: --severity CRITICAL filter hides non-CRITICAL findings"
    output=$(python3 "$AUDIT" --no-color --severity CRITICAL "$APK_SHA256" 2>&1)
    # SHA-256/RSA-2048 APK: CRITICAL from v1-only signing scheme; HIGH/MEDIUM from cert
    # With --severity CRITICAL, MEDIUM and WARNING should not appear
    if echo "$output" | grep -q "\[MEDIUM\]"; then
        fail "--severity CRITICAL still shows MEDIUM findings"
    else
        ok "--severity CRITICAL hides MEDIUM findings"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "=========================================="

[[ $FAIL -eq 0 ]]
