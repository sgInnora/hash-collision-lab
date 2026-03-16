#!/usr/bin/env bash
# verify-timeline.sh — Verify attack timeline content integrity
# PoC-11: Attack Timeline Visualization
# Innora AI Security Research

set -euo pipefail

TIMELINE_DIR="$(cd "$(dirname "$0")" && pwd)"

PASS=0
FAIL=0
WARN=0

green()  { printf '\033[0;32m[PASS]\033[0m %s\n' "$*"; }
red()    { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; }
yellow() { printf '\033[0;33m[WARN]\033[0m %s\n' "$*"; }
info()   { printf '\033[0;36m[INFO]\033[0m %s\n' "$*"; }
header() { printf '\n\033[1;37m%s\033[0m\n%s\n' "$*" "$(printf '─%.0s' {1..60})"; }

check() {
  local desc="$1"
  local result="$2"
  if [ "$result" = "pass" ]; then
    green "$desc"
    PASS=$((PASS + 1))
  elif [ "$result" = "warn" ]; then
    yellow "$desc"
    WARN=$((WARN + 1))
  else
    red "$desc"
    FAIL=$((FAIL + 1))
  fi
}

# ─────────────────────────────────────────────
header "FILE EXISTENCE CHECKS"
# ─────────────────────────────────────────────

for f in "timeline.md" "index.html" "verify-timeline.sh"; do
  if [ -f "$TIMELINE_DIR/$f" ]; then
    check "File exists: $f" "pass"
  else
    check "File exists: $f" "fail"
  fi
done

# ─────────────────────────────────────────────
header "TIMELINE.MD — KEY EVENT VERIFICATION"
# ─────────────────────────────────────────────

MD_FILE="$TIMELINE_DIR/timeline.md"

KEY_EVENTS=(
  "2004"
  "2005"
  "2006"
  "2008"
  "2009"
  "2009-12-16"
  "2012"
  "2013"
  "2015"
  "2017"
  "2020"
  "2023"
  "2025"
  "2026"
  "2026-03-10"
)

echo ""
info "Checking key dates in timeline.md..."
DATES_FOUND=0
for date in "${KEY_EVENTS[@]}"; do
  if grep -q "$date" "$MD_FILE" 2>/dev/null; then
    DATES_FOUND=$((DATES_FOUND + 1))
  fi
done
check "Key dates found: $DATES_FOUND / ${#KEY_EVENTS[@]}" \
  "$([ "$DATES_FOUND" -eq "${#KEY_EVENTS[@]}" ] && echo 'pass' || echo 'fail')"

KEY_TERMS=(
  "md5WithRSAEncryption"
  "RSA-1024"
  "FastColl"
  "SHAttered"
  "Janus"
  "CVE-2017-13156"
  "Flame"
  "Batch GCD"
  "Innora"
  "Ant Group"
  "Wang et al"
  "SHA-1 is a Shambles"
)

info "Checking key technical terms in timeline.md..."
TERMS_FOUND=0
for term in "${KEY_TERMS[@]}"; do
  if grep -qi "$term" "$MD_FILE" 2>/dev/null; then
    TERMS_FOUND=$((TERMS_FOUND + 1))
  fi
done
check "Technical terms found: $TERMS_FOUND / ${#KEY_TERMS[@]}" \
  "$([ "$TERMS_FOUND" -eq "${#KEY_TERMS[@]}" ] && echo 'pass' || echo 'fail')"

# Mermaid syntax check
if grep -q '```mermaid' "$MD_FILE" 2>/dev/null; then
  check "Mermaid code blocks present" "pass"
else
  check "Mermaid code blocks present" "fail"
fi

MERMAID_BLOCKS=$(grep -c '```mermaid' "$MD_FILE" 2>/dev/null || echo 0)
check "Multiple Mermaid diagrams: $MERMAID_BLOCKS blocks" \
  "$([ "$MERMAID_BLOCKS" -ge 2 ] && echo 'pass' || echo 'warn')"

# ─────────────────────────────────────────────
header "INDEX.HTML — D3.JS VISUALIZATION CHECKS"
# ─────────────────────────────────────────────

HTML_FILE="$TIMELINE_DIR/index.html"

if grep -q 'd3js.org/d3.v7.min.js' "$HTML_FILE" 2>/dev/null; then
  check "D3.js v7 CDN referenced" "pass"
else
  check "D3.js v7 CDN referenced" "fail"
fi

if grep -q 'zoom' "$HTML_FILE" 2>/dev/null; then
  check "Zoom/pan functionality present" "pass"
else
  check "Zoom/pan functionality present" "fail"
fi

LANES=("Cryptographic Attacks" "Alipay" "Industry Response")
for lane in "${LANES[@]}"; do
  if grep -q "$lane" "$HTML_FILE" 2>/dev/null; then
    check "Lane present: '$lane'" "pass"
  else
    check "Lane present: '$lane'" "fail"
  fi
done

if grep -q 'tooltip' "$HTML_FILE" 2>/dev/null; then
  check "Tooltip/hover functionality present" "pass"
else
  check "Tooltip/hover functionality present" "fail"
fi

if grep -qi 'ff7b72\|#da3633\|red' "$HTML_FILE" 2>/dev/null; then
  check "Alipay red highlight color present" "pass"
else
  check "Alipay red highlight color present" "warn"
fi

CONCLUSION_TEXT="Alipay's certificate was issued AFTER MD5 was broken, and remains in use 17 years later"
if grep -q "17 years later" "$HTML_FILE" 2>/dev/null; then
  check "Conclusion statement present (17 years)" "pass"
else
  check "Conclusion statement present (17 years)" "fail"
fi

if grep -q 'resize' "$HTML_FILE" 2>/dev/null; then
  check "Responsive resize handler present" "pass"
else
  check "Responsive resize handler present" "warn"
fi

HTML_EVENTS=$(grep -c "title:" "$HTML_FILE" 2>/dev/null || echo 0)
check "Event count in HTML: $HTML_EVENTS events defined" \
  "$([ "$HTML_EVENTS" -ge 15 ] && echo 'pass' || echo 'warn')"

# ─────────────────────────────────────────────
header "DATE RANGE & COVERAGE ANALYSIS"
# ─────────────────────────────────────────────

info "Scanning timeline.md for year references..."
EARLIEST_YEAR=$(grep -oE '\b(200[0-9]|201[0-9]|202[0-9])\b' "$MD_FILE" 2>/dev/null | sort -n | head -1)
LATEST_YEAR=$(grep -oE '\b(200[0-9]|201[0-9]|202[0-9])\b' "$MD_FILE" 2>/dev/null | sort -n | tail -1)

info "Earliest year found: ${EARLIEST_YEAR:-unknown}"
info "Latest year found:   ${LATEST_YEAR:-unknown}"

check "Coverage starts at or before 2004" \
  "$([ "${EARLIEST_YEAR:-9999}" -le 2004 ] && echo 'pass' || echo 'fail')"
check "Coverage extends to 2026" \
  "$([ "${LATEST_YEAR:-0}" -ge 2026 ] && echo 'pass' || echo 'fail')"

YEAR_SPAN=$(( ${LATEST_YEAR:-2026} - ${EARLIEST_YEAR:-2004} ))
info "Timeline span: ~${YEAR_SPAN} years (${EARLIEST_YEAR}–${LATEST_YEAR})"

# ─────────────────────────────────────────────
header "FILE SIZE SANITY"
# ─────────────────────────────────────────────

for f in "timeline.md" "index.html"; do
  SIZE=$(wc -c < "$TIMELINE_DIR/$f" 2>/dev/null || echo 0)
  SIZE_KB=$(( SIZE / 1024 ))
  check "File size OK ($f): ${SIZE_KB}KB" \
    "$([ "$SIZE" -gt 1000 ] && echo 'pass' || echo 'fail')"
done

# ─────────────────────────────────────────────
header "SUMMARY"
# ─────────────────────────────────────────────

TOTAL=$((PASS + FAIL + WARN))
echo ""
printf "  Total checks : %d\n" "$TOTAL"
printf "  \033[0;32mPASS\033[0m         : %d\n" "$PASS"
printf "  \033[0;31mFAIL\033[0m         : %d\n" "$FAIL"
printf "  \033[0;33mWARN\033[0m         : %d\n" "$WARN"
echo ""

if [ "$FAIL" -eq 0 ]; then
  printf '\033[0;32m[OK] All required checks passed. Timeline visualization is complete.\033[0m\n'
  exit 0
else
  printf '\033[0;31m[ERROR] %d check(s) failed. Review output above.\033[0m\n' "$FAIL"
  exit 1
fi
