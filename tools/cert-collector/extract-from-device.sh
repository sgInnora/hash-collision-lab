#!/bin/bash
# Extract APK signing certificates from connected Android device/emulator
set -e

DEVICE="${1:-emulator-5554}"
OUTPUT_DIR="${2:-/tmp/device-apks}"
mkdir -p "$OUTPUT_DIR"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Device APK Certificate Extractor                           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo "Device: $DEVICE"
echo "Output: $OUTPUT_DIR"
echo ""

# List all installed packages (non-system for more variety, then system)
echo "━━━ Listing installed packages ━━━"
PACKAGES=$(adb -s "$DEVICE" shell pm list packages -3 2>/dev/null | sed 's/package://' | sort)
SYS_PACKAGES=$(adb -s "$DEVICE" shell pm list packages -s 2>/dev/null | sed 's/package://' | sort)

TOTAL_3RD=$(echo "$PACKAGES" | wc -l | tr -d ' ')
TOTAL_SYS=$(echo "$SYS_PACKAGES" | wc -l | tr -d ' ')
echo "  Third-party packages: $TOTAL_3RD"
echo "  System packages: $TOTAL_SYS"
echo ""

EXTRACTED=0

extract_apk() {
  local pkg="$1"
  local apk_path
  apk_path=$(adb -s "$DEVICE" shell pm path "$pkg" 2>/dev/null | head -1 | sed 's/package://' | tr -d '\r')

  if [ -z "$apk_path" ]; then
    return 1
  fi

  local output_file="$OUTPUT_DIR/${pkg}.apk"
  if [ -f "$output_file" ]; then
    return 0  # Already extracted
  fi

  adb -s "$DEVICE" pull "$apk_path" "$output_file" > /dev/null 2>&1
  if [ -f "$output_file" ] && [ -s "$output_file" ]; then
    EXTRACTED=$((EXTRACTED + 1))
    return 0
  fi
  return 1
}

echo "━━━ Extracting third-party APKs ━━━"
for pkg in $PACKAGES; do
  echo -n "  $pkg... "
  if extract_apk "$pkg"; then
    echo "OK"
  else
    echo "SKIP"
  fi
done

echo ""
echo "━━━ Extracting system APKs (finance/payment related) ━━━"
for pkg in $SYS_PACKAGES; do
  # Only extract finance-related system apps
  case "$pkg" in
    *pay*|*bank*|*finance*|*wallet*|*money*|*alipay*|*wechat*|*union*)
      echo -n "  $pkg... "
      if extract_apk "$pkg"; then
        echo "OK"
      else
        echo "SKIP"
      fi
      ;;
  esac
done

echo ""
echo "━━━ Summary ━━━"
echo "  Extracted: $EXTRACTED APKs"
echo "  Directory: $OUTPUT_DIR"
echo ""
echo "Next: python3 tools/cert-collector/collect-certs.py $OUTPUT_DIR"
