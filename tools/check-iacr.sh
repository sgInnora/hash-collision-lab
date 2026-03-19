#!/bin/bash
# Check IACR ePrint 2026/108361 status
URL="https://eprint.iacr.org/2026/108361"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)
TITLE=$(curl -s "$URL" 2>/dev/null | grep -o '<title>[^<]*' | head -1 | sed 's/<title>//')

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

if [ "$STATUS" = "200" ] && echo "$TITLE" | grep -qiv "unknown"; then
  echo "[$TIMESTAMP] ✅ IACR 2026/108361 LIVE — $URL"
  echo "$TITLE"
  osascript -e "display notification \"IACR ePrint 2026/108361 is LIVE!\" with title \"Paper Published\" sound name \"Glass\"" 2>/dev/null
else
  echo "[$TIMESTAMP] ⏳ Still pending (HTTP $STATUS) — $TITLE"
fi
