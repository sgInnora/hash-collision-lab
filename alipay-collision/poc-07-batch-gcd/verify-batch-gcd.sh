#!/bin/bash
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  Batch GCD Attack — RSA Key Factoring at Scale          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"

echo "━━━ Certificate Collection Summary ━━━"
TOTAL=$(grep -c "bits)" "$DIR/batch-gcd-report.txt" 2>/dev/null || echo "0")
echo "  Total certificates analyzed: $TOTAL"
echo ""

echo "━━━ Key Size Distribution ━━━"
grep "bits)" "$DIR/batch-gcd-report.txt" | grep -oE "[0-9]+ bits" | sort | uniq -c | sort -rn
echo ""

echo "━━━ Vulnerable Keys (Factored via Batch GCD) ━━━"
VULN=$(python3 -c "import json; print(len(json.load(open('$DIR/MEGA_VULNERABLE.json'))))" 2>/dev/null || echo "?")
echo "  Keys fully factored: $VULN"
echo ""

python3 -c "
import json
with open('$DIR/MEGA_VULNERABLE.json') as f:
    data = json.load(f)
print('  IP Address          | Port  | Bits | Status')
print('  --------------------|-------|------|--------')
for entry in data[:10]:
    ip = entry.get('ip', '?')
    port = entry.get('port', '?')
    bits = entry.get('bits', '?')
    print(f'  {ip:<20}| {port:<6}| {bits:<5}| FACTORED — private key recovered')
if len(data) > 10:
    print(f'  ... and {len(data)-10} more')
" 2>/dev/null

echo ""
echo "━━━ Shared Prime Factor Analysis ━━━"
python3 -c "
import json
from collections import Counter
with open('$DIR/MEGA_VULNERABLE.json') as f:
    data = json.load(f)
primes = []
for e in data:
    primes.extend([e.get('p',''), e.get('q','')])
freq = Counter(primes)
shared = {p: c for p, c in freq.items() if c > 1 and p}
print(f'  Total prime factors: {len([p for p in primes if p])}')
print(f'  Unique primes: {len(set(p for p in primes if p))}')
print(f'  Shared primes: {len(shared)} (appear in multiple keys)')
print()
print('  ⚠️  Shared primes indicate weak PRNG in key generation.')
print('     Batch GCD exploits this to factor keys in O(n·log²n) time.')
" 2>/dev/null

echo ""
echo "━━━ Impact ━━━"
echo "  Every factored key means:"
echo "  • Full TLS private key recovery"
echo "  • Ability to decrypt all past/future traffic (no PFS)"
echo "  • Man-in-the-middle attack capability"
echo "  • Server impersonation"
echo ""
echo "  ⚠️  $VULN servers' RSA keys were factored from public certificates alone."
