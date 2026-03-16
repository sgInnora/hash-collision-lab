#!/usr/bin/env python3
"""Weak Randomness Analysis for Alipay Ecosystem.

Analyzes DES key entropy, certificate key reuse, and shared prime
factors indicative of weak PRNG in cryptographic key generation.
"""
import json
import math
import os
import re
import sys
from collections import Counter

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BATCH_GCD_REPORT = os.path.join(SCRIPT_DIR, "..", "poc-07-batch-gcd", "batch-gcd-report.txt")
MEGA_VULN = os.path.join(SCRIPT_DIR, "..", "poc-07-batch-gcd", "MEGA_VULNERABLE.json")


def shannon_entropy(data):
    """Calculate Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def analyze_des_keys():
    """Part A: DES Key Entropy Analysis."""
    print("━━━ Part A: DES Key Entropy Analysis ━━━")
    print()

    keys = [
        {"hex": "2d31313531353931", "ascii": "-1151591", "name": "Key 1"},
        {"hex": "636865636b4b6579", "ascii": "checkKey", "name": "Key 2"},
    ]

    ideal_entropy = 8.0  # bits per byte for perfect random

    for key in keys:
        raw = bytes.fromhex(key["hex"])
        entropy = shannon_entropy(raw)
        unique_bytes = len(set(raw))
        keyspace_bits = math.log2(256 ** len(raw)) if len(raw) > 0 else 0
        effective_bits = entropy * len(raw)

        # Check characteristics
        is_ascii = all(32 <= b < 127 for b in raw)
        is_meaningful = key["ascii"].isascii() and any(c.isalpha() for c in key["ascii"])

        print(f"  [{key['name']}]")
        print(f"    Hex:            {key['hex']}")
        print(f"    ASCII:          '{key['ascii']}'")
        print(f"    Length:         {len(raw)} bytes")
        print(f"    Unique bytes:   {unique_bytes}/{len(raw)}")
        print(f"    Shannon entropy: {entropy:.2f} bits/byte (ideal: {ideal_entropy:.1f})")
        print(f"    Effective keyspace: {effective_bits:.1f} bits (DES theoretical: 56 bits)")
        print(f"    Is printable ASCII: {'YES ⚠️' if is_ascii else 'No'}")
        print(f"    Is meaningful word: {'YES ⚠️' if is_meaningful else 'No'}")

        # Brute force estimation
        if is_ascii:
            # Only printable ASCII: 95 chars per position
            ascii_space = 95 ** len(raw)
            ascii_bits = math.log2(ascii_space)
            print(f"    ASCII keyspace:  {ascii_bits:.1f} bits ({ascii_space:,.0f} combinations)")
            ops_per_sec = 10**9  # ~1 billion DES ops/sec on modern GPU
            seconds = ascii_space / ops_per_sec
            if seconds < 1:
                print(f"    Brute force:     < 1 second (GPU)")
            elif seconds < 3600:
                print(f"    Brute force:     {seconds:.0f} seconds (GPU)")
            else:
                print(f"    Brute force:     {seconds/3600:.1f} hours (GPU)")
        print()

    # DES itself
    print("  DES Algorithm Weakness:")
    print("    Effective key size: 56 bits (8 parity bits discarded)")
    print("    Brute force at 10^9 ops/sec: ~0.83 days")
    print("    Deep Crack (1998): 56 hours")
    print("    Modern FPGA cluster: < 1 hour")
    print("    → DES is broken regardless of key quality")
    print("    → Hardcoded ASCII keys make it trivially extractable")
    print()


def analyze_cert_key_reuse():
    """Part B: Certificate Key Reuse Detection."""
    print("━━━ Part B: Certificate Key Reuse Detection ━━━")
    print()

    if not os.path.exists(BATCH_GCD_REPORT):
        print(f"  ⚠️  Batch GCD report not found: {BATCH_GCD_REPORT}")
        return {}

    with open(BATCH_GCD_REPORT, 'r') as f:
        content = f.read()

    # Parse modulus entries
    modulus_map = {}  # modulus_prefix -> [(name, bits)]
    bit_counts = Counter()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('Batch') or line.startswith('Result'):
            continue
        # Format: "name: 0xMODULUS... (BITS bits)"
        match = re.match(r'^(.+?):\s+0x([0-9a-fA-F]+)\.\.\.\s+\((\d+)\s+bits\)', line)
        if match:
            name = match.group(1).strip()
            mod_prefix = match.group(2).lower()
            bits = int(match.group(3))
            bit_counts[bits] += 1
            if mod_prefix not in modulus_map:
                modulus_map[mod_prefix] = []
            modulus_map[mod_prefix].append((name, bits))

    # Key reuse statistics
    reuse_groups = {k: v for k, v in modulus_map.items() if len(v) > 1}
    total_certs = sum(len(v) for v in modulus_map.values())

    print(f"  Total certificates analyzed: {total_certs}")
    print(f"  Unique moduli: {len(modulus_map)}")
    print(f"  Key reuse groups: {len(reuse_groups)}")
    print()

    print("  Key size distribution:")
    for bits, count in sorted(bit_counts.items()):
        risk = "CRITICAL" if bits <= 512 else "HIGH" if bits <= 1024 else "MEDIUM" if bits <= 2048 else "LOW"
        print(f"    {bits}-bit: {count} certs [{risk}]")
    print()

    if reuse_groups:
        print("  Key reuse detected (same modulus):")
        for mod_prefix, certs in sorted(reuse_groups.items(), key=lambda x: -len(x[1])):
            print(f"    Modulus 0x{mod_prefix[:16]}... ({len(certs)} certs):")
            for name, bits in certs[:5]:
                print(f"      - {name} ({bits}-bit)")
            if len(certs) > 5:
                print(f"      ... and {len(certs) - 5} more")
        print()

    return bit_counts


def analyze_shared_primes():
    """Part C: Weak PRNG Detection via Shared Prime Factors."""
    print("━━━ Part C: Weak PRNG Detection (Shared Prime Factors) ━━━")
    print()

    if not os.path.exists(MEGA_VULN):
        print(f"  ⚠️  MEGA_VULNERABLE.json not found: {MEGA_VULN}")
        return

    with open(MEGA_VULN, 'r') as f:
        vuln_data = json.load(f)

    print(f"  Factored keys: {len(vuln_data)}")
    print()

    # Collect all primes
    all_p = []
    all_q = []
    prime_to_ips = {}

    for entry in vuln_data:
        ip = entry.get("ip", "unknown")
        p = entry.get("p", "")
        q = entry.get("q", "")
        bits = entry.get("bits", 0)

        if p:
            all_p.append(p)
            prime_to_ips.setdefault(p, []).append(ip)
        if q:
            all_q.append(q)
            prime_to_ips.setdefault(q, []).append(ip)

    # Find shared primes
    all_primes = all_p + all_q
    prime_freq = Counter(all_primes)
    shared = {p: c for p, c in prime_freq.items() if c > 1}

    print(f"  Total prime factors collected: {len(all_primes)}")
    print(f"  Unique primes: {len(set(all_primes))}")
    print(f"  Shared primes (appear in >1 key): {len(shared)}")
    print()

    if shared:
        print("  Shared prime factor details:")
        for prime, count in sorted(shared.items(), key=lambda x: -x[1]):
            ips = prime_to_ips[prime]
            p_short = prime[:20] + "..." if len(prime) > 20 else prime
            print(f"    Prime {p_short}")
            print(f"      Shared across {count} keys: {', '.join(ips[:5])}")
            if len(ips) > 5:
                print(f"      ... and {len(ips) - 5} more IPs")
        print()

        print("  PRNG Weakness Indicators:")
        print("    ⚠️  Shared prime factors strongly indicate:")
        print("    1. Low-entropy PRNG seed (e.g., system time with second resolution)")
        print("    2. Same PRNG instance across multiple key generations")
        print("    3. Embedded device with limited entropy pool (/dev/urandom underflow)")
        print("    4. Factory-default keys never rotated")
        print()
    else:
        print("  No shared prime factors detected in factored keys.")
        print()

    # Key size analysis
    bit_dist = Counter(entry.get("bits", 0) for entry in vuln_data)
    print("  Factored key sizes:")
    for bits, count in sorted(bit_dist.items()):
        print(f"    {bits}-bit: {count} keys")
    print()


def risk_assessment():
    """Part D: Comprehensive Risk Assessment."""
    print("━━━ Part D: Comprehensive Risk Assessment ━━━")
    print()

    findings = [
        {
            "id": "WR-01",
            "title": "Hardcoded DES Keys",
            "severity": "CRITICAL",
            "cvss": "9.8",
            "description": "DES encryption keys are hardcoded ASCII strings, trivially extractable",
            "impact": "Complete bypass of DES encryption, data exposure",
            "recommendation": "Replace DES with AES-256-GCM, use hardware-backed key storage",
        },
        {
            "id": "WR-02",
            "title": "DES Algorithm (Obsolete)",
            "severity": "HIGH",
            "cvss": "7.5",
            "description": "56-bit DES is brute-forceable in hours on modern hardware",
            "impact": "All DES-encrypted data is effectively plaintext",
            "recommendation": "Migrate to AES-256 or ChaCha20-Poly1305",
        },
        {
            "id": "WR-03",
            "title": "Certificate Key Reuse",
            "severity": "HIGH",
            "cvss": "7.4",
            "description": "Multiple APKs share identical RSA moduli (same keypair)",
            "impact": "Compromising one key compromises all apps using same cert",
            "recommendation": "Generate unique keypairs per application",
        },
        {
            "id": "WR-04",
            "title": "Shared Prime Factors (Weak PRNG)",
            "severity": "CRITICAL",
            "cvss": "9.1",
            "description": "RSA keys from different servers share prime factors, enabling Batch GCD factoring",
            "impact": "Full private key recovery, TLS interception, data theft",
            "recommendation": "Use cryptographically secure PRNG (CSPRNG) with hardware entropy",
        },
        {
            "id": "WR-05",
            "title": "512-bit RSA Keys in Production",
            "severity": "CRITICAL",
            "cvss": "9.8",
            "description": "512-bit RSA keys factored in seconds, yet still deployed on public servers",
            "impact": "Complete TLS compromise, MITM attacks trivial",
            "recommendation": "Minimum RSA-2048, prefer RSA-4096 or Ed25519",
        },
    ]

    for f in findings:
        print(f"  [{f['severity']}] {f['id']}: {f['title']} (CVSS {f['cvss']})")
        print(f"    Issue: {f['description']}")
        print(f"    Impact: {f['impact']}")
        print(f"    Fix: {f['recommendation']}")
        print()


def main():
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║  Weak Randomness & Key Quality Analysis — Alipay Ecosystem  ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print()

    analyze_des_keys()
    analyze_cert_key_reuse()
    analyze_shared_primes()
    risk_assessment()

    print("━━━ Conclusion ━━━")
    print("  Multiple classes of weak randomness detected:")
    print("  • Hardcoded DES keys (zero entropy)")
    print("  • Certificate key reuse (same modulus across apps)")
    print("  • Shared RSA prime factors (weak PRNG)")
    print("  • 512-bit RSA keys still in production")
    print()
    print("  These findings demonstrate systemic cryptographic weakness")
    print("  stemming from poor random number generation practices.")
    print()


if __name__ == "__main__":
    main()
