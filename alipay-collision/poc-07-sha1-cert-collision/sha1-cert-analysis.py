#!/usr/bin/env python3
"""SHA-1 Certificate Collision Analysis for Alipay APK Signing Certificate.

Analyzes the feasibility and cost of SHA-1 collision attacks against
Alipay's APK signing certificate, based on SHAttered (2017) and
SHA-1 is a Shambles (2020) research.
"""
import hashlib
import struct
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DER = os.path.join(SCRIPT_DIR, "..", "poc-01-md5-cert", "alipay-original-cert.der")
CERT_PEM = os.path.join(SCRIPT_DIR, "..", "alipay-original-cert.pem")


def parse_asn1_tlv(data, offset=0):
    """Minimal ASN.1 TLV parser (Tag-Length-Value)."""
    if offset >= len(data):
        return None
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        num_bytes = length & 0x7F
        length = int.from_bytes(data[offset:offset + num_bytes], 'big')
        offset += num_bytes
    return {"tag": tag, "header_end": offset, "length": length,
            "value_start": offset, "value_end": offset + length}


def analyze_cert_structure(cert_der):
    """Analyze X.509 certificate DER structure for collision injection points."""
    print("━━━ Certificate DER Structure Analysis ━━━")
    print(f"  Total size: {len(cert_der)} bytes")

    # Outer SEQUENCE
    outer = parse_asn1_tlv(cert_der, 0)
    print(f"  Outer SEQUENCE: offset 0, length {outer['length']}")

    # TBSCertificate (first element inside outer SEQUENCE)
    tbs = parse_asn1_tlv(cert_der, outer['value_start'])
    tbs_data = cert_der[outer['value_start']:tbs['value_end']]
    tbs_sha1 = hashlib.sha1(tbs_data).hexdigest()
    print(f"  TBSCertificate: offset {outer['value_start']}, length {tbs['length']}")
    print(f"  TBSCertificate SHA-1: {tbs_sha1}")

    # SignatureAlgorithm (after TBS)
    sig_alg = parse_asn1_tlv(cert_der, tbs['value_end'])
    print(f"  SignatureAlgorithm: offset {tbs['value_end']}, length {sig_alg['length']}")

    # Signature Value
    sig_val = parse_asn1_tlv(cert_der, sig_alg['value_end'])
    print(f"  SignatureValue: offset {sig_alg['value_end']}, length {sig_val['length']}")

    # Collision injection analysis
    print()
    print("━━━ Collision Injection Points ━━━")
    print("  SHAttered-style collision requires a chosen-prefix + collision blocks")
    print("  in the TBSCertificate before signing.")
    print()
    print("  Viable injection points in TBSCertificate:")
    print("  1. Subject CN extension field (variable-length string)")
    print("     → Inject collision block as part of CN value")
    print(f"     → TBS offset range: {outer['value_start']}-{tbs['value_end']}")
    print("  2. SubjectPublicKeyInfo (replace RSA modulus)")
    print("     → Both certificates would have different keys")
    print("     → Attacker controls one key's private key")
    print("  3. Certificate Extensions (if X.509 v3)")
    print("     → This cert is v1, no extensions available")
    print("     → Would need to upgrade to v3 format")
    print()

    return tbs_data, outer['value_start'], tbs['value_end']


def estimate_attack_cost():
    """Estimate SHA-1 collision attack cost across different years."""
    print("━━━ Attack Cost Estimation ━━━")
    print()

    estimates = [
        ("2017 SHAttered (identical-prefix)",
         "6,500 CPU-years + 110 GPU-years",
         "$110,000 (GCP)",
         "Proven (Google/CWI)"),
        ("2020 Shambles (chosen-prefix)",
         "2^63.4 SHA-1 calls",
         "$45,000 (GCP)",
         "Proven (Leurent & Peyrin)"),
        ("2023 Optimized chosen-prefix",
         "~2^61.2 SHA-1 calls",
         "$11,000 (estimated, GPU price drops)",
         "Theoretical (extrapolated)"),
        ("2026 Current estimate",
         "~2^60 SHA-1 calls",
         "$5,000-$8,000 (H100 GPU pricing)",
         "Projected (Moore's law + GPU advances)"),
    ]

    for name, compute, cost, status in estimates:
        print(f"  [{name}]")
        print(f"    Compute: {compute}")
        print(f"    Cost: {cost}")
        print(f"    Status: {status}")
        print()

    print("  ⚠️  Certificate collision is a CHOSEN-PREFIX attack:")
    print("     Attacker needs two TBSCertificate values that produce")
    print("     the same SHA-1 hash when signed by the CA.")
    print("     This is more expensive than identical-prefix collision,")
    print("     but still feasible at ~$5K-$45K depending on optimization.")
    print()


def generate_collision_candidates(tbs_data, cert_der):
    """Generate demonstration collision candidate structures."""
    print("━━━ Collision Candidate Generation (Demonstration) ━━━")
    print()

    # Create candidate A: original TBS + collision placeholder
    collision_block_a = b'\x41' * 128  # Placeholder block A
    collision_block_b = b'\x42' * 128  # Placeholder block B

    # Find a suitable injection point (after the serial number)
    # In a real attack, these 128 bytes would be computed by the collision finder
    candidate_a = tbs_data[:64] + collision_block_a + tbs_data[64:]
    candidate_b = tbs_data[:64] + collision_block_b + tbs_data[64:]

    sha1_a = hashlib.sha1(candidate_a).hexdigest()
    sha1_b = hashlib.sha1(candidate_b).hexdigest()

    out_dir = SCRIPT_DIR
    path_a = os.path.join(out_dir, "cert-candidate-A.der")
    path_b = os.path.join(out_dir, "cert-candidate-B.der")

    with open(path_a, 'wb') as f:
        f.write(candidate_a)
    with open(path_b, 'wb') as f:
        f.write(candidate_b)

    print("  Generated collision candidate TBS structures:")
    print(f"  Candidate A: {path_a}")
    print(f"    Size: {len(candidate_a)} bytes")
    print(f"    SHA-1: {sha1_a}")
    print(f"  Candidate B: {path_b}")
    print(f"    Size: {len(candidate_b)} bytes")
    print(f"    SHA-1: {sha1_b}")
    print()
    print("  ⚠️  These are DEMONSTRATION candidates with placeholder blocks.")
    print("     In a real attack, the 128-byte collision blocks would be")
    print("     computed using the SHA-1 chosen-prefix collision algorithm")
    print("     (Leurent & Peyrin, 2020) to make SHA-1(A) == SHA-1(B).")
    print()
    print("  Attack flow:")
    print("    1. Attacker obtains legitimate cert from CA (or self-signs)")
    print("    2. Constructs two TBS structures with collision blocks")
    print("    3. Runs chosen-prefix collision finder (~$5K-$45K compute)")
    print("    4. Gets CA to sign candidate A (legitimate-looking)")
    print("    5. Uses the signature on candidate B (malicious)")
    print("    6. Both certificates have identical SHA-1 fingerprints")
    print()


def alipay_specific_analysis(cert_der):
    """Analyze Alipay-specific attack implications."""
    sha1_fp = hashlib.sha1(cert_der).hexdigest()
    sha256_fp = hashlib.sha256(cert_der).hexdigest()

    print("━━━ Alipay-Specific Impact Analysis ━━━")
    print()
    print(f"  Certificate SHA-1 fingerprint:  {sha1_fp}")
    print(f"  Certificate SHA-256 fingerprint: {sha256_fp}")
    print()
    print("  Vulnerability chain:")
    print("  1. Alipay APK uses v1 signing (md5WithRSAEncryption)")
    print("  2. Android PackageManager verifies cert SHA-1 fingerprints")
    print("     for app update authorization (same signer check)")
    print("  3. A forged cert with same SHA-1 fingerprint could:")
    print("     a. Sign a malicious APK update")
    print("     b. Pass Android's same-signer verification")
    print("     c. Replace the legitimate app on user devices")
    print()
    print("  Mitigations already in place:")
    print("  ✅ APK Signature Scheme v2/v3 uses SHA-256 (not vulnerable)")
    print("  ✅ Google Play enforces v2+ for new uploads")
    print("  ✅ Android 7.0+ prefers v2 signature over v1")
    print()
    print("  Remaining risk:")
    print("  ⚠️  Sideloaded APKs with only v1 signature")
    print("  ⚠️  Android <7.0 devices only check v1")
    print("  ⚠️  SHA-1 fingerprint still used in some cert pinning configs")
    print("  ⚠️  Enterprise MDM systems may rely on SHA-1 fingerprint matching")
    print()


def main():
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║  SHA-1 Certificate Collision Analysis — Alipay APK Cert     ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print()

    if not os.path.exists(CERT_DER):
        print(f"Error: Certificate not found at {CERT_DER}")
        sys.exit(1)

    with open(CERT_DER, 'rb') as f:
        cert_der = f.read()

    print(f"Loaded certificate: {len(cert_der)} bytes")
    print()

    tbs_data, tbs_start, tbs_end = analyze_cert_structure(cert_der)
    print()
    estimate_attack_cost()
    generate_collision_candidates(tbs_data, cert_der)
    alipay_specific_analysis(cert_der)

    print("━━━ Conclusion ━━━")
    print("  SHA-1 certificate collision against Alipay's signing cert")
    print("  is technically feasible at $5K-$45K compute cost.")
    print("  The primary defense is migration to APK Signature Scheme v2/v3")
    print("  which uses SHA-256. Legacy v1-only installations remain at risk.")
    print()


if __name__ == "__main__":
    main()
