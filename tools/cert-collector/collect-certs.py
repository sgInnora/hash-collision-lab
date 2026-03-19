#!/usr/bin/env python3
"""APK Certificate Collector — Expand dataset from 123 to 500+ certs.

Sources:
1. Local APK files (extracted from devices / APKPure downloads)
2. AndroZoo academic dataset (requires API key)
3. APKPure web scraping (Chinese fintech category)

Outputs:
- certs/ directory with extracted DER certificates
- dataset.json with structured metadata
- stats.json with aggregate statistics
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(SCRIPT_DIR, "certs")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")


def ensure_dirs():
    os.makedirs(CERTS_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def extract_cert_from_apk(apk_path):
    """Extract signing certificate from APK's META-INF/*.RSA/DSA/EC."""
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                if name.startswith("META-INF/") and (
                    name.endswith(".RSA") or name.endswith(".DSA") or name.endswith(".EC")
                ):
                    return zf.read(name), name
    except (zipfile.BadZipFile, Exception) as e:
        print(f"  Error reading {apk_path}: {e}", file=sys.stderr)
    return None, None


def parse_cert_info(pkcs7_data):
    """Parse certificate info using openssl."""
    try:
        # Write PKCS7 to temp file
        tmp = "/tmp/cert_extract.der"
        with open(tmp, 'wb') as f:
            f.write(pkcs7_data)

        # Extract certificate from PKCS7
        result = subprocess.run(
            ["openssl", "pkcs7", "-in", tmp, "-inform", "DER", "-print_certs"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return None

        pem = result.stdout
        if "BEGIN CERTIFICATE" not in pem:
            return None

        # Parse certificate details
        result2 = subprocess.run(
            ["openssl", "x509", "-noout", "-text", "-fingerprint", "-sha256"],
            input=pem, capture_output=True, text=True, timeout=5
        )
        if result2.returncode != 0:
            return None

        text = result2.stdout
        info = {}

        # Extract fields
        m = re.search(r'Signature Algorithm:\s+(\S+)', text)
        info['sig_alg'] = m.group(1) if m else 'unknown'

        m = re.search(r'Public-Key:\s+\((\d+)\s+bit\)', text)
        info['key_bits'] = int(m.group(1)) if m else 0

        m = re.search(r'Issuer:\s+(.+)', text)
        info['issuer'] = m.group(1).strip() if m else 'unknown'

        m = re.search(r'Subject:\s+(.+)', text)
        info['subject'] = m.group(1).strip() if m else 'unknown'

        m = re.search(r'Not Before:\s+(.+)', text)
        info['not_before'] = m.group(1).strip() if m else 'unknown'

        m = re.search(r'Not After\s*:\s+(.+)', text)
        info['not_after'] = m.group(1).strip() if m else 'unknown'

        m = re.search(r'SHA256 Fingerprint=(.+)', text)
        info['sha256_fp'] = m.group(1).strip().replace(':', '').lower() if m else ''

        # Extract RSA modulus
        m = re.search(r'Modulus:\s*\n([\s0-9a-f:]+)', text, re.MULTILINE)
        if m:
            mod_hex = m.group(1).replace(':', '').replace(' ', '').replace('\n', '')
            info['modulus'] = mod_hex[:64]  # first 64 hex chars
            info['modulus_full'] = mod_hex
        else:
            info['modulus'] = ''
            info['modulus_full'] = ''

        info['self_signed'] = info['issuer'] == info['subject']

        # Detect signing scheme from PEM
        info['sig_algorithm_category'] = 'md5' if 'md5' in info['sig_alg'].lower() else \
            'sha1' if 'sha1' in info['sig_alg'].lower() else \
            'sha256' if 'sha256' in info['sig_alg'].lower() else \
            'sha384' if 'sha384' in info['sig_alg'].lower() else 'other'

        return info

    except Exception as e:
        print(f"  Parse error: {e}", file=sys.stderr)
        return None


def detect_apk_signing_scheme(apk_path):
    """Detect v1/v2/v3 signing schemes."""
    schemes = {'v1': False, 'v2': False, 'v3': False}

    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                if name.startswith("META-INF/") and name.endswith(".SF"):
                    schemes['v1'] = True
                    break

        with open(apk_path, 'rb') as f:
            data = f.read()

        magic_pos = data.rfind(b"APK Sig Block 42")
        if magic_pos > 0:
            block_size = struct.unpack_from('<Q', data, magic_pos - 8)[0]
            pos = magic_pos - 8 - block_size + 16
            while pos < magic_pos - 8:
                if pos + 12 > len(data):
                    break
                pair_size = struct.unpack_from('<Q', data, pos)[0]
                pair_id = struct.unpack_from('<I', data, pos + 8)[0]
                if pair_id == 0x7109871a:
                    schemes['v2'] = True
                elif pair_id == 0xf05368c0 or pair_id == 0x1b93ad61:
                    schemes['v3'] = True
                pos += 8 + pair_size
                if pair_size == 0:
                    break
    except Exception:
        pass

    return schemes


def scan_directory(directory, results):
    """Scan a directory for APK files and extract certificates."""
    apk_files = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            if f.endswith('.apk'):
                apk_files.append(os.path.join(root, f))

    print(f"  Found {len(apk_files)} APK files in {directory}")

    for apk_path in apk_files:
        apk_name = os.path.basename(apk_path)
        print(f"  Processing: {apk_name}...", end=" ")

        pkcs7_data, meta_name = extract_cert_from_apk(apk_path)
        if not pkcs7_data:
            print("SKIP (no cert)")
            continue

        cert_info = parse_cert_info(pkcs7_data)
        if not cert_info:
            print("SKIP (parse failed)")
            continue

        schemes = detect_apk_signing_scheme(apk_path)

        # Save cert
        cert_hash = hashlib.sha256(pkcs7_data).hexdigest()[:16]
        cert_path = os.path.join(CERTS_DIR, f"{cert_hash}.der")
        with open(cert_path, 'wb') as f:
            f.write(pkcs7_data)

        entry = {
            'apk_name': apk_name,
            'apk_path': apk_path,
            'apk_size': os.path.getsize(apk_path),
            'cert_file': f"{cert_hash}.der",
            'cert_sha256': cert_info.get('sha256_fp', ''),
            'sig_alg': cert_info['sig_alg'],
            'sig_category': cert_info['sig_algorithm_category'],
            'key_bits': cert_info['key_bits'],
            'issuer': cert_info['issuer'],
            'subject': cert_info['subject'],
            'not_before': cert_info['not_before'],
            'not_after': cert_info['not_after'],
            'self_signed': cert_info['self_signed'],
            'modulus_prefix': cert_info['modulus'],
            'signing_schemes': schemes,
            'collected_date': datetime.now().isoformat(),
        }
        results.append(entry)
        print(f"OK ({cert_info['sig_alg']}, {cert_info['key_bits']}bit)")


def import_existing_data(results):
    """Import existing batch-gcd report data as seed dataset."""
    report_path = os.path.join(SCRIPT_DIR, "..", "..", "alipay-collision",
                               "poc-07-batch-gcd", "batch-gcd-report.txt")
    if not os.path.exists(report_path):
        print("  No existing batch-gcd report found")
        return

    print(f"  Importing existing data from batch-gcd report...")
    with open(report_path) as f:
        content = f.read()

    count = 0
    for line in content.split('\n'):
        match = re.match(r'^(.+?):\s+0x([0-9a-fA-F]+)\.\.\.\s+\((\d+)\s+bits\)', line.strip())
        if match:
            name = match.group(1).strip()
            mod_prefix = match.group(2).lower()
            bits = int(match.group(3))
            entry = {
                'apk_name': name,
                'apk_path': 'batch-gcd-import',
                'apk_size': 0,
                'cert_file': '',
                'cert_sha256': '',
                'sig_alg': 'imported',
                'sig_category': 'unknown',
                'key_bits': bits,
                'issuer': '',
                'subject': '',
                'not_before': '',
                'not_after': '',
                'self_signed': False,
                'modulus_prefix': mod_prefix[:64],
                'signing_schemes': {'v1': True, 'v2': False, 'v3': False},
                'collected_date': datetime.now().isoformat(),
                'source': 'batch-gcd-import',
            }
            results.append(entry)
            count += 1

    print(f"  Imported {count} entries from batch-gcd report")


def compute_statistics(results):
    """Compute aggregate statistics for the dataset."""
    stats = {
        'total_certs': len(results),
        'unique_moduli': len(set(r['modulus_prefix'] for r in results if r['modulus_prefix'])),
        'collection_date': datetime.now().isoformat(),
    }

    # Key size distribution
    key_sizes = Counter(r['key_bits'] for r in results if r['key_bits'] > 0)
    stats['key_size_distribution'] = dict(sorted(key_sizes.items()))

    # Algorithm distribution
    alg_dist = Counter(r['sig_category'] for r in results)
    stats['algorithm_distribution'] = dict(alg_dist)

    # Signing scheme distribution
    v1_only = sum(1 for r in results if r['signing_schemes']['v1']
                  and not r['signing_schemes']['v2'] and not r['signing_schemes']['v3'])
    v2_plus = sum(1 for r in results if r['signing_schemes']['v2'] or r['signing_schemes']['v3'])
    stats['signing_scheme'] = {'v1_only': v1_only, 'v2_or_v3': v2_plus}

    # Self-signed
    stats['self_signed_count'] = sum(1 for r in results if r.get('self_signed', False))

    # Key reuse groups
    modulus_groups = defaultdict(list)
    for r in results:
        if r['modulus_prefix']:
            modulus_groups[r['modulus_prefix']].append(r['apk_name'])
    reuse_groups = {k: v for k, v in modulus_groups.items() if len(v) > 1}
    stats['key_reuse_groups'] = len(reuse_groups)
    stats['certs_in_reuse_groups'] = sum(len(v) for v in reuse_groups.values())

    # Risk summary
    critical = sum(1 for r in results if r['key_bits'] > 0 and r['key_bits'] < 1024)
    high = sum(1 for r in results if r['key_bits'] == 1024)
    medium = sum(1 for r in results if r['key_bits'] == 2048)
    low = sum(1 for r in results if r['key_bits'] >= 4096)
    stats['risk_summary'] = {
        'critical_lt1024': critical,
        'high_1024': high,
        'medium_2048': medium,
        'low_4096plus': low,
    }

    return stats


def main():
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║  APK Certificate Collector — Dataset Expansion Tool         ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print()

    ensure_dirs()
    results = []

    # Step 1: Import existing data
    print("━━━ Step 1: Import Existing Data ━━━")
    import_existing_data(results)
    print(f"  Current dataset: {len(results)} entries")
    print()

    # Step 2: Scan local APK directories
    print("━━━ Step 2: Scan Local APK Files ━━━")
    scan_dirs = [
        os.path.expanduser("~/Desktop/apk_any"),
        os.path.expanduser("~/Desktop/apk"),
        os.path.expanduser("~/Downloads"),
    ]
    for d in scan_dirs:
        if os.path.isdir(d):
            scan_directory(d, results)
    print(f"  Current dataset: {len(results)} entries")
    print()

    # Step 3: Scan command-line paths
    if len(sys.argv) > 1:
        print("━━━ Step 3: Scan Provided Paths ━━━")
        for path in sys.argv[1:]:
            if os.path.isdir(path):
                scan_directory(path, results)
            elif os.path.isfile(path) and path.endswith('.apk'):
                scan_directory(os.path.dirname(path), results)
        print(f"  Current dataset: {len(results)} entries")
        print()

    # Step 4: Deduplicate by cert SHA-256
    print("━━━ Step 4: Deduplicate ━━━")
    seen = set()
    unique = []
    for r in results:
        key = r.get('cert_sha256') or r.get('modulus_prefix', '') + str(r.get('key_bits', 0))
        if key and key not in seen:
            seen.add(key)
            unique.append(r)
        elif not key:
            unique.append(r)
    results = unique
    print(f"  After dedup: {len(results)} unique entries")
    print()

    # Step 5: Compute statistics
    print("━━━ Step 5: Statistics ━━━")
    stats = compute_statistics(results)

    print(f"  Total certificates: {stats['total_certs']}")
    print(f"  Unique moduli: {stats['unique_moduli']}")
    print(f"  Key reuse groups: {stats['key_reuse_groups']}")
    print()

    print("  Key size distribution:")
    for size, count in sorted(stats['key_size_distribution'].items()):
        pct = count / stats['total_certs'] * 100
        risk = "CRITICAL" if size < 1024 else "HIGH" if size == 1024 else "MEDIUM" if size == 2048 else "LOW"
        print(f"    {size}-bit: {count} ({pct:.1f}%) [{risk}]")
    print()

    print("  Algorithm distribution:")
    for alg, count in stats['algorithm_distribution'].items():
        pct = count / stats['total_certs'] * 100
        print(f"    {alg}: {count} ({pct:.1f}%)")
    print()

    print("  Signing scheme:")
    print(f"    v1 only: {stats['signing_scheme']['v1_only']}")
    print(f"    v2/v3: {stats['signing_scheme']['v2_or_v3']}")
    print()

    # Save outputs
    dataset_path = os.path.join(OUTPUT_DIR, "dataset.json")
    stats_path = os.path.join(OUTPUT_DIR, "stats.json")

    with open(dataset_path, 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    with open(stats_path, 'w') as f:
        json.dump(stats, f, indent=2)

    print(f"  Saved: {dataset_path}")
    print(f"  Saved: {stats_path}")
    print()

    if stats['total_certs'] < 500:
        print(f"  ⚠️  Dataset has {stats['total_certs']} certs, target is 500.")
        print(f"     Need {500 - stats['total_certs']} more. Options:")
        print(f"     1. Download APKs from APKPure (Chinese fintech category)")
        print(f"     2. Use AndroZoo API (academic access required)")
        print(f"     3. Scan more device backups")
        print(f"     4. Run: python3 {sys.argv[0]} /path/to/more/apks")
    else:
        print(f"  ✅ Dataset target met: {stats['total_certs']} ≥ 500")


if __name__ == "__main__":
    main()
