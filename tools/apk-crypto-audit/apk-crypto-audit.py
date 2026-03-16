#!/usr/bin/env python3
"""
apk-crypto-audit.py — APK Cryptographic Security Audit Tool

Analyzes APK files for cryptographic weaknesses including:
- Certificate signature algorithm (MD5/SHA-1 = insecure)
- RSA key length
- APK signing scheme version (v1/v2/v3)
- Certificate validity period
- Key reuse across multiple APKs
- Self-signed certificate detection

Dependencies: Python 3 stdlib + openssl (CLI, optional but recommended)
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"OK": 0, "INFO": 1, "WARNING": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
SEVERITY_NAMES = list(SEVERITY_ORDER.keys())

# ANSI color codes
COLORS = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH":     "\033[31m",   # red
    "MEDIUM":   "\033[93m",   # yellow
    "WARNING":  "\033[33m",   # dark yellow
    "INFO":     "\033[36m",   # cyan
    "OK":       "\033[32m",   # green
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
}


def colorize(text: str, color_key: str, use_color: bool = True) -> str:
    if not use_color:
        return text
    code = COLORS.get(color_key, "")
    return f"{code}{text}{COLORS['RESET']}"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    check: str
    severity: str        # OK / INFO / WARNING / MEDIUM / HIGH / CRITICAL
    title: str
    detail: str
    recommendation: str = ""

    def as_dict(self):
        return asdict(self)


@dataclass
class ApkReport:
    apk_path: str
    findings: list = field(default_factory=list)
    cert_modulus: Optional[str] = None   # used for cross-APK key-reuse detection
    error: Optional[str] = None

    def as_dict(self):
        d = {
            "apk_path": self.apk_path,
            "findings": [f.as_dict() for f in self.findings],
        }
        if self.error:
            d["error"] = self.error
        return d

    def max_severity(self) -> str:
        if not self.findings:
            return "OK"
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER.get(s, 0))


# ---------------------------------------------------------------------------
# OpenSSL helpers
# ---------------------------------------------------------------------------

def openssl_available() -> bool:
    try:
        r = subprocess.run(["openssl", "version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def openssl_parse_cert(der_bytes: bytes) -> Optional[dict]:
    """Parse a DER certificate using openssl x509.  Returns a dict of fields."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout",
             "-text", "-subject", "-issuer", "-dates", "-modulus"],
            input=der_bytes,
            capture_output=True,
            timeout=15,
        )
        if result.returncode != 0:
            return None
        text = result.stdout.decode("utf-8", errors="replace")
        return _parse_openssl_text(text)
    except Exception:
        return None


def _parse_openssl_text(text: str) -> dict:
    info = {}

    # Signature Algorithm
    sig_matches = re.findall(r"Signature Algorithm:\s*(\S+)", text)
    if sig_matches:
        info["signature_algorithm"] = sig_matches[0]

    # Public Key size
    pk_match = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", text)
    if pk_match:
        info["key_bits"] = int(pk_match.group(1))

    # Key type
    pk_type_match = re.search(r"Public Key Algorithm:\s*(\S+)", text)
    if pk_type_match:
        info["key_type"] = pk_type_match.group(1)

    # Subject / Issuer (single-line versions printed by -subject -issuer flags)
    subj_match = re.search(r"^subject=(.+)$", text, re.MULTILINE)
    if subj_match:
        info["subject"] = subj_match.group(1).strip()

    issuer_match = re.search(r"^issuer=(.+)$", text, re.MULTILINE)
    if issuer_match:
        info["issuer"] = issuer_match.group(1).strip()

    # Validity dates
    not_before = re.search(r"notBefore=(.+)", text)
    not_after  = re.search(r"notAfter=(.+)", text)
    if not_before:
        info["not_before"] = not_before.group(1).strip()
    if not_after:
        info["not_after"] = not_after.group(1).strip()

    # Modulus (hex string without spaces/colons, for key-reuse detection)
    mod_match = re.search(r"Modulus=([0-9A-Fa-f]+)", text)
    if mod_match:
        info["modulus"] = mod_match.group(1).upper()

    return info


# ---------------------------------------------------------------------------
# APK parsing helpers
# ---------------------------------------------------------------------------

def extract_cert_der(apk_path: str) -> Optional[bytes]:
    """
    Extract the first signing certificate (DER) from META-INF/*.RSA / *.DSA / *.EC
    inside the APK zip.
    """
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                upper = name.upper()
                if upper.startswith("META-INF/") and any(
                    upper.endswith(ext) for ext in (".RSA", ".DSA", ".EC")
                ):
                    raw = zf.read(name)
                    # PKCS#7 / CMS SignedData: strip wrapper to get the cert DER.
                    # The certificate is embedded inside the PKCS7 blob.
                    der = _extract_cert_from_pkcs7(raw)
                    if der:
                        return der
    except (zipfile.BadZipFile, OSError):
        pass
    return None


def _extract_cert_from_pkcs7(pkcs7_der: bytes) -> Optional[bytes]:
    """
    Use openssl to extract the certificate from a PKCS#7 SignedData blob.
    Falls back to raw DER if it looks like a raw certificate already.
    """
    try:
        result = subprocess.run(
            ["openssl", "pkcs7", "-inform", "DER", "-print_certs", "-outform", "DER"],
            input=pkcs7_der,
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
    except Exception:
        pass
    # If openssl is unavailable, try returning the raw bytes (may work if it is
    # already a raw DER cert for simple cases).
    return pkcs7_der


# ---------------------------------------------------------------------------
# APK Signing Block detection (v2 / v3)
# ---------------------------------------------------------------------------

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
# Block ID for v2: 0x7109871a, v3: 0xf05368c0
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0


def detect_signing_schemes(apk_path: str) -> dict:
    """
    Detect which APK signing schemes are present.
    Returns dict: {v1: bool, v2: bool, v3: bool}
    """
    result = {"v1": False, "v2": False, "v3": False}

    # v1: presence of META-INF/*.SF file
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if name.upper().startswith("META-INF/") and name.upper().endswith(".SF"):
                    result["v1"] = True
                    break
    except (zipfile.BadZipFile, OSError):
        pass

    # v2 / v3: APK Signing Block before ZIP Central Directory
    try:
        with open(apk_path, "rb") as f:
            file_size = os.path.getsize(apk_path)
            # Read the ZIP End of Central Directory record (last 22+ bytes)
            eocd_offset = _find_eocd_offset(f, file_size)
            if eocd_offset is None:
                return result

            f.seek(eocd_offset + 16)
            (cd_offset,) = struct.unpack("<I", f.read(4))

            # Check for APK Signing Block immediately before the Central Directory
            if cd_offset < 32:
                return result

            f.seek(cd_offset - 16)
            magic = f.read(16)
            if magic != APK_SIG_BLOCK_MAGIC:
                return result

            # Read block size (8 bytes before magic)
            f.seek(cd_offset - 24)
            (block_size_footer,) = struct.unpack("<Q", f.read(8))

            block_start = cd_offset - block_size_footer - 8
            if block_start < 0:
                return result

            # Parse key-value pairs inside the block
            f.seek(block_start + 8)  # skip block_size_header
            block_end = cd_offset - 24  # before the size footer + magic
            while f.tell() < block_end:
                pos = f.tell()
                raw = f.read(8)
                if len(raw) < 8:
                    break
                (pair_size,) = struct.unpack("<Q", raw)
                if pair_size < 4 or pos + 8 + pair_size > block_end + 24:
                    break
                raw_id = f.read(4)
                if len(raw_id) < 4:
                    break
                (block_id,) = struct.unpack("<I", raw_id)
                if block_id == V2_BLOCK_ID:
                    result["v2"] = True
                elif block_id == V3_BLOCK_ID:
                    result["v3"] = True
                f.seek(pos + 8 + pair_size)

    except OSError:
        pass

    return result


def _find_eocd_offset(f, file_size: int) -> Optional[int]:
    """Find the offset of the ZIP End of Central Directory record."""
    # EOCD minimum size = 22 bytes; comment up to 65535 bytes
    max_search = min(file_size, 65535 + 22)
    f.seek(file_size - max_search)
    data = f.read(max_search)
    # Search backwards for EOCD signature
    sig = b"\x50\x4b\x05\x06"
    idx = data.rfind(sig)
    if idx == -1:
        return None
    return file_size - max_search + idx


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_signature_algorithm(cert_info: dict) -> Finding:
    algo = cert_info.get("signature_algorithm", "").lower()
    if not algo:
        return Finding(
            check="signature_algorithm",
            severity="INFO",
            title="Signature algorithm unknown",
            detail="Could not determine the certificate signature algorithm.",
        )
    if "md5" in algo:
        return Finding(
            check="signature_algorithm",
            severity="CRITICAL",
            title=f"MD5 signature algorithm: {cert_info['signature_algorithm']}",
            detail="MD5 is cryptographically broken. Collisions can be constructed in seconds.",
            recommendation="Re-sign the APK with SHA-256 or stronger algorithm.",
        )
    if "sha1" in algo:
        return Finding(
            check="signature_algorithm",
            severity="HIGH",
            title=f"SHA-1 signature algorithm: {cert_info['signature_algorithm']}",
            detail="SHA-1 is deprecated; practical collision attacks exist (SHAttered, 2017).",
            recommendation="Re-sign the APK with SHA-256 or stronger algorithm.",
        )
    return Finding(
        check="signature_algorithm",
        severity="OK",
        title=f"Signature algorithm acceptable: {cert_info['signature_algorithm']}",
        detail="Algorithm meets current security standards.",
    )


def check_key_length(cert_info: dict) -> Finding:
    key_type = cert_info.get("key_type", "").lower()
    key_bits = cert_info.get("key_bits")

    if key_bits is None and not key_type:
        return Finding(
            check="key_length",
            severity="INFO",
            title="Key length unknown",
            detail="Could not determine the public key size.",
        )

    # Ed25519 / EC: generally OK
    if "ec" in key_type or "ed25519" in key_type:
        return Finding(
            check="key_length",
            severity="OK",
            title=f"Key type: {cert_info.get('key_type', 'EC/Ed25519')}",
            detail="Elliptic-curve key — modern and secure.",
        )

    if key_bits is None:
        return Finding(
            check="key_length",
            severity="INFO",
            title="Key length unknown",
            detail=f"Key type reported as '{key_type}' but bit length unavailable.",
        )

    if key_bits < 2048:
        return Finding(
            check="key_length",
            severity="CRITICAL",
            title=f"RSA key too short: {key_bits} bits",
            detail=f"RSA-{key_bits} can be factored with modern hardware.",
            recommendation="Regenerate the signing key with at least RSA-2048 (RSA-4096 recommended).",
        )
    if key_bits < 4096:
        return Finding(
            check="key_length",
            severity="MEDIUM",
            title=f"RSA key length marginal: {key_bits} bits",
            detail="RSA-2048 is currently the minimum acceptable. RSA-4096 is recommended for long-term security.",
            recommendation="Consider regenerating the signing key with RSA-4096.",
        )
    return Finding(
        check="key_length",
        severity="OK",
        title=f"RSA key length adequate: {key_bits} bits",
        detail="Key size meets current best-practice recommendations.",
    )


def check_signing_scheme(schemes: dict) -> Finding:
    v1 = schemes.get("v1", False)
    v2 = schemes.get("v2", False)
    v3 = schemes.get("v3", False)
    label = " + ".join(
        f"v{n}" for n, present in [(1, v1), (2, v2), (3, v3)] if present
    ) or "none detected"

    if not v1 and not v2 and not v3:
        return Finding(
            check="signing_scheme",
            severity="INFO",
            title="No signing scheme detected",
            detail="Could not detect v1, v2, or v3 signing.",
        )
    if v1 and not v2 and not v3:
        return Finding(
            check="signing_scheme",
            severity="CRITICAL",
            title=f"APK signed with v1 only ({label})",
            detail="v1-only signing is vulnerable to Janus attack (CVE-2017-13156): "
                   "a DEX file can be prepended to the APK without invalidating the signature.",
            recommendation="Re-sign with v2 or v3 signing scheme.",
        )
    if v1 and v2 and not v3:
        return Finding(
            check="signing_scheme",
            severity="MEDIUM",
            title=f"APK signed with v1+v2 ({label})",
            detail="v1+v2 provides backward compatibility but v1 is still present. "
                   "On Android < 7.0, only v1 is verified.",
            recommendation="Add v3 signing scheme; disable v1 if Android < 7.0 support is not required.",
        )
    return Finding(
        check="signing_scheme",
        severity="OK",
        title=f"APK signing scheme: {label}",
        detail="v2 or v3 signing scheme is present.",
    )


def _parse_openssl_date(date_str: str) -> Optional[datetime]:
    """Parse openssl date strings like 'Jan  1 00:00:00 2020 GMT'."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def check_cert_validity(cert_info: dict) -> Finding:
    not_before_str = cert_info.get("not_before", "")
    not_after_str  = cert_info.get("not_after", "")

    if not not_before_str or not not_after_str:
        return Finding(
            check="cert_validity",
            severity="INFO",
            title="Certificate validity period unknown",
            detail="Could not parse certificate dates.",
        )

    not_before = _parse_openssl_date(not_before_str)
    not_after  = _parse_openssl_date(not_after_str)

    if not not_before or not not_after:
        return Finding(
            check="cert_validity",
            severity="INFO",
            title="Certificate validity period could not be parsed",
            detail=f"notBefore='{not_before_str}' notAfter='{not_after_str}'",
        )

    now = datetime.now(timezone.utc)

    if now < not_before:
        return Finding(
            check="cert_validity",
            severity="HIGH",
            title="Certificate not yet valid",
            detail=f"Certificate validity starts {not_before_str}.",
        )
    if now > not_after:
        return Finding(
            check="cert_validity",
            severity="HIGH",
            title="Certificate has expired",
            detail=f"Certificate expired on {not_after_str}.",
            recommendation="Renew the signing certificate.",
        )

    validity_years = (not_after - not_before).days / 365.25
    remaining_days = (not_after - now).days

    if validity_years > 30:
        return Finding(
            check="cert_validity",
            severity="HIGH",
            title=f"Certificate validity period excessively long: {validity_years:.1f} years",
            detail=f"Validity from {not_before_str} to {not_after_str}. "
                   "Extremely long-lived certificates increase exposure if the key is compromised.",
            recommendation="Use a shorter certificate validity period (e.g., 25 years for Play Store compatibility).",
        )
    if validity_years > 10:
        return Finding(
            check="cert_validity",
            severity="WARNING",
            title=f"Certificate validity period long: {validity_years:.1f} years",
            detail=f"Validity from {not_before_str} to {not_after_str}.",
        )

    return Finding(
        check="cert_validity",
        severity="OK",
        title=f"Certificate validity period: {validity_years:.1f} years ({remaining_days} days remaining)",
        detail=f"notBefore={not_before_str} notAfter={not_after_str}",
    )


def check_self_signed(cert_info: dict) -> Finding:
    subject = cert_info.get("subject", "")
    issuer  = cert_info.get("issuer", "")
    if not subject or not issuer:
        return Finding(
            check="self_signed",
            severity="INFO",
            title="Self-signed status unknown",
            detail="Could not determine subject/issuer.",
        )
    if subject.strip() == issuer.strip():
        return Finding(
            check="self_signed",
            severity="WARNING",
            title="Certificate is self-signed",
            detail=f"Subject and issuer are identical: {subject}",
            recommendation="Self-signed is normal for Android APK signing; ensure the private key is well protected.",
        )
    return Finding(
        check="self_signed",
        severity="OK",
        title="Certificate is CA-signed",
        detail=f"Issuer: {issuer}",
    )


# ---------------------------------------------------------------------------
# Key-reuse detection (cross-APK)
# ---------------------------------------------------------------------------

def check_key_reuse(reports: list) -> list:
    """
    Compare moduli across all reports. Returns additional Finding objects
    per affected APK, injected into their report.findings list.
    """
    modulus_map: dict = {}  # modulus -> list of apk_path
    for report in reports:
        if report.cert_modulus:
            modulus_map.setdefault(report.cert_modulus, []).append(report.apk_path)

    extra_findings = []
    for modulus, paths in modulus_map.items():
        if len(paths) > 1:
            short_mod = modulus[:16] + "..."
            for report in reports:
                if report.apk_path in paths:
                    finding = Finding(
                        check="key_reuse",
                        severity="HIGH",
                        title=f"Signing key reused across {len(paths)} APKs",
                        detail=f"Modulus prefix: {short_mod}\n"
                               f"Shared by: {', '.join(os.path.basename(p) for p in paths)}",
                        recommendation="Use distinct signing keys per app to limit blast radius of key compromise.",
                    )
                    report.findings.append(finding)
                    extra_findings.append(finding)
    return extra_findings


# ---------------------------------------------------------------------------
# Main audit function
# ---------------------------------------------------------------------------

def audit_apk(apk_path: str, has_openssl: bool) -> ApkReport:
    report = ApkReport(apk_path=apk_path)

    if not os.path.isfile(apk_path):
        report.error = f"File not found: {apk_path}"
        return report

    # --- Signing scheme (no openssl needed) ---
    schemes = detect_signing_schemes(apk_path)
    report.findings.append(check_signing_scheme(schemes))

    # --- Certificate-based checks ---
    if not has_openssl:
        report.findings.append(Finding(
            check="certificate",
            severity="INFO",
            title="openssl not available — certificate checks skipped",
            detail="Install openssl and re-run for full analysis.",
        ))
        return report

    cert_der = extract_cert_der(apk_path)
    if cert_der is None:
        report.findings.append(Finding(
            check="certificate",
            severity="INFO",
            title="No signing certificate found in META-INF/",
            detail="APK may use v2/v3 only (no META-INF/*.RSA/DSA). Certificate checks skipped.",
        ))
        return report

    cert_info = openssl_parse_cert(cert_der)
    if cert_info is None:
        report.findings.append(Finding(
            check="certificate",
            severity="INFO",
            title="Could not parse signing certificate",
            detail="openssl x509 parsing failed.",
        ))
        return report

    # Store modulus for key-reuse detection
    report.cert_modulus = cert_info.get("modulus")

    report.findings.append(check_signature_algorithm(cert_info))
    report.findings.append(check_key_length(cert_info))
    report.findings.append(check_cert_validity(cert_info))
    report.findings.append(check_self_signed(cert_info))

    return report


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def _severity_badge(severity: str, use_color: bool) -> str:
    width = 8
    padded = f"[{severity}]".ljust(width)
    return colorize(padded, severity, use_color)


def print_report(report: ApkReport, min_severity: str, use_color: bool) -> None:
    min_level = SEVERITY_ORDER.get(min_severity, 0)
    bold = COLORS["BOLD"] if use_color else ""
    reset = COLORS["RESET"] if use_color else ""
    dim = COLORS["DIM"] if use_color else ""

    print(f"\n{bold}{'=' * 60}{reset}")
    print(f"{bold}APK: {report.apk_path}{reset}")
    print(f"{'=' * 60}")

    if report.error:
        print(colorize(f"  ERROR: {report.error}", "CRITICAL", use_color))
        return

    visible = [f for f in report.findings if SEVERITY_ORDER.get(f.severity, 0) >= min_level]
    if not visible:
        print(f"{dim}  No findings at or above severity '{min_severity}'.{reset}")
        return

    for finding in visible:
        badge = _severity_badge(finding.severity, use_color)
        print(f"\n  {badge} {bold}{finding.title}{reset}")
        if finding.detail:
            for line in finding.detail.splitlines():
                print(f"           {dim}{line}{reset}")
        if finding.recommendation:
            rec_color = "WARNING"
            print(f"           {colorize('Recommendation:', rec_color, use_color)} "
                  f"{finding.recommendation}")

    overall = report.max_severity()
    print(f"\n  {bold}Overall:{reset} {_severity_badge(overall, use_color)}")


def print_summary(reports: list, use_color: bool) -> None:
    bold  = COLORS["BOLD"]  if use_color else ""
    reset = COLORS["RESET"] if use_color else ""
    print(f"\n{bold}{'=' * 60}{reset}")
    print(f"{bold}SUMMARY{reset}")
    print(f"{'=' * 60}")
    for report in reports:
        overall = report.max_severity()
        badge = _severity_badge(overall, use_color)
        name = os.path.basename(report.apk_path)
        print(f"  {badge} {name}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def collect_apks(path: str) -> list:
    p = Path(path)
    if p.is_file():
        return [str(p)]
    if p.is_dir():
        apks = sorted(p.glob("**/*.apk"))
        return [str(a) for a in apks]
    return []


def main():
    parser = argparse.ArgumentParser(
        prog="apk-crypto-audit",
        description="Audit APK files for cryptographic weaknesses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 apk-crypto-audit.py app.apk
  python3 apk-crypto-audit.py /path/to/apks/
  python3 apk-crypto-audit.py --json app.apk
  python3 apk-crypto-audit.py --severity HIGH app.apk
        """,
    )
    parser.add_argument("path", help="APK file or directory containing APK files")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument(
        "--severity",
        default="OK",
        choices=SEVERITY_NAMES,
        help="Minimum severity level to display (default: OK — show all)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output",
    )
    args = parser.parse_args()

    use_color = not args.no_color and sys.stdout.isatty()

    apk_paths = collect_apks(args.path)
    if not apk_paths:
        print(f"Error: no APK files found at '{args.path}'", file=sys.stderr)
        sys.exit(1)

    has_openssl = openssl_available()
    if not has_openssl and not args.json:
        print(
            colorize(
                "Warning: openssl not found in PATH. Certificate checks will be skipped.",
                "WARNING",
                use_color,
            )
        )

    reports = []
    for apk_path in apk_paths:
        report = audit_apk(apk_path, has_openssl)
        reports.append(report)

    # Cross-APK key-reuse check
    if len(reports) > 1:
        check_key_reuse(reports)

    if args.json:
        output = {
            "tool": "apk-crypto-audit",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "openssl_available": has_openssl,
            "reports": [r.as_dict() for r in reports],
        }
        print(json.dumps(output, indent=2))
    else:
        for report in reports:
            print_report(report, args.severity, use_color)
        if len(reports) > 1:
            print_summary(reports, use_color)

    # Exit code: 0 = all OK/INFO/WARNING, 1 = MEDIUM+, 2 = HIGH+, 3 = CRITICAL
    max_level = max(
        (SEVERITY_ORDER.get(r.max_severity(), 0) for r in reports), default=0
    )
    if max_level >= SEVERITY_ORDER["CRITICAL"]:
        sys.exit(3)
    if max_level >= SEVERITY_ORDER["HIGH"]:
        sys.exit(2)
    if max_level >= SEVERITY_ORDER["MEDIUM"]:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
