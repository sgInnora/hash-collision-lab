# apk-crypto-audit

A command-line tool for auditing APK files for cryptographic weaknesses.

## Requirements

- Python 3.6+
- `openssl` in `PATH` (optional but required for certificate checks)

No third-party Python packages are needed.

## Usage

```
python3 apk-crypto-audit.py <apk_file>
python3 apk-crypto-audit.py <directory_of_apks>
python3 apk-crypto-audit.py --json <apk_file>
python3 apk-crypto-audit.py --severity HIGH <apk_file>
```

### Options

| Flag | Description |
|---|---|
| `--json` | Output results as structured JSON |
| `--severity LEVEL` | Show only findings at or above this level (OK / INFO / WARNING / MEDIUM / HIGH / CRITICAL) |
| `--no-color` | Disable ANSI color output |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All findings below MEDIUM (OK / INFO / WARNING) |
| `1` | At least one MEDIUM finding |
| `2` | At least one HIGH finding |
| `3` | At least one CRITICAL finding |

## Checks performed

### 1. APK Signing Scheme (v1 / v2 / v3)
Detects the APK Signing Block (`APK Sig Block 42` magic) to identify v2/v3 signatures.

| Condition | Severity |
|---|---|
| v1 only | CRITICAL — vulnerable to Janus attack (CVE-2017-13156) |
| v1 + v2 | MEDIUM |
| v2 or v3 present | OK |

### 2. Certificate Signature Algorithm
Extracted from `META-INF/*.RSA` / `*.DSA`.

| Algorithm | Severity |
|---|---|
| md5WithRSAEncryption | CRITICAL |
| sha1WithRSAEncryption | HIGH |
| sha256WithRSAEncryption or stronger | OK |

### 3. Key Length
| Condition | Severity |
|---|---|
| RSA < 2048 bits | CRITICAL |
| RSA 2048–4095 bits | MEDIUM |
| RSA >= 4096 bits or EC/Ed25519 | OK |

### 4. Certificate Validity Period
| Condition | Severity |
|---|---|
| Certificate expired or not yet valid | HIGH |
| Validity > 30 years | HIGH |
| Validity > 10 years | WARNING |

### 5. Self-Signed Detection
Self-signed certificates (issuer == subject) are flagged as WARNING.
This is normal for Android APK signing; it serves as a reminder to protect the private key.

### 6. Key Reuse (batch mode)
When auditing a directory of APKs, the RSA modulus is compared across all certificates.
Identical moduli mean the same key is used to sign multiple APKs.

| Condition | Severity |
|---|---|
| Same key used in 2+ APKs | HIGH |

## Example output

```
============================================================
APK: app-release.apk
============================================================

  [HIGH]   SHA-1 signature algorithm: sha1WithRSAEncryption
           SHA-1 is deprecated; practical collision attacks exist (SHAttered, 2017).
           Recommendation: Re-sign the APK with SHA-256 or stronger algorithm.

  [MEDIUM] RSA key length marginal: 2048 bits
           RSA-2048 is currently the minimum acceptable. RSA-4096 is recommended.
           Recommendation: Consider regenerating the signing key with RSA-4096.

  [WARNING] Certificate is self-signed
           Subject and issuer are identical: CN=Android Debug, O=Android, C=US

  [OK]     APK signing scheme: v1 + v2 + v3

  Overall: [HIGH]
```

## Background

This tool was created as part of the [hash-collision-lab](../../README.md) project to
demonstrate and audit real-world cryptographic weaknesses in Android application signing.

Related vulnerabilities:
- **Janus (CVE-2017-13156)** — v1-only APK signature bypass via DEX/ZIP polyglot
- **SHAttered** — first practical SHA-1 chosen-prefix collision (2017)
- **MD5 collisions** — trivially constructible since 2004
