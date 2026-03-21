# Responsible Disclosure Timeline

This document records the coordinated disclosure process for the vulnerabilities described in this repository.

## Timeline

| Date | Event |
|------|-------|
| 2026-02-16 | Initial vulnerability analysis began |
| 2026-03-01 | Full attack chain verification completed (15 PoCs) |
| 2026-02-25 | First vulnerability report submitted to Ant Group (4 rounds through 2026-03-07) |
| 2026-03-10 | Vendor response received: findings classified as "normal functionality"; no remediation planned |
| 2026-03-16 | IACR ePrint preprint submitted (2026/526) |
| 2026-03-22 | Public release of research repository with redacted sensitive data |

## Disclosure Policy

This research follows the **90-day coordinated disclosure** standard established by Google Project Zero and widely adopted by the security research community. Key principles:

1. **Vendor notification first**: All findings were reported to the vendor before any public disclosure.
2. **Reasonable remediation window**: The vendor was given the opportunity to investigate and respond.
3. **Proportional disclosure**: Sensitive data (private keys, server addresses, production credentials) has been redacted from the public release. Only the cryptographic analysis methodology and abstract findings are published.
4. **Academic context**: This research is published as an IACR ePrint paper for peer review and academic discourse.

## Scope of Redaction

The following categories of data have been redacted from the public repository:

- Real server IP addresses (replaced with `[REDACTED_SERVER_XX]`)
- RSA private key factors (p, q, d) from Batch GCD results
- Production symmetric encryption keys
- Local filesystem paths

The redacted data is available to qualified peer reviewers upon request, subject to responsible handling agreements.

## Contact

For questions about this research or to request access to redacted data for peer review:

- Jiqiang Feng — feng@innora.ai
- Innora AI Security Research Lab — https://innora.ai
