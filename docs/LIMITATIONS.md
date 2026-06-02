# Limitations

VulScan is a local authorised security assessment and vulnerability management project. It is useful for workflow demonstration and controlled lab use, but it has important limits.

## Accuracy

- Findings can include false positives.
- Findings can miss real issues.
- Service banners and passive web indicators can be incomplete or misleading.
- OWASP mapping is indicator-only and does not prove exploitability.

## Intelligence Data

- Local CVE, EPSS, and exploit metadata may be stale.
- VulScan does not fetch live advisory feeds by default.
- Local exploit availability metadata is a prioritisation signal only. VulScan does not download or run exploits.

## Manual Validation

- Manual review is required before acting on findings.
- Safe Validation checks are intentionally limited.
- Security Finding Reports should be reviewed before sharing externally.

## Local-Only Model

- The API is designed for localhost development use.
- It is not hardened as a public internet service.
- Enterprise authentication, RBAC, audit logging, and multi-tenant controls are not implemented.

## Demo Data

- Demo mode uses fake data only.
- Demo screenshots should not be interpreted as real assessment results.

## External Platforms

- VulScan does not submit reports to external platforms.
- VulScan does not store external platform credentials, API keys, tokens, cookies, or session data.
- VulScan does not scrape external dashboards.

## Commercial Tooling

VulScan is not a replacement for Nessus, Qualys, Burp Suite, enterprise EDR, SIEM, or a full vulnerability management programme.
