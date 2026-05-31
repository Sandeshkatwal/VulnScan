# Security Finding Reporting

VulScan uses Security Finding Reports for authorised vulnerability discovery, evidence organisation, and responsible disclosure workflow support.

Reports may include scan findings, endpoint and parameter candidates, OWASP indicator mapping, Safe Validation indicators, remediation notes, and retest context. Candidate and indicator wording is intentional: endpoint, parameter, OWASP, and Safe Validation results do not confirm exploitability without authorised manual validation.

Submission and Retest Tracking stores local report status, evidence references, follow-up notes, accepted or duplicate outcomes, and retest results. It is tracking only: VulScan does not submit reports to external platforms and does not store platform credentials.

The legacy phrase "bug bounty report" may still appear in compatibility route names or historical file paths, but user-facing workflow language should use Security Finding Report, Evidence & Reports, and Submission and Retest Tracking.
## Duplicate Detection

Version 18.8 adds Finding Fingerprinting and Duplicate Detection for Security Finding Reports. Fingerprints are based on stable metadata such as host, normalised path, issue type, and parameter names. They do not include parameter values, secrets, full response bodies, report IDs, or timestamps.

Duplicate status is a local review indicator only. It can warn that a similar Security Finding Report or submission may already exist, but manual review is required before marking a report as duplicate.
