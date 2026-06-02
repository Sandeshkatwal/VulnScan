# Interview Talking Points

## 1. What problem does VulScan solve?

It turns local authorised assessment output into a vulnerability management workflow: discovery, evidence, prioritisation, reporting, remediation tracking, responsible disclosure workflow, and dashboard review.

## 2. Why did you build it?

To demonstrate practical security engineering beyond a simple scanner. The project shows backend design, API design, persistence, dashboard UX, safety controls, testing, and documentation.

## 3. How is it different from a simple port scanner?

It includes credentialed audit foundations, passive Web DAST, vulnerability intelligence, prioritisation, reports, remediation records, Bug Intelligence workflow, duplicate detection, and performance metrics.

## 4. How does the prioritisation engine work?

It combines finding severity, risk score, asset context, vulnerability intelligence, exploit metadata as a local signal, and trend context to produce fix-first guidance. It is a triage aid, not a replacement for human risk review.

## 5. What safety controls did you implement?

Local-first API binding, optional API key protection, scope enforcement, request rate limits, redaction, path traversal protections for reports, no exploit execution, no brute force, no credential attacks, and no platform token storage.

## 6. How does the Bug Intelligence workflow work?

The flow is Program Scope -> Recon Intelligence -> Endpoint Intelligence -> OWASP Indicator Mapping -> Safe Validation -> Evidence Capture -> Security Finding Reports -> Submission -> Retest -> Performance Metrics.

## 7. How do you prevent out-of-scope testing?

Program Scope files define in-scope and out-of-scope domains, URLs, API base URLs, and IP ranges. Recon, endpoint analysis, and Safe Validation support `--scope-file` and `--enforce-scope`.

## 8. How does evidence redaction work?

Evidence helpers redact common sensitive patterns such as passwords, tokens, cookies, authorisation headers, JWT-like values, private keys, and credential-like strings before storing report-safe summaries.

## 9. What are the limitations?

It is not a replacement for commercial scanners or Burp Suite, does not prove exploitability, relies on local/offline intelligence, requires manual validation, and is not hardened for enterprise multi-user deployment.

## 10. What would you improve next?

Add CI/CD, Docker/dev container support, PDF reports, stronger auth, SBOM input, plugin architecture, visual regression tests, and a secure deployment model.
