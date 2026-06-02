# Bug Intelligence Workflow

VulScan supports a local authorised Bug Intelligence Engine for responsible disclosure, bug bounty programme compatibility, and internal security testing.

Use only on systems you own or have explicit permission to test.

## Workflow

1. Define Program Scope
   - Store local scope files in `data/programs/`.
   - Legacy `data/bug_bounty/` files are still read for compatibility.

2. Run Scope-Aware Recon
   - Import known targets from `data/recon/sample_targets.txt` or manual input.
   - Use `--scope-file` and `--enforce-scope` to skip out-of-scope assets.

3. Analyse Endpoints and Parameters
   - Use Endpoint Intelligence and Parameter Intelligence on supplied URLs or paths.
   - Scope enforcement is supported before candidate generation.

4. Map OWASP Indicators
   - OWASP Indicator Mapping maps findings and candidates to OWASP Top 10 categories.
   - Mapping is an indicator only, not proof of exploitability.

5. Run Safe Validation
   - Safe Validation performs limited, non-destructive checks.
   - It does not generate exploit payloads, run SQL injection exploitation, create XSS payloads, test SSRF, bypass auth, or attack credentials.

6. Capture Evidence
   - Evidence Capture keeps report-safe summaries and redacts credential-like values.
   - Full response bodies, cookies, platform tokens, and secrets are not stored.

7. Generate Security Finding Report
   - Security Finding Reports organise evidence, impact, reproduction notes, and remediation guidance for manual review.

8. Track Submission
   - Submission and Retest Tracker stores local status, duplicate/accepted outcomes, follow-up dates, and payment notes.
   - VulScan never submits reports to external platforms.

9. Track Retest
   - Retest records track manual verification status and evidence references.

10. Review Performance Metrics
   - Performance Metrics summarise local progress, quality, duplicates, acceptance rate, retest outcomes, Program Performance, vulnerability classes, and monthly activity.

## Compatibility

Legacy command flags, route paths, JSON keys, and folder names containing `bug-bounty` or `bug_bounty` are retained where needed. Prefer the professional commands and paths documented in [COMMAND_REFERENCE.md](COMMAND_REFERENCE.md).
