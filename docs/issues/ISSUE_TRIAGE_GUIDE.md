# Issue Triage Guide

## Labels

- `bug`: confirmed or suspected defect.
- `documentation`: docs correction or clarification.
- `public-beta`: Public Beta feedback.
- `safety`: safety wording, redaction, secret handling, or authorised-use concern.
- `regression`: behaviour that previously worked.
- `needs-reproduction`: more detail needed.

## Triage Flow

1. Confirm the issue contains no secrets, tokens, cookies, passwords, private keys, or private customer data.
2. Reproduce with Safe Local Testing where possible.
3. Classify as blocking, high, normal, or documentation-only.
4. Link affected commands, dashboard pages, tests, or docs.
5. Add the smallest actionable next step.

## Blocking Criteria

- Secret exposure.
- Misleading safety or release claims.
- Broken Public Beta verification command.
- Dashboard build failure.
- Backend regression affecting core demo, evidence, reporting, API, or OWASP workflows.
