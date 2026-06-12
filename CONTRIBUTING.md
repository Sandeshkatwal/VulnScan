# Contributing

VulScan is an Authorised Security Assessment and Defensive Security project. Contributions must preserve safe local testing boundaries.

## Code Style

- Prefer clear Python and TypeScript with focused modules.
- Keep changes scoped and covered by tests.
- Use existing project patterns before adding new abstractions.

## Testing

Run:

```powershell
.\.venv311\Scripts\python.exe -m pytest
cd dashboard
npm run build
```

## Safety Requirements

- Do not add exploit payloads.
- Do not add attack automation.
- Do not add credential attacks.
- Do not commit secrets, cookies, bearer tokens, passwords, private keys, real customer data, HAR files, or real auth profiles.
- Demo data must be simulated, redacted, and clearly labelled.
- Findings should use candidate wording unless manual validation supports stronger wording.

## Pull Request Checklist

- Tests added or updated.
- Documentation updated.
- Demo data safety preserved.
- No secrets in commits.
- Safety and limitations remain clear.

