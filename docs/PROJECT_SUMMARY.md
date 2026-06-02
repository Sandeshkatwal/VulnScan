# Project Summary

## What It Is

VulScan is a local authorised security assessment, vulnerability management, and bug intelligence platform.

## Why It Matters

Security assessment work is more useful when findings are tracked through evidence, prioritisation, reporting, remediation, responsible disclosure, retesting, and metrics. VulScan demonstrates that full workflow locally and safely.

## Tech Stack

- Python 3.11
- Typer CLI
- FastAPI
- SQLite
- React
- Vite
- TypeScript
- Pytest

## Key Features

- Discovery Engine
- Credentialed Linux and Windows audit foundations
- Passive Web DAST
- Vulnerability Intelligence
- Prioritisation Engine
- JSON and HTML reporting
- Remediation tracking
- Local API
- React dashboard
- Bug Intelligence workflow
- Duplicate Detection
- Performance Metrics

## Safety Model

VulScan is built for authorised testing only. It is local-first, scope-aware, redacts sensitive evidence, avoids exploit execution, avoids brute force, avoids credential attacks, and does not submit to external platforms.

## What I Learned

- How to structure a Python security tool beyond a single scanner script.
- How to design a local API around scanner output and saved state.
- How to build a React dashboard for security workflows.
- How to model vulnerability management, remediation, and responsible disclosure workflows.
- How to document safety boundaries and limitations clearly.

## Future Improvements

- CI/CD and Docker/dev container support.
- PDF reports.
- Stronger authentication and deployment model.
- Plugin architecture.
- SBOM input and richer passive web checks.
- More dashboard tests and visual QA.
