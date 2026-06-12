# Verification Matrix

| Area | Command/Test | Expected Result | Status | Notes |
| --- | --- | --- | --- | --- |
| Backend tests | `.\.venv311\Scripts\python.exe -m pytest` | Tests pass locally | Pending | Regression Testing |
| Dashboard build | `npm run build` | TypeScript and Vite build pass | Pending | Run from `dashboard` |
| Demo safety | `.\.venv311\Scripts\python.exe scripts\check_demo_safety.py` | Simulated redacted demo data only | Pending | Safe Local Testing |
| Secret safety | `.\.venv311\Scripts\python.exe scripts\check_no_secrets.py` | No unredacted secret-like values | Pending | Verification |
| Version command | `.\.venv311\Scripts\python.exe -m scanner.main version` | 22.0.0-beta metadata prints | Pending | Version Metadata |
| Health command | `.\.venv311\Scripts\python.exe -m scanner.main health` | Health summary prints | Pending | Public Beta |
| Demo commands | `.\.venv311\Scripts\python.exe -m scanner.main demo status` | Demo status prints | Pending | Safe Demo Dataset |
| Evidence commands | `.\.venv311\Scripts\python.exe -m scanner.main evidence redact-check --text "Authorization: Bearer secret-demo-token"` | Redaction check does not print raw secret | Pending | Redaction Quality Controls |
| Report composer | `.\.venv311\Scripts\python.exe -m scanner.main reports compose --title "VulScan OWASP Assessment Report" --target http://127.0.0.1:8000 --findings-file data\findings\sample_finding.json --markdown --html --json` | Local report artifacts generated | Pending | Safe sample file |
| OWASP report | `web-scan` localhost command | OWASP report artifacts generated | Pending | Localhost only |
| API startup | `.\.venv311\Scripts\python.exe -m scanner.main api` | API starts on localhost | Pending | Stop manually after verification |
| Dashboard startup | `npm run dev` | Dashboard starts locally | Pending | Run from `dashboard` |
| GitHub Actions | workflow files | Practical checks are configured | Pending | Public Beta checks |
