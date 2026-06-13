# Verification Matrix

## Version 22.2 Performance Review

| Area | Command/Test | Expected Result | Status | Notes |
| --- | --- | --- | --- | --- |
| Pagination | `.\.venv311\Scripts\python.exe -m pytest tests\test_pagination.py` | Page model tests pass | Pending | Large Dataset Handling |
| Large Dataset Handling | `.\.venv311\Scripts\python.exe -m pytest tests\regression\test_large_dataset_regressions.py` | Regression tests pass | Pending | Simulated data only |
| Performance Baseline | `.\.venv311\Scripts\python.exe scripts\performance_baseline.py` | Baseline JSON is written | Pending | Local timing |
| Large Dataset Check | `.\.venv311\Scripts\python.exe scripts\check_large_dataset_performance.py` | Check JSON is written | Pending | Response Size Control |
| Dashboard Rendering Optimisation | `npm run build` | Dashboard build passes | Pending | Run from `dashboard` |

| Area | Command/Test | Expected Result | Status | Notes |
| --- | --- | --- | --- | --- |
| Backend tests | `.\.venv311\Scripts\python.exe -m pytest` | Tests pass locally | Pending | Regression Testing |
| Dashboard build | `npm run build` | TypeScript and Vite build pass | Pending | Run from `dashboard` |
| Demo safety | `.\.venv311\Scripts\python.exe scripts\check_demo_safety.py` | Simulated redacted demo data only | Pending | Safe Local Testing |
| Secret safety | `.\.venv311\Scripts\python.exe scripts\check_no_secrets.py` | No unredacted secret-like values | Pending | Verification |
| Version command | `.\.venv311\Scripts\python.exe -m scanner.main version` | 22.1.0-beta metadata prints | Pending | Version Metadata |
| Health command | `.\.venv311\Scripts\python.exe -m scanner.main health` | Health summary prints | Pending | Public Beta |
| Demo commands | `.\.venv311\Scripts\python.exe -m scanner.main demo status` | Demo status prints | Pending | Safe Demo Dataset |
| Evidence commands | `.\.venv311\Scripts\python.exe -m scanner.main evidence redact-check --text "Authorization: Bearer secret-demo-token"` | Redaction check does not print raw secret | Pending | Redaction Quality Controls |
| Report composer | `.\.venv311\Scripts\python.exe -m scanner.main reports compose --title "VulScan OWASP Assessment Report" --target http://127.0.0.1:8000 --findings-file data\findings\sample_finding.json --markdown --html --json` | Local report artifacts generated | Pending | Safe sample file |
| OWASP report | `web-scan` localhost command | OWASP report artifacts generated | Pending | Localhost only |
| API startup | `.\.venv311\Scripts\python.exe -m scanner.main api` | API starts on localhost | Pending | Stop manually after verification |
| Dashboard startup | `npm run dev` | Dashboard starts locally | Pending | Run from `dashboard` |
| GitHub Actions | workflow files | Practical checks are configured | Pending | Public Beta checks |
| Regression suite | `.\.venv311\Scripts\python.exe -m pytest tests\regression` | Regression checks pass | Pending | Version 22.1 |
| Sample data | `.\.venv311\Scripts\python.exe scripts\verify_sample_data.py` | Required sample files exist and JSON parses | Pending | Sample reliability |
| Report exports | `.\.venv311\Scripts\python.exe scripts\check_report_exports.py` | Safe sample report export is allowed | Pending | Export safety |
