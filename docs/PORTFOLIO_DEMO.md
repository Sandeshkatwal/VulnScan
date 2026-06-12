# Portfolio Demo Mode

Portfolio Demo Mode is a screenshot-friendly, interview-ready VulScan workflow that uses a Safe Demo Dataset only.

It is Local Demo Only:

- no real target is scanned
- no live requests are sent by demo mode
- no raw secrets, real cookies, bearer tokens, passwords, or customer data are included
- all findings are simulated and labelled as demo data
- candidate findings keep manual-validation-required wording

## Demo Dataset

The Safe Demo Dataset lives under `data/demo/` and includes:

- dashboard summary metrics
- OWASP A01-A10 coverage matrix
- simulated findings
- Redacted Demo Evidence records
- authenticated assessment summary
- role and permission matrix
- access-control manual test plan
- parameter replay plan
- business logic workflow plan
- report composer draft metadata

## CLI

```powershell
.\.venv311\Scripts\python.exe -m scanner.main demo status
.\.venv311\Scripts\python.exe -m scanner.main demo generate --json
.\.venv311\Scripts\python.exe -m scanner.main demo report --markdown --html --json
.\.venv311\Scripts\python.exe -m scanner.main demo walkthrough
```

## API

```http
GET /demo/status
GET /demo/dashboard
POST /demo/generate
POST /demo/report/build
GET /demo/report/latest
```

## Dashboard

Use the Portfolio Demo Mode section to load the Safe Demo Dataset, show the Feature Tour, and generate a Demo Report. The dashboard also has a Screenshot-Ready View toggle in Settings.

