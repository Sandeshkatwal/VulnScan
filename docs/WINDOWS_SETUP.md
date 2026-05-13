# Windows Setup

Use these commands from the project root:

```powershell
cd C:\Users\Sande\MyProject\VulScan
```

## Activate `.venv311`

```powershell
.\.venv311\Scripts\Activate.ps1
```

If PowerShell blocks activation, allow local user scripts and try again:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\.venv311\Scripts\Activate.ps1
```

## Install Requirements

```powershell
python -m pip install -r requirements.txt
```

## Run the Scanner

```powershell
python -m scanner.main scan --target 127.0.0.1
```

To save a JSON report in the `reports` folder:

```powershell
python -m scanner.main scan --target 127.0.0.1 --json
```

To save an HTML report in the `reports` folder:

```powershell
python -m scanner.main scan --target 127.0.0.1 --html
```

To save both report formats:

```powershell
python -m scanner.main scan --target 127.0.0.1 --json --html
```

To save scan history to the local SQLite database:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
```

To view previous scans for a target:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1
```

To view saved asset inventory:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main assets
.\.venv311\Scripts\python.exe -m scanner.main assets --target 127.0.0.1
```

To limit displayed history rows:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1 --limit 5
```

To compare the latest two saved scans for a target:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
.\.venv311\Scripts\python.exe -m scanner.main diff --target 127.0.0.1
```

To track remediation status for saved findings:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main remediation list --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main remediation summary --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main remediation update --fingerprint ABC123 --status "In Progress" --owner "Sandesh" --note "Reviewing exposure"
```

The database is stored at `data\vulscan.db`. It is local scan history and should not be committed to Git. Asset records are created only when `--save-db` is used. The history command also shows latest-scan severity, risk-label, and remediation summaries, and it validates that the required SQLite tables exist. The diff command uses the latest two saved scans to show new, fixed, unchanged, and changed-risk findings. Remediation tracking stores status, owner, note, first seen, and last seen for saved findings. Asset inventory tracks discovered hosts, open services, and exposure summaries for future dashboard and exposure management features.

You can also call the virtual environment Python directly:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --json --html
.\.venv311\Scripts\python.exe -m scanner.main scan --target example.com --http-audit --tls-audit --json --html
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main assets
.\.venv311\Scripts\python.exe -m scanner.main assets --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1 --limit 5
.\.venv311\Scripts\python.exe -m scanner.main diff --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main remediation list --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main remediation summary --target 127.0.0.1
```

To run the optional HTTP security header audit:

```powershell
python -m scanner.main scan --target example.com --http-audit
```

To run HTTP auditing and save both report formats:

```powershell
python -m scanner.main scan --target example.com --http-audit --json --html
```

To run the optional TLS certificate audit:

```powershell
python -m scanner.main scan --target example.com --tls-audit
```

To run TLS auditing and save both report formats:

```powershell
python -m scanner.main scan --target example.com --tls-audit --json --html
```

You can also run the included helper script:

```powershell
.\run_scan.ps1
```

## Run Tests Later

When tests are added, run:

```powershell
python -m pytest
```

## Safety

Use VulScan only for authorised defensive assessment. Do not use it for exploitation, brute force, credential attacks, payload attacks, destructive checks, stealth scanning, crawling, fuzzing, firewall bypassing, cipher probing, or protocol downgrade testing.
