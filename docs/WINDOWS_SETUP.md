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

To export saved local data:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main export assets --format csv
.\.venv311\Scripts\python.exe -m scanner.main export history --target 127.0.0.1 --format json
.\.venv311\Scripts\python.exe -m scanner.main export findings --target 127.0.0.1 --format csv
.\.venv311\Scripts\python.exe -m scanner.main export remediation --format json
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

The database is stored at `data\vulscan.db`. It is local scan history and should not be committed to Git. Asset records are created only when `--save-db` is used. Exports are generated from this local SQLite data and saved under `exports`, which is ignored by Git. CSV is useful for Excel, and JSON is useful for APIs, dashboards, and automation. The history command also shows latest-scan severity, risk-label, and remediation summaries, and it validates that the required SQLite tables exist. The diff command uses the latest two saved scans to show new, fixed, unchanged, and changed-risk findings. Remediation tracking stores status, owner, note, first seen, and last seen for saved findings. Asset inventory tracks discovered hosts, open services, and exposure summaries for future dashboard and exposure management features.

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
.\.venv311\Scripts\python.exe -m scanner.main export assets --format csv
.\.venv311\Scripts\python.exe -m scanner.main export history --target 127.0.0.1 --format json
.\.venv311\Scripts\python.exe -m scanner.main export findings --target 127.0.0.1 --format csv
.\.venv311\Scripts\python.exe -m scanner.main export remediation --format json
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

To run the optional authenticated SSH audit against an authorised Linux system:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-password PASSWORD
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-key PATH_TO_PRIVATE_KEY
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-key PATH_TO_PRIVATE_KEY --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile basic
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile standard
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile detailed --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile basic --ssh-timeout 8 --ssh-command-timeout 10
```

SSH audit is for authorised Linux systems only. Use least-privilege credentials. VulScan attempts one SSH login, runs read-only inspection commands only, and does not run `sudo`, modify files, install packages, update packages, restart services, exploit, brute force, guess passwords, or attempt privilege escalation. SSH passwords, key values, and private key paths are not stored in reports, the SQLite database, logs, or terminal output. The SSH audit summary appears in terminal, JSON, and HTML output, and SSH findings are grouped by source. Windows SMB/WinRM auditing currently provides safe reachability checks, optional WinRM authentication validation, optional basic host information collection, and optional Firewall/Defender status collection only.

Credentialed audit profiles apply only with `--ssh-audit`. `standard` is the default. `basic` performs fast login, OS, and SSH hardening checks. `standard` adds package, firewall, and logging indicators. `detailed` adds password policy, temporary directory sticky-bit, and cleartext service exposure indicators. All profiles are read-only; `detailed` may take slightly longer.

SSH audit timeout controls are available for slow authorised targets. `--ssh-timeout` controls the SSH connection timeout and defaults to `8` seconds. `--ssh-command-timeout` controls each read-only command and defaults to `10` seconds. `--ssh-audit-timeout` controls the overall post-login audit budget and defaults by profile: `basic` `30`, `standard` `60`, and `detailed` `90` seconds. Invalid timeout values are rejected before the SSH audit starts.

SSH audit error handling is structured. Authentication failures, connection timeouts, missing key files, unsupported targets, command timeouts, and audit budget exhaustion are reported with safe status and error-code fields such as `failed`, `partial`, `SSH_AUTH_FAILED`, `SSH_COMMAND_TIMEOUT`, or `SSH_AUDIT_TIME_BUDGET_EXCEEDED`. Partial command failures do not crash the scan, skipped checks are counted, and credentials are not printed or stored.

Package checks over SSH are read-only. VulScan detects package managers with `command -v` for `apt`, `apt-get`, `dnf`, `yum`, `pacman`, and `zypper`, then runs the appropriate read-only update check such as `apt list --upgradable`, `dnf check-update`, `yum check-update`, `pacman -Qu`, or `zypper list-updates`. It does not run `apt update`, upgrade packages, or install anything. On apt-based systems, results may depend on existing package metadata on the host. Package findings support patch management review but do not replace full vulnerability intelligence or vendor advisory review.

Linux configuration audit checks over SSH are read-only and require authorised SSH credentials. VulScan reviews firewall indicators, logging service indicators, local password policy indicators, temporary directory sticky-bit indicators, cleartext service exposure indicators, and basic hostname/OS information. Results are indicators that need operational review. This is not a full CIS benchmark implementation yet, but it prepares the framework for CIS-style templates.

Version 12.6 includes Windows SMB/WinRM audit foundation checks, optional safe WinRM authentication validation, optional read-only Windows host information collection, optional read-only Firewall/Defender status collection, optional read-only local security policy indicators, and optional narrow registry audit templates:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --windows-audit
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method none
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-user USER --windows-password PASSWORD --windows-domain WORKGROUP --windows-auth-method smb --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-domain WORKGROUP --windows-user USER --windows-password PASSWORD --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-domain WORKGROUP --windows-user USER --windows-password PASSWORD --windows-host-info --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-domain WORKGROUP --windows-user USER --windows-password PASSWORD --windows-security-status --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-domain WORKGROUP --windows-user USER --windows-password PASSWORD --windows-policy-status --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-domain WORKGROUP --windows-user USER --windows-password PASSWORD --windows-registry-audit --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-domain WORKGROUP --windows-user USER --windows-password PASSWORD --windows-registry-audit --windows-registry-template templates\windows_registry\basic_security_indicators.json
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-domain WORKGROUP --windows-user USER --windows-password PASSWORD --windows-host-info --windows-security-status --windows-patch-status --windows-policy-status --windows-registry-audit --json --html --save-db
```

The Windows foundation checks use safe TCP socket reachability only for SMB, NetBIOS/SMB, WinRM HTTP, WinRM HTTPS, and RDP. With `--windows-auth-method winrm`, VulScan requires an explicitly provided username and password, selects HTTPS 5986 when reachable before HTTP 5985, uses `pywinrm` if installed, and performs one harmless command such as `hostname` to validate authentication. If `pywinrm` is missing, VulScan reports a friendly dependency-missing result instead of crashing.

With `--windows-host-info`, VulScan runs safe read-only PowerShell commands only after successful WinRM authentication. It collects hostname, current identity, PowerShell version, OS caption/version/build/architecture/boot/install dates, computer system domain/workgroup/manufacturer/model, and timezone.

With `--windows-security-status`, VulScan runs safe read-only PowerShell commands only after successful WinRM authentication. It collects Firewall profile status, WinDefend service status, and Defender computer status when available. It does not modify Firewall or Defender settings, start or stop services, enable or disable firewall rules, enumerate individual firewall rules, query registry, or query local security policy. Defender disabled may be expected if approved third-party EDR/AV is used.

With `--windows-policy-status`, VulScan runs only `net accounts` after successful WinRM authentication. It collects local password and lockout policy indicators and does not modify password policy, lockout policy, accounts, groups, registry, or security policy. It does not run `secedit /export`, `gpresult`, registry queries, local user enumeration, or local group enumeration. Domain Group Policy or identity provider controls may override local indicators, so results should be reviewed in organisational context.

With `--windows-registry-audit`, VulScan loads a JSON template and reads only exact `HKLM` registry paths and values listed in that template. It does not query broad registry trees, recurse through registry keys, export registry hives, write registry values, or run registry modification commands. Missing values may be normal on some Windows versions and should be interpreted in organisational context.

Version 12.6 does not run deep Windows enumeration, broad registry queries, registry hive exports, security policy exports, patch enumeration, user enumeration, group enumeration, share enumeration, process listing, file listing, credential dumping, browser data collection, hash collection, token collection, private key collection, privilege checks, exploitation, brute forcing, system modification, or service restarts. Passwords are not stored or printed. WinRM should be enabled only where required and restricted to trusted networks.

The pytest suite uses fake SSH audit fixtures, mocked socket reachability, and mocked WinRM behavior. Tests do not require internet access, a live SSH server, a live WinRM server, or real credentials. Runtime SSH testing still requires authorised Linux credentials.

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

Use VulScan only for authorised defensive assessment. Do not use it for exploitation, brute force, credential attacks, password guessing, payload attacks, destructive checks, stealth scanning, crawling, fuzzing, firewall bypassing, cipher probing, privilege escalation, or protocol downgrade testing.
