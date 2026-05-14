# VulScan Usage

VulScan is for authorised defensive vulnerability assessment only.

## TCP Port Scan

From the project root in PowerShell, activate the virtual environment first:

```powershell
.\.venv311\Scripts\Activate.ps1
```

Then run:

```powershell
python -m scanner.main scan --target 127.0.0.1
```

Or use the included helper script:

```powershell
.\run_scan.ps1
```

The Version 11 scanner performs TCP connect checks against a fixed default list of common ports and identifies likely services from a safe static port mapping:

```text
21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443
```

Only open ports are shown by default. Each open result includes the host, resolved IP address, TCP port, protocol, service, status, confidence, evidence, and a defensive recommendation. For example, an open `445/tcp` result is identified as `smb`.

## Findings

VulScan reports include a standard top-level `findings` section. Findings include sequential IDs, severity, category, affected host/port/URL, service, evidence, confidence, impact, recommendation, verification, limitation, source, risk score, risk label, fix priority, and creation time.

Open ports remain in `open_ports` for asset inventory. Open services also create informational service exposure findings.

## Risk Scoring

Risk scores are heuristic and range from 0 to 100. They combine severity, confidence, finding source, and exposure context such as sensitive ports or clear-text services.

Risk scores help with triage, but they are not a final statement of business risk. A human reviewer should validate context, asset criticality, exposure, compensating controls, and operational impact before prioritising remediation.

## Scan History

Use `--save-db` to store scan results in the local SQLite database at `data\vulscan.db`:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
```

View previous scans for a target:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1
```

Limit the number of history rows shown:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1 --limit 5
```

The history command shows the database path, target, number of scans shown, scan summaries, and latest-scan severity and risk-label counts. If the database does not exist, required tables are missing, or a target has no saved scans, VulScan prints a friendly message.

The database is local to your workstation and should not be committed to Git. It supports future scan diffing, remediation tracking, and trend reporting.

## Scan Diffing

Version 10.2 can compare the latest two saved scans for the same target using the local SQLite database.

Save at least two scans:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
```

Then compare them:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main diff --target 127.0.0.1
```

The diff command shows the database path, previous and latest scan times, finding totals, total risk score trend, and counts for new, fixed, unchanged, and changed-risk findings. It uses stable finding fingerprints based on title, affected host, affected port, affected URL, service, category, and source.

If the database does not exist, a target has no saved scans, only one saved scan exists, or no findings are available to compare, VulScan prints a friendly message.

## Remediation Status Tracking

Version 10.3 adds remediation status tracking for saved findings. When a scan is saved with `--save-db`, VulScan creates remediation records for new findings with status `Open` and updates `last_seen` for existing findings. Existing status, owner, and note values are preserved. If a finding marked `Fixed` appears again, VulScan reopens it as `Open`.

Save scan results first:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
```

List remediation records for a target:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main remediation list --target 127.0.0.1
```

Show remediation status counts:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main remediation summary --target 127.0.0.1
```

Update a finding by full or unique short fingerprint:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main remediation update --fingerprint ABC123 --status "In Progress" --owner "Sandesh" --note "Reviewing exposure"
```

Allowed remediation status values are `Open`, `In Progress`, `Fixed`, `Accepted Risk`, and `False Positive`.

## Asset Inventory

Version 10.4 tracks discovered assets and services in the local SQLite database at `data\vulscan.db`. Asset records are created or updated only when a scan is saved with `--save-db`.

Save a scan first:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
```

List all saved assets:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main assets
```

Show one target with detected services:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main assets --target 127.0.0.1
```

Asset inventory tracks target, resolved IP, first seen, last seen, scan count, latest open-port count, latest finding count, highest risk label, exposure summary, and detected services. It supports future dashboard views, exposure management, trend reporting, and asset criticality workflows.

## Exports

Version 10.5 exports saved SQLite data to CSV or JSON files in the `exports` folder. Exports are generated from local data in `data\vulscan.db`; run scans with `--save-db` first. The `exports` folder is ignored by Git.

CSV exports are useful for Excel and spreadsheet review. JSON exports are useful for APIs, dashboards, and automation.

Export assets:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main export assets --format csv
.\.venv311\Scripts\python.exe -m scanner.main export assets --format json
```

Export scan history for one target, or omit `--target` to export all history:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main export history --target 127.0.0.1 --format csv
.\.venv311\Scripts\python.exe -m scanner.main export history --target 127.0.0.1 --format json
```

Export findings:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main export findings --target 127.0.0.1 --format csv
.\.venv311\Scripts\python.exe -m scanner.main export findings --format json
```

Export remediation records:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main export remediation --target 127.0.0.1 --format csv
.\.venv311\Scripts\python.exe -m scanner.main export remediation --format json
```

## HTTP Security Header Audit

HTTP auditing is optional and runs only when `--http-audit` is provided. It only targets detected web services on `80`, `443`, `8080`, and `8443`, and sends a normal HTTP GET request to `/`.

```powershell
python -m scanner.main scan --target example.com --http-audit
```

To include HTTP findings in both JSON and HTML reports:

```powershell
python -m scanner.main scan --target example.com --http-audit --json --html
```

The HTTP audit checks for common missing security headers, basic information disclosure headers, and basic cookie flags when `Set-Cookie` is present.

## TLS Certificate Audit

TLS auditing is optional and runs only when `--tls-audit` is provided. It only targets detected HTTPS services on `443` and `8443`, and performs a normal TLS handshake to inspect certificate information.

```powershell
python -m scanner.main scan --target example.com --tls-audit
```

To include TLS findings in both JSON and HTML reports:

```powershell
python -m scanner.main scan --target example.com --tls-audit --json --html
```

The TLS audit checks certificate validation status, hostname mismatch where possible, certificate expiry, certificates expiring within 30 days, subject, issuer, and validity dates. It does not test weak ciphers, perform downgrade testing, or run aggressive TLS probing.

## Authenticated SSH Audit

Version 11.5 includes optional authenticated SSH auditing for authorised Linux systems only. It runs only when `--ssh-audit` is provided and requires a username plus either a password or a private key. VulScan does not prompt interactively for passwords.

Use least-privilege read-only credentials:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-password PASSWORD
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-key C:\Users\Sande\.ssh\id_rsa
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-key C:\Users\Sande\.ssh\id_rsa --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile basic
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile standard
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile detailed --json --html --save-db
```

Use `--ssh-port` if SSH is listening on a non-standard port. The default is `22`.

Use `--audit-profile` to choose the depth of read-only credentialed checks. Profiles apply only when `--ssh-audit` is used:

- `basic`: SSH login verification, OS information, hostname, kernel summary, and SSH hardening review.
- `standard`: default profile; includes `basic` plus package manager detection, package update checks, firewall indicators, and logging indicators.
- `detailed`: includes `standard` plus password policy indicators, temporary directory sticky-bit checks, and cleartext service exposure indicators.

All profiles are read-only. The `detailed` profile runs more checks and may take slightly longer.

The SSH audit attempts one login using the credentials explicitly provided for that scan. Passwords, key values, and private key paths are not stored in reports, the SQLite database, logs, or terminal output. SSH audit results are stored as sanitized audit status, command results, a top-level `ssh_audit_summary`, and standard findings.

When `--ssh-audit` is used, the terminal output includes a **Credentialed SSH Audit Summary** before the general findings. JSON and HTML reports include a top-level SSH audit summary with authentication status, username, auth method, audit profile, enabled/skipped checks, OS family, hostname, kernel summary, package indicators, SSH hardening status, Linux configuration status, total SSH findings, highest SSH risk, and limitations. SSH findings are grouped by source in terminal output, including `ssh_audit`, `package_audit`, `ssh_hardening`, and `linux_config_audit`.

Version 11.6 adds structured SSH audit error handling. If authentication fails, the SSH target times out, a key file is missing, or an individual read-only command cannot complete, VulScan returns safe status fields such as `success`, `failed`, `skipped`, or `partial` with a short error code and message. Partial command failures do not crash the scan; VulScan continues other read-only checks where safe. Technical details are sanitized and credentials are not stored or printed.

Version 11.7 improves credentialed audit evidence quality. VulScan stores concise evidence summaries for SSH findings instead of full raw SSH command output by default. Evidence is designed for reporting and remediation, includes safe observed/expected values where useful, limits package samples, and redacts values that look like passwords, tokens, private keys, authorization headers, or secrets. Credentialed audit evidence should still be reviewed in operational context.

After login, VulScan runs read-only Linux inspection commands only: `uname -a`, `cat /etc/os-release`, `sshd -T` when available, firewall status checks when available, package-manager discovery, package update checks, and Linux configuration indicator checks. It does not run `sudo`, change files, install packages, update packages, restart services, fuzz, crawl, exploit, brute force, guess passwords, or attempt privilege escalation.

Package manager detection checks `apt`, `apt-get`, `dnf`, `yum`, `pacman`, and `zypper` with `command -v`. VulScan derives the Linux family from `/etc/os-release` and reports Debian/Kali/Parrot/Ubuntu, Fedora/RHEL/Rocky/Alma, Arch, openSUSE/SUSE, or Unknown Linux.

Package update checks are read-only:

```text
apt list --upgradable
dnf check-update
yum check-update
pacman -Qu
zypper list-updates
```

For apt-based systems, VulScan does not run `apt update`; `apt list --upgradable` depends on the package metadata already available on the host. Package findings support patch management review by reporting detected package manager details, update counts, and a sample of up to 20 package names. This does not replace full vulnerability intelligence, CVE enrichment, vendor advisories, asset criticality, or change-management review.

Linux configuration audit templates are also read-only. VulScan reviews available firewall indicators, audit/logging service status, local password policy indicators from `/etc/login.defs` and `/etc/security/pwquality.conf`, sticky-bit indicators for `/tmp` and `/var/tmp`, cleartext service exposure indicators from existing service detection, and basic hostname/OS information.

These checks are indicators and should be reviewed in operational context. They may not reflect all PAM settings, central identity provider policy, central logging agents, cloud firewall controls, or enterprise hardening exceptions. This is not a full CIS benchmark implementation yet, but it prepares the framework for CIS-style audit templates.

SSH audit can reduce false positives by checking system configuration directly. Unsupported or non-Linux systems are handled safely by stopping Linux-specific checks when Linux OS details are not available. Windows SMB/WinRM auditing is planned for a future version.

## Windows Example

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

To save both JSON and HTML reports:

```powershell
python -m scanner.main scan --target 127.0.0.1 --json --html
```

Equivalent explicit virtual environment commands:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --json --html
.\.venv311\Scripts\python.exe -m scanner.main scan --target example.com --http-audit --tls-audit --json --html
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-key C:\Users\Sande\.ssh\id_rsa --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main assets
.\.venv311\Scripts\python.exe -m scanner.main assets --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1 --limit 5
.\.venv311\Scripts\python.exe -m scanner.main diff --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main remediation list --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main remediation summary --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main remediation update --fingerprint ABC123 --status "In Progress" --owner "Sandesh" --note "Reviewing exposure"
.\.venv311\Scripts\python.exe -m scanner.main export assets --format csv
.\.venv311\Scripts\python.exe -m scanner.main export history --target 127.0.0.1 --format json
.\.venv311\Scripts\python.exe -m scanner.main export findings --target 127.0.0.1 --format csv
.\.venv311\Scripts\python.exe -m scanner.main export remediation --format json
```

To run HTTP auditing and save reports:

```powershell
python -m scanner.main scan --target example.com --http-audit --json --html
```

To run TLS auditing and save reports:

```powershell
python -m scanner.main scan --target example.com --tls-audit --json --html
```

Example output includes a table with:

```text
Port  Protocol  Service  Status  Evidence  Recommendation
```

When `--json` is used, VulScan also prints the saved report path:

```text
JSON report saved: reports\127.0.0.1_2026-05-12_231500.json
```

When `--html` is used, VulScan also prints the saved report path:

```text
HTML report saved: reports\127.0.0.1_2026-05-13_231500.html
```

## Installing Dependencies

After activating `.venv311`, install the project requirements from PowerShell:

```powershell
python -m pip install -r requirements.txt
```

## Running Tests

Run tests from the project root with:

```powershell
.\.venv311\Scripts\python.exe -m pytest
```

SSH audit tests use fake fixtures in `tests\fixtures` and mocked command output. They do not require internet access, a live SSH server, or real credentials. Runtime SSH testing still requires authorised Linux credentials. Test fixtures must not contain real passwords, private keys, tokens, host secrets, or personal data.

## Safety Boundaries

Do not use VulScan against systems you do not own or do not have explicit permission to test. VulScan does not perform SYN scanning, UDP scanning, stealth scanning, crawling, fuzzing, brute forcing, credential attacks, password guessing, exploitation, payload attacks, firewall bypassing, cipher probing, protocol downgrade testing, privilege escalation, or destructive actions.
