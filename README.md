# VulScan

VulScan is an intermediate-level defensive vulnerability scanner and auditing tool for authorised use.

Current capabilities include safe TCP connect scanning, service detection, JSON and HTML reports, HTTP security header checks, TLS certificate checks, SQLite history, scan diffing, remediation tracking, asset inventory, exports, and optional authenticated SSH auditing for authorised Linux systems with read-only audit profiles, package checks, and configuration checks.
Version 12.3 also includes Windows SMB/WinRM audit foundation checks, optional single-attempt WinRM authentication validation, opt-in read-only Windows host information collection, and opt-in Windows Firewall and Microsoft Defender status collection using explicitly provided credentials.

## Requirements

- Windows 11
- PowerShell
- Python 3.11
- Virtual environment: `.venv311`

Dependencies are listed in `requirements.txt`.

## Windows Setup

From the project root in PowerShell:

```powershell
.\.venv311\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, allow scripts for the current user and then activate again:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\.venv311\Scripts\Activate.ps1
```

## Usage

From the project root with `.venv311` activated:

```powershell
python -m scanner.main scan --target 127.0.0.1
```

Optional authenticated SSH audit for an authorised Linux system:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-password PASSWORD
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-key PATH_TO_PRIVATE_KEY
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile basic
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile detailed --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile basic --ssh-timeout 8 --ssh-command-timeout 10
```

SSH audit uses one explicitly provided login, runs read-only Linux inspection commands only, and does not store SSH passwords, key values, or private key paths. Package and configuration checks are read-only and do not install, update, or modify packages or files. Results are indicators for authorised review, not a full CIS benchmark implementation. Use least-privilege credentials. Windows WinRM authentication validation uses one explicitly provided username/password pair. Optional Windows collection runs only safe read-only commands for host information, Firewall profile status, WinDefend service status, and Defender computer status. VulScan does not store or print the Windows password.

Credentialed SSH audit output includes a sanitized summary in terminal, JSON, and HTML reports. Passwords, key values, and private key paths are never included. Audit profiles apply only with `--ssh-audit`: `basic` is fastest with a 30 second default audit budget, `standard` is the default with 60 seconds, and `detailed` runs additional read-only configuration indicators with 90 seconds.

SSH audit timeout options are `--ssh-timeout`, `--ssh-command-timeout`, and `--ssh-audit-timeout`. SSH audit error handling reports safe status and error-code fields for authentication failures, timeouts, missing key files, unsupported targets, partial command failures, and audit budget exhaustion. Partial results keep completed findings and count skipped checks. Tests use fake fixtures and mocked SSH behavior; they do not require a live SSH server or real credentials.

Credentialed audit findings store concise evidence summaries, not full raw SSH output by default. Evidence is designed for reporting and remediation, includes safe observed/expected values in JSON and HTML reports where useful, and redacts values that look like passwords, tokens, private keys, authorization headers, or secrets.

Credentialed audit results are normalised internally under `credentialed_audits` in JSON and HTML reports. Existing SSH summaries remain available, and existing commands are unchanged. The normalised model avoids storing passwords, private key contents, or private key paths and prepares VulScan for future Windows SMB/WinRM audit modules.

Windows audit foundation examples:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --windows-audit
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method none
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-user USER --windows-password PASSWORD --windows-domain WORKGROUP --windows-auth-method smb --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-user USER --windows-password PASSWORD
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-user USER --windows-password PASSWORD --windows-host-info
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-user USER --windows-password PASSWORD --windows-security-status
```

Version 12.3 Windows audit checks TCP reachability for SMB, NetBIOS/SMB, WinRM HTTP, WinRM HTTPS, and RDP. With `--windows-auth-method winrm`, it requires `--windows-user` and `--windows-password`, prefers HTTPS on 5986 over HTTP on 5985, uses `pywinrm` when installed, and performs one safe read-only validation command. With `--windows-host-info`, it collects basic host information only after successful WinRM authentication. With `--windows-security-status`, it collects read-only Firewall profile and Defender status. It does not change Firewall or Defender settings, enumerate firewall rules, query registry or security policy, enumerate users, groups, files, processes, shares, patches, secrets, browser data, hashes, tokens, or private keys, exploit, brute force, modify systems, or restart services. Defender disabled may be expected where approved third-party EDR/AV is used. Passwords are not stored or printed.

You can also use the helper script:

```powershell
.\run_scan.ps1
```

The scanner prints the VulScan version, target, resolved IP, scan mode, safe usage warning, open TCP ports, evidence, and total scan time.

## Tests

Run tests from PowerShell with:

```powershell
.\.venv311\Scripts\python.exe -m pytest
```

## Safety

Use VulScan only on systems you own or have explicit written permission to assess. This project must remain defensive and must not include exploitation, brute forcing, credential attacks, password guessing, payload attacks, package modification, privilege escalation, or destructive functionality.
