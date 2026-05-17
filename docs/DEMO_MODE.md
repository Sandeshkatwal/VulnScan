# VulScan Demo Mode

Windows demo mode is for portfolio screenshots, report testing, training, and UI validation only.

It does not perform a real scan. It does not open sockets, connect to WinRM, require credentials, or inspect a real host. All values are fake sample data and must not be used for real security decisions.

## Commands

Generate terminal-only demo output:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target demo-windows --windows-audit --windows-demo
```

Generate JSON and HTML demo reports:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target demo-windows --windows-audit --windows-demo --windows-audit-profile detailed --json --html
```

Save demo output to the local SQLite history database:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target demo-windows --windows-audit --windows-demo --json --html --save-db
```

Saved demo scans are sample records. Keep the target name clearly demo-oriented, such as `demo-windows`, so history, assets, exports, and screenshots cannot be mistaken for real assessment data.

## What Demo Mode Shows

Demo mode creates fake Windows audit data for:

- Windows service reachability indicators for SMB, WinRM, and RDP.
- Windows host information for a fake host named `WIN-DEMO-01`.
- Windows Firewall and Defender status indicators.
- Windows patch/update indicators.
- Local security policy indicators.
- Registry audit template indicators.
- Standard VulScan findings, risk scoring, JSON, HTML, and credentialed audit report sections.

Every demo result is marked with:

```text
demo_mode: true
demo_notice: Demo data only. No real target was scanned.
```

HTML reports also show a visible banner that says the report uses fake sample data.

## Safety

Demo mode must remain fake-data only. It must not:

- Connect to any host.
- Run TCP socket checks.
- Connect to WinRM.
- Require or store passwords.
- Query or modify a real Windows system.
- Be used for real security decisions.
