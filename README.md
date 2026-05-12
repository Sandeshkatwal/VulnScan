# VulScan

VulScan is an intermediate-level defensive vulnerability scanner for authorised use.

Version 2 provides a Typer-based CLI with Rich terminal output and a defensive TCP connect scanner for a fixed list of common ports.

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

You can also use the helper script:

```powershell
.\run_scan.ps1
```

The scanner prints the VulScan version, target, resolved IP, scan mode, safe usage warning, open TCP ports, evidence, and total scan time.

## Tests

Tests can be run later from PowerShell with:

```powershell
python -m pytest
```

## Safety

Use VulScan only on systems you own or have explicit written permission to assess. This project must remain defensive and must not include exploitation, brute forcing, credential attacks, payload attacks, or destructive functionality.
