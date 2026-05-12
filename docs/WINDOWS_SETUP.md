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

Use VulScan only for authorised defensive assessment. Do not use it for exploitation, brute force, credential attacks, payload attacks, destructive checks, stealth scanning, or firewall bypassing.
