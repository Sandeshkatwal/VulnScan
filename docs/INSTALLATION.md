# Installation

VulScan is developed for local authorised testing on Windows with PowerShell.

## Backend Requirements

- Windows 11
- Python 3.11
- PowerShell
- Git

## Backend Setup

From the project root:

```powershell
python -m venv .venv311
.\.venv311\Scripts\python.exe -m pip install --upgrade pip
.\.venv311\Scripts\python.exe -m pip install -r requirements.txt
```

## Run Tests

```powershell
.\.venv311\Scripts\python.exe -m pytest
```

## Run Scanner

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1
```

Generate reports:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --json --html
```

## Run API

```powershell
.\.venv311\Scripts\python.exe -m scanner.main api
```

The API binds to `127.0.0.1:8088` by default.

## Dashboard Requirements

- Node.js LTS
- npm

## Dashboard Setup

```powershell
cd dashboard
npm install
npm run dev
npm run build
```

Copy `dashboard/.env.example` to `dashboard/.env` for local dashboard settings. Do not commit `.env`.
