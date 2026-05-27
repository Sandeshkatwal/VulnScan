# VulScan Dashboard

Version 16.0 adds a local React + Vite dashboard foundation for the VulScan API. It is for local development only and should be used with the API bound to `127.0.0.1`.

## Start The API

From the project root:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main api
```

With API key protection:

```powershell
$env:VULSCAN_API_KEY="change-this-local-dev-key"
.\.venv311\Scripts\python.exe -m scanner.main api --require-api-key
```

The API runs at:

```text
http://127.0.0.1:8088
```

## Configure The Dashboard

Copy `dashboard/.env.example` to `dashboard/.env` for local settings. Do not commit `.env`.

```text
VITE_VULSCAN_API_URL=http://127.0.0.1:8088
VITE_VULSCAN_API_KEY=
```

If the backend is running with `--require-api-key`, set `VITE_VULSCAN_API_KEY` to the same local development key. The dashboard sends `X-VulScan-API-Key` only when that value exists.

## Start The Dashboard

```powershell
cd dashboard
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

## Build Check

```powershell
cd dashboard
npm run build
```

## Scope

The Version 16.0 dashboard shows API health, version metadata, recent jobs, recent scans, and a high-level findings/prioritisation summary from recent completed jobs. It does not add public deployment, exploitation, credential collection, credentialed scan forms, password fields, or stored secrets.
