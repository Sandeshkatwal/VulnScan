# Demo Guide

Demo mode is for screenshots, portfolio presentation, and UI review. Demo data is fake, and no real target is scanned in dashboard demo mode.

## Backend Demo

Run a local safe scan:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1
```

Generate JSON and HTML reports:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --json --html --save-db
```

Run the API:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main api
```

Create an API job:

```powershell
curl -X POST http://127.0.0.1:8088/scans -H "Content-Type: application/json" -d "{\"target\":\"127.0.0.1\",\"scan_mode\":\"safe\",\"json_report\":true,\"html_report\":true,\"save_db\":true,\"prioritise\":true,\"fix_first_dashboard\":true}"
```

## Dashboard Demo

Create `dashboard/.env` from `dashboard/.env.example`:

```text
VITE_VULSCAN_API_URL=http://127.0.0.1:8088
VITE_VULSCAN_API_KEY=
VITE_VULSCAN_DEMO_MODE=true
VITE_VULSCAN_PORTFOLIO_MODE=true
VITE_VULSCAN_SCREENSHOT_MODE=true
```

Start the dashboard:

```powershell
cd dashboard
npm run dev
```

Open `http://localhost:5173`.

## Notes

- Demo data is fake.
- No real target is scanned in dashboard demo mode.
- Demo mode is for screenshots and portfolio presentation.
- Do not mix real client data into demo screenshots.
- Do not show secrets, API keys, passwords, tokens, or private local paths.
