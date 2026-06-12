# Screenshot Guide

## Run The Dashboard

```powershell
cd dashboard
npm run dev
```

Open `http://127.0.0.1:5173`.

## Enable Portfolio Demo Mode

Open the Portfolio Demo Mode section and load the Safe Demo Dataset. If the API is unavailable, the dashboard can use frontend fallback demo data.

## Enable Screenshot-Ready View

Open Settings and enable Screenshot-Ready View. This reduces noisy development context and keeps the interface clean for GitHub screenshots.

## Recommended Pages

- Dashboard Home: `docs/screenshots/dashboard-home.png`
- Portfolio Demo Mode: `docs/screenshots/demo-mode.png`
- OWASP Report: `docs/screenshots/owasp-report.png`
- Authenticated Assessment: `docs/screenshots/authenticated-assessment.png`
- Evidence Vault: `docs/screenshots/evidence-vault.png`
- Finding Builder: `docs/screenshots/finding-builder.png`
- Report Composer: `docs/screenshots/report-composer.png`
- Business Logic Review: `docs/screenshots/business-logic-review.png`

## Capture Tips

- Use demo data only.
- Crop browser chrome unless useful.
- Keep the Portfolio Demo Mode badge visible.
- Avoid raw JSON panels unless they are part of the story.
- Do not capture secrets, real cookies, bearer tokens, passwords, API keys, private keys, or customer data.

