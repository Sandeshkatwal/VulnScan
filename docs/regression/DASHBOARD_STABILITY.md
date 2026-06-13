# Dashboard Stability

Dashboard Resilience in 22.1 focuses on graceful failure:

- API failures should show a clear notice and retry action.
- Unexpected render errors should fall back to a safe local state.
- Empty states should avoid unsafe wording and suggest demo mode where useful.
- Build and regression status should be visible without requiring live scans.
- Screenshot mode should remain clean and not expose raw JSON unnecessarily.
