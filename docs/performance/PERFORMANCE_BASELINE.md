# Performance Baseline

The Performance Baseline script measures local operations only:

- Demo dataset load time.
- Large findings pagination time.
- Large evidence pagination time.
- Report compose time using sample findings.
- JSON export time.
- HTML export time.
- Basic memory estimate using local file sizes.

Run:

```powershell
.\.venv311\Scripts\python.exe scripts\performance_baseline.py
```

The script writes `reports/performance/performance_baseline.json` and prints a readable terminal summary.

## Known Limitations

- Memory Usage Review is an estimate based on local file sizes and Python object handling.
- Timings vary by machine, filesystem state, and dashboard build status.
- The baseline uses simulated data and does not contact the internet.
