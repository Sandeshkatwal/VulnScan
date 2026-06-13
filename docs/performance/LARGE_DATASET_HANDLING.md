# Large Dataset Handling

Version 22.2 adds a common pagination model for large local datasets.

## Pagination Model

`paginated_response` includes:

- `items`
- `total`
- `page`
- `page_size`
- `total_pages`
- `has_next`
- `has_previous`
- `next_page`
- `previous_page`
- `sort_by`
- `sort_direction`
- `filters_applied`

Defaults:

- `page = 1`
- `page_size = 25`
- `max_page_size = 100`

Invalid pagination input returns a structured safe error. Oversized `page_size` values are capped at the maximum.

## Summary Vs Detail

Large list endpoints should return compact summaries by default. Detail endpoints return one full safe record by ID.

Current summary-first endpoints include:

- `/evidence`
- `/reports/findings`
- `/demo/dashboard?large=true`

## Large Demo Dataset

Generate safe simulated records:

```powershell
.\.venv311\Scripts\python.exe scripts\generate_large_demo_dataset.py --findings 500 --evidence 1000 --reports 50
```

Outputs:

- `data/demo/large/demo_large_findings.json`
- `data/demo/large/demo_large_evidence.json`
- `data/demo/large/demo_large_reports.json`
- `data/demo/large/demo_large_summary.json`

All records are simulated and use `demo.local` only.
