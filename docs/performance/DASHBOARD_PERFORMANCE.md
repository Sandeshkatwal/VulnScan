# Dashboard Performance

Version 22.2 dashboard work focuses on Dashboard Rendering Optimisation for large local datasets.

## Patterns

- Load summary cards first.
- Use paginated tables for large records.
- Use Lazy Loading for heavy sections.
- Avoid raw JSON rendering by default.
- Keep detail views separate from list views.
- Use API page size controls for large local datasets.

## Components

- `PaginatedTable`
- `TablePaginationControls`
- `TableToolbar`
- `LazySection`
- `PerformanceNotice`
- `LargeDatasetSummary`
- `ApiPageSizeSelector`
- `PerformanceDiagnosticsPanel`

## Safe Data Handling

Dashboard performance changes must not display raw secrets, tokens, cookies, passwords, API keys, or private keys. Evidence and finding details remain behind explicit detail views and existing redaction controls.
