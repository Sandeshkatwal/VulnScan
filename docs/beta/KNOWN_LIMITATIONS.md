# Known Limitations

## Version 22.2 Performance Review

- Large Dataset Handling is optimised for local public beta usage and simulated Large Demo Dataset records.
- Pagination defaults to 25 records per page and caps page size at 100.
- Performance Baseline timings vary by local machine and filesystem state.
- Summary endpoints avoid full huge arrays by default; detailed records should be fetched separately by ID.

- VulScan is not a replacement for professional manual penetration testing.
- Many findings are indicators or candidates.
- Manual validation is required before treating findings as confirmed.
- Authenticated testing is boundary-controlled and not exploitative.
- No automatic auth bypass testing is performed.
- No brute force is performed.
- No destructive or state-changing workflow execution is performed.
- There is no guarantee of complete OWASP coverage.
- Demo mode uses simulated data only.
- PDF export may be future work if not implemented in the local environment.
- Some modules may depend on local sample data.
- External integrations are limited.
- Public Beta may contain bugs.
