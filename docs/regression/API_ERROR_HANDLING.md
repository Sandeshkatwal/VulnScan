# API Error Handling

API Error Handling in 22.1 keeps responses structured and safe:

- Invalid payloads return a controlled 422 response.
- Missing resources return 404 without tracebacks.
- Unsafe report paths are blocked.
- Generic failures return a safe error without internal details.
- Health, version, and diagnostics remain public and do not expose secrets.

API responses must not include raw tokens, cookies, passwords, API keys, private keys, or auth profile content.
