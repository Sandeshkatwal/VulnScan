# Safety

VulScan is for authorised defensive vulnerability assessment only. Use it only on systems, networks, and web applications you own or have explicit written permission to assess.

For public screenshots and portfolio demos, use demo mode and follow [SCREENSHOT_CHECKLIST.md](SCREENSHOT_CHECKLIST.md).

## Safe Defaults

- The API binds to `127.0.0.1` by default.
- Remote API binding requires an explicit CLI flag and should not be used for public deployment.
- Credentialed Linux and Windows scans are CLI-only unless specifically enabled in a future reviewed workflow.
- The dashboard does not collect credentials and does not include password, token, private key, exploit, brute-force, or active attack controls.
- Web DAST is passive: it uses bounded GET requests, scope controls, robots/sitemap awareness, and polite rate limiting. It does not submit forms, authenticate, fuzz, send payloads, test SQL injection, test XSS, or prove exploitability.
- Vulnerability intelligence uses local files only. It does not download exploit code or execute exploit checks.
- Report access endpoints serve only `.json` and `.html` files from the local `reports` directory and block path traversal.
- Bug Intelligence release commands prefer Program Scope enforcement with `--scope-file` and `--enforce-scope`. Legacy `--bug-bounty-scope` remains an alias only.
- Preferred API routes remain local and protected when `VULSCAN_API_KEY` is configured. Legacy `/bug-bounty/...` routes are compatibility aliases.
- Remediation features update local tracking records only. They do not patch systems, restart services, run commands, or modify targets.

## Secrets

Do not commit:

- `.env` files
- API keys
- Passwords
- Tokens
- Private keys
- Real client data
- Local databases or generated reports containing sensitive data

Store local API keys in environment variables or untracked `.env` files only.

## Deployment Limitations

Do not expose the dashboard or API publicly without a separate security review, authentication design, transport security, logging review, secret handling review, and deployment hardening. The current dashboard is local development and portfolio tooling.
