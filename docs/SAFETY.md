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
# Authenticated Assessment Safety

Authenticated Web Assessment requires explicit authorisation. Do not store real credentials, raw session cookies, bearer tokens, API keys, HAR files, Burp exports, or cookie jars in the repository. VulScan 21.0 redacts auth material from UI, reports, API responses, and terminal output, and does not perform login automation, unauthorised authentication testing, or state-changing authenticated requests.

Authenticated Crawl in 21.1 is GET-only, does not submit forms, does not call logout endpoints, blocks destructive-looking links, and stores Redacted Authenticated Evidence only.
## Version 21.2 Role and Permission Mapping Safety

Role and Permission Mapping is for authorised access-control planning and documentation only. VulScan does not perform automatic role comparison, account-to-account requests, form submission, or state-changing access checks. Role Profiles use safe labels only and must not contain usernames, passwords, session cookies, bearer tokens, Authorization headers, or secret authentication material.
## Version 21.3 Access Control Manual Test Planner Safety

The Access Control Manual Test Planner creates local workflow and documentation records only. Use Authorised Test Accounts Only. Planner commands and API endpoints do not perform live access-control requests, form submission, state-changing actions, or account-to-account requests.
## Safe Authenticated Parameter Replay Planner

Replay Plans are manual templates only. VulScan does not replay requests, mutate parameters, submit forms, send payloads, perform automatic authorization testing, perform automatic privilege changes, or compare live accounts automatically.

Redacted Request Templates store names and schemas only: header names, cookie names, parameter names, path placeholders, form field names, and JSON body schema. Raw credentials, raw cookies, bearer tokens, passwords, CSRF values, nonce values, and session tokens must not be stored.
