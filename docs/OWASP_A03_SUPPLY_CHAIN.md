# OWASP A03 Software Supply Chain

Version 20.7 adds safe A03 Software Supply Chain Failures evidence for component exposure indicators, dependency metadata indicators, SBOM analysis, and local vulnerability-intelligence enrichment.

## Purpose

The A03 module helps identify software supply chain evidence that should be reviewed during an authorised assessment. It is metadata-based and report-oriented.

## Scope

Implemented checks include:

- JavaScript library hints from observed script URLs and limited HTML snippets.
- Component/version exposure from headers, generator meta tags, and asset URLs.
- Dependency metadata exposure from discovered or explicitly supplied URLs only.
- Local CycloneDX JSON and SPDX JSON SBOM import.
- Local CVE/CPE enrichment when local vulnerability-intelligence data is supplied.
- Source map, build artifact, and third-party script manual review indicators.

## What Is Not Checked

VulScan does not perform dependency confusion testing, malicious package testing, package takeover simulation, CI/CD attack simulation, package registry fetching, exploit validation, or exploit code download.

## SBOM Support

Supported input is local JSON:

- CycloneDX JSON components.
- SPDX JSON packages.

The parser normalises component name, version, type, PURL, CPE, license, supplier, hash presence, and external reference counts. Raw hashes are not stored.

## CLI Examples

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a03-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a03-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --vuln-intel --a03-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main sbom analyse --sbom-file data\sbom\sample_cyclonedx_sbom.json --a03-checks --owasp-assess --json --html
```

## API Examples

- `GET /owasp/a03/rules`
- `POST /owasp/a03/assess`
- `POST /sbom/analyse`

The API accepts metadata bodies only for SBOM analysis. It does not accept arbitrary server-side file paths for SBOM import.

## Dashboard Usage

The OWASP Assessment page includes an A03 Software Supply Chain section with summary cards, component evidence, dependency metadata, SBOM analysis, CVE/CPE enrichment, source map/build artifact indicators, third-party script review, recommendations, and limitations.

## Remediation Guidance

Maintain an SBOM, update vulnerable components after verifying component identity and version, avoid unintentionally exposing dependency metadata, review source map exposure in production, and use SRI/CSP where appropriate for third-party scripts.
