# Dashboard Guide

The VulScan dashboard is a local React + Vite + TypeScript interface for authorised vulnerability assessment workflows.

## Main Sections

- Dashboard Home: product headline, summary cards, platform modules, recommended workflow, and safe usage statement.
- Portfolio Demo Mode: loads the Safe Demo Dataset and Demo Report workflow.
- OWASP Report: shows OWASP-focused assessment context and category mapping.
- Authenticated Assessment: shows redacted auth context, role mapping, manual test planning, parameter replay planning, and business logic review.
- Evidence Vault: shows Redacted Evidence, Evidence Quality, timeline, and export safety status.
- Finding Builder: builds careful Technical Findings with candidate wording when required.
- Report Composer: composes Executive Summary, Technical Findings, Evidence Summary, OWASP Mapping, Retest Summary, and Safe Export outputs.
- Settings: API connection, local-only notices, Demo Mode, and Screenshot-Ready View.

## Empty, Loading, And Error States

Dashboard views now use reusable Empty State, Loading State, and Error State components. If the API is unavailable, Portfolio Demo Mode can still use frontend fallback demo data.

## Screenshot-Ready View

Screenshot-Ready View reduces noisy development context and keeps portfolio screenshots focused on report-ready sections and simulated demo data.

