# Interview FAQ

## Why did you build VulScan?

To demonstrate a portfolio-grade Authorised Security Assessment platform that connects discovery, OWASP-focused Assessment, Evidence Vault workflows, and Professional Reporting.

## What makes it safe?

It focuses on passive checks, planning workflows, redacted evidence, export safety checks, Portfolio Demo Mode, and Manual Validation Workflow. It avoids exploit automation and credential attacks.

## How does it map OWASP?

VulScan collects local evidence and maps indicators to OWASP categories. Category outputs include confidence, evidence strength, manual validation status, and limitations.

## Does it exploit vulnerabilities?

No. VulScan is not an exploit framework and does not add attack automation.

## How do you handle authentication?

Authenticated workflows use redacted session profiles, boundary checks, GET-only authenticated crawl controls, and planning records. Raw cookies, tokens, and passwords are not stored.

## How do you prevent secret leakage?

Evidence is redacted, export safety checks run before report export, and demo safety scripts scan Safe Demo Dataset files.

## What is the Evidence Vault?

The Evidence Vault stores Redacted Evidence summaries, redaction status, evidence quality, timeline events, and links to findings and reports.

## What are the limitations?

VulScan is indicator-based, requires manual validation, does not guarantee complete coverage, and must only be used on authorised systems.

## What would you improve next?

PDF export, deeper authenticated assessment, plugin architecture, CI/CD hardening, more lab integrations, and richer report templates.

## How would you use this in a real engagement?

Use it to organise passive assessment outputs, OWASP mapping, redacted evidence, Manual Validation Workflow records, and professional reporting for authorised targets.

