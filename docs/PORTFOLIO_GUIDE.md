# Portfolio Guide

## Short Description

VulScan is a local authorised security assessment, vulnerability management, and bug intelligence platform built with Python, FastAPI, SQLite, React, and TypeScript.

## CV Description

Example CV bullet points:

- Built VulScan, a local authorised security assessment and vulnerability management platform using Python, FastAPI, SQLite, React, and TypeScript.
- Implemented discovery, passive Web DAST, vulnerability intelligence, risk prioritisation, reporting, remediation tracking, and dashboard visualisation.
- Designed a Bug Intelligence workflow for Program Scope, Recon Intelligence, Endpoint Intelligence, OWASP Indicator Mapping, Safe Validation, Evidence Capture, Security Finding Reports, Duplicate Detection, and Performance Metrics.

## Technical Stack

- Python 3.11 backend
- Typer CLI
- FastAPI local API
- SQLite persistence
- React + Vite + TypeScript dashboard
- Local JSON/HTML reports
- Pytest backend coverage

## Security Modules

- Discovery Engine
- Credentialed Linux SSH audit
- Credentialed Windows audit foundation
- Passive Web DAST Engine
- Vulnerability Intelligence Engine
- Prioritisation Engine
- Bug Intelligence Engine
- Duplicate Detection and Finding Fingerprinting
- Performance Metrics

## Architecture Explanation

VulScan separates collection, enrichment, storage, API access, and dashboard presentation. CLI commands perform authorised local assessment workflows. Results are saved to local reports and SQLite. The FastAPI layer exposes local jobs, findings, reports, remediation records, and Bug Intelligence data. The React dashboard presents the workflow for review and triage.

## Safe-Use Statement

VulScan is designed for systems the user owns or has explicit permission to test. It does not add exploitation, brute force controls, credential attacks, destructive payloads, external platform submission, or remote API exposure by default.

## Demo Workflow

1. Start the API locally.
2. Start the dashboard in demo and portfolio mode.
3. Show overview, jobs, vulnerability list, risk, reports, Bug Intelligence Workflow, Duplicate Detection, and Performance Metrics.
4. Run a safe localhost scan or show preloaded demo data.
5. Explain how findings move into reporting, remediation, submission tracking, retesting, and metrics.

## 2-Minute Interview Pitch

VulScan is my end-to-end security tooling project. It started as a defensive scanner and grew into a local vulnerability management and bug intelligence platform. It has a Python backend, FastAPI API, SQLite persistence, and a React/TypeScript dashboard. The project demonstrates safe scanner design, report generation, risk prioritisation, OWASP mapping, remediation tracking, and responsible disclosure workflow modelling. I focused heavily on safety boundaries: local-first operation, scope enforcement, redaction, no exploitation, no brute force, and no external platform tokens.

## 5-Minute Technical Demo Plan

1. Show the README and safety statement.
2. Run `scanner.main scan --target 127.0.0.1`.
3. Open the dashboard overview and jobs page.
4. Show findings, risk, reports, and remediation tracking.
5. Open Bug Intelligence Workflow and explain Program Scope through Metrics.
6. Show Duplicate Detection and Performance Metrics.
7. Mention limitations and future roadmap.
