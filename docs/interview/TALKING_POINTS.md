# Interview Talking Points

## 30-Second Pitch

VulScan is an OWASP-focused vulnerability assessment, evidence management, and professional reporting platform for Authorised Security Assessment. It combines passive web checks, OWASP mapping, authenticated assessment planning, Evidence Vault controls, Professional Finding Builder, Report Composer, and Portfolio Demo Mode.

## 2-Minute Project Explanation

VulScan is local-first. The Python 3.11 backend exposes a FastAPI API and CLI workflows, while the React + Vite + TypeScript dashboard provides a portfolio-ready interface. The project emphasises Manual Validation Workflow, redacted evidence, and Responsible Use rather than exploit automation.

## Technical Architecture

The CLI and dashboard call the FastAPI layer, which coordinates discovery, passive Web DAST, OWASP modules, authenticated assessment planning, Evidence Vault, finding building, and report composition. Data is stored in SQLite/local JSON/report files.

## Security And Safety Design

VulScan is not an exploit framework. It is an authorised assessment and reporting platform that focuses on evidence quality, OWASP mapping, manual validation, and safe reporting.

## OWASP Coverage

The project maps evidence to OWASP categories and produces category-level assessment outputs with manual validation requirements and limitations.

## Authenticated Assessment

Authenticated assessment uses redacted session profiles, boundary controls, GET-only crawling, and planning records. It does not store raw cookies, bearer tokens, or passwords.

## Evidence Vault

The Evidence Vault stores Redacted Evidence, redaction status, evidence quality, timeline events, and export safety status.

## Reporting Workflow

Evidence references feed the Professional Finding Builder, then the Report Composer creates Executive Summary, Technical Findings, Evidence Summary, OWASP Mapping, Retest Summary, and Markdown/HTML/JSON exports.

## Limitations And Future Work

VulScan is indicator-based and requires manual validation. Future work includes richer authenticated assessment, role comparison workflows, PDF export, CI/CD hardening, plugin architecture, and more test labs.

## What I Learned

- Designing safe security tooling boundaries.
- Building a full-stack FastAPI and React product.
- Mapping technical evidence to professional reporting.
- Writing tests and release checks for safety-sensitive workflows.

## Role Relevance

VulScan demonstrates skills relevant to SOC, penetration testing, application security, security analyst, and vulnerability management roles.

