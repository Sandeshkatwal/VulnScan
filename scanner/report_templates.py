"""Default templates for Professional Finding Builder and Report Composer."""

from __future__ import annotations

from scanner.finding_models import build_professional_finding
from scanner.report_composer import compose_report


def sample_finding_template() -> dict:
    return build_professional_finding(
        finding_id="finding-template",
        title="Template Technical Finding",
        severity="Low",
        confidence="Low",
        validation_status="manual_validation_required",
        technical_summary="Describe the safe observed behaviour using redacted evidence references only.",
        remediation="Provide Developer Remediation guidance.",
        owasp_categories=["A02:2025"],
    )


def sample_report_template() -> dict:
    return compose_report(title="VulScan OWASP Assessment Report", target="http://127.0.0.1:8000", findings=[sample_finding_template()])

