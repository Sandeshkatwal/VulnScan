"""Category based Developer Remediation guidance for professional reports."""

from __future__ import annotations


REMEDIATION_LIBRARY: dict[str, list[str]] = {
    "A01": [
        "Enforce server-side authorization for every privileged action.",
        "Validate object ownership before returning or modifying records.",
        "Apply deny by default access-control decisions.",
        "Maintain tenant isolation at the data access layer.",
        "Use role-based access controls and avoid trusting client-side role or permission fields.",
    ],
    "A02": [
        "Harden security headers according to application context.",
        "Disable debug and default endpoints in production.",
        "Configure CORS with explicit trusted origins only.",
        "Remove unnecessary service banners and diagnostic metadata.",
    ],
    "A03": [
        "Maintain an SBOM for deployed components.",
        "Update vulnerable components through a managed patch process.",
        "Remove exposed dependency metadata where it is not required.",
        "Monitor CVEs for deployed components.",
    ],
    "A04": [
        "Enforce HTTPS for application traffic.",
        "Deploy HSTS after validating HTTPS coverage.",
        "Set Secure and HttpOnly cookie attributes where appropriate.",
        "Maintain TLS certificate and protocol hygiene.",
    ],
    "A05": [
        "Use parameterised queries for data access.",
        "Apply output encoding before rendering user-controlled content.",
        "Use allowlist validation for structured inputs.",
        "Apply context-aware escaping for HTML, JavaScript, URLs, and SQL contexts.",
    ],
    "A07": [
        "Harden session lifecycle controls.",
        "Secure password reset and account recovery flows.",
        "Use MFA where risk and user population justify it.",
        "Apply rate limiting and account lockout controls for authentication workflows.",
    ],
    "A08": [
        "Verify signatures and integrity for trusted data or code paths.",
        "Validate uploads and imports server-side.",
        "Apply webhook replay protection where webhooks are used.",
        "Use SRI and CSP where browser-loaded assets require integrity protection.",
    ],
    "A10": [
        "Return generic user-facing error messages.",
        "Keep detailed diagnostics in server-side logs only.",
        "Disable debug mode in production.",
    ],
    "BUSINESS_LOGIC": [
        "Enforce business rules server-side.",
        "Validate workflow state transitions.",
        "Add audit logging for sensitive business actions.",
        "Use anti-replay controls for state-changing workflows.",
    ],
}


def remediation_for_categories(categories: list[str], finding_type: str = "") -> dict[str, list[str]]:
    guidance: dict[str, list[str]] = {}
    for category in categories:
        key = str(category).split(":")[0].upper()
        if key in REMEDIATION_LIBRARY:
            guidance[key] = REMEDIATION_LIBRARY[key]
    if finding_type == "business_logic_issue" and "BUSINESS_LOGIC" not in guidance:
        guidance["BUSINESS_LOGIC"] = REMEDIATION_LIBRARY["BUSINESS_LOGIC"]
    return guidance


def remediation_text(categories: list[str], finding_type: str = "") -> str:
    guidance = remediation_for_categories(categories, finding_type)
    return " ".join(" ".join(items) for items in guidance.values())

