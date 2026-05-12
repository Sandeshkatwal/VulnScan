"""Safe HTTP security header auditing."""

from __future__ import annotations

from typing import Any

import requests


WEB_PORT_SCHEMES = {
    80: "http",
    443: "https",
    8080: "http",
    8443: "https",
}

MISSING_HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "title": "Missing Strict-Transport-Security header",
        "severity": "Medium",
        "recommendation": "Add HSTS on HTTPS services to instruct browsers to use HTTPS for future requests.",
    },
    "Content-Security-Policy": {
        "title": "Missing Content-Security-Policy header",
        "severity": "Medium",
        "recommendation": "Add a Content-Security-Policy header to reduce the impact of content injection issues.",
    },
    "X-Frame-Options": {
        "title": "Missing X-Frame-Options header",
        "severity": "Low",
        "recommendation": "Add X-Frame-Options or a CSP frame-ancestors directive to control framing.",
    },
    "X-Content-Type-Options": {
        "title": "Missing X-Content-Type-Options header",
        "severity": "Low",
        "recommendation": "Add X-Content-Type-Options: nosniff to reduce MIME sniffing risk.",
    },
    "Referrer-Policy": {
        "title": "Missing Referrer-Policy header",
        "severity": "Low",
        "recommendation": "Add a Referrer-Policy header to control referrer information sent by browsers.",
    },
    "Permissions-Policy": {
        "title": "Missing Permissions-Policy header",
        "severity": "Informational",
        "recommendation": "Add a Permissions-Policy header to restrict unnecessary browser features.",
    },
}


def audit_http_services(
    open_ports: list[dict[str, Any]],
    timeout: float = 5.0,
    max_redirects: int = 5,
) -> list[dict[str, Any]]:
    """Run safe HTTP header checks against detected web services."""
    findings: list[dict[str, Any]] = []

    for port_result in open_ports:
        port = int(port_result["port"])
        if port not in WEB_PORT_SCHEMES:
            continue

        url = _build_url(port_result["host"], port)
        findings.extend(_audit_url(url, timeout=timeout, max_redirects=max_redirects))

    return findings


def _audit_url(url: str, timeout: float, max_redirects: int) -> list[dict[str, Any]]:
    session = requests.Session()
    session.max_redirects = max_redirects

    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.SSLError as exc:
        return [
            _finding(
                title="HTTPS request failed due to SSL error",
                severity="Informational",
                category="HTTP audit error",
                affected_url=url,
                evidence=f"SSL error: {exc.__class__.__name__}",
                recommendation="Review the TLS certificate and configuration if this HTTPS service is expected to be available.",
                verification="VulScan sent a normal HTTP GET request to / and the TLS handshake failed.",
                limitation="No further HTTP header checks were performed for this URL.",
            )
        ]
    except requests.exceptions.TooManyRedirects:
        return [
            _finding(
                title="HTTP request exceeded redirect limit",
                severity="Informational",
                category="HTTP audit error",
                affected_url=url,
                evidence=f"More than {max_redirects} redirects were encountered.",
                recommendation="Review redirect configuration for loops or excessive redirect chains.",
                verification="VulScan sent a normal HTTP GET request to / with a limited redirect count.",
                limitation="No further HTTP header checks were performed for this URL.",
            )
        ]
    except requests.exceptions.RequestException as exc:
        return [
            _finding(
                title="HTTP request failed",
                severity="Informational",
                category="HTTP audit error",
                affected_url=url,
                evidence=f"Request error: {exc.__class__.__name__}",
                recommendation="Confirm the web service is reachable and intended to respond to HTTP GET requests.",
                verification="VulScan sent a normal HTTP GET request to /.",
                limitation="No further HTTP header checks were performed for this URL.",
            )
        ]

    findings = _check_missing_headers(response)
    findings.extend(_check_information_disclosure(response))
    findings.extend(_check_cookie_flags(response))
    return findings


def _check_missing_headers(response: requests.Response) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    is_https = response.url.lower().startswith("https://")

    for header_name, check in MISSING_HEADER_CHECKS.items():
        if header_name == "Strict-Transport-Security" and not is_https:
            continue

        if header_name not in response.headers:
            findings.append(
                _finding(
                    title=check["title"],
                    severity=check["severity"],
                    category="HTTP security headers",
                    affected_url=response.url,
                    evidence=f"{header_name} header was not present in the HTTP response.",
                    recommendation=check["recommendation"],
                    verification="Review the HTTP response headers returned from a normal GET request to /.",
                    limitation="Header presence is checked only on the final response after allowed redirects.",
                )
            )

    return findings


def _check_information_disclosure(response: requests.Response) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    server_header = response.headers.get("Server")
    if server_header:
        findings.append(
            _finding(
                title="Server header disclosure",
                severity="Informational",
                category="Information disclosure",
                affected_url=response.url,
                evidence=f"Server header present: {server_header}",
                recommendation="Reduce or standardize Server header details where supported by the web server.",
                verification="Review the HTTP response headers returned from a normal GET request to /.",
                limitation="Header presence alone does not confirm a vulnerability.",
            )
        )

    powered_by_header = response.headers.get("X-Powered-By")
    if powered_by_header:
        findings.append(
            _finding(
                title="X-Powered-By header disclosure",
                severity="Low",
                category="Information disclosure",
                affected_url=response.url,
                evidence=f"X-Powered-By header present: {powered_by_header}",
                recommendation="Remove or standardize X-Powered-By details where supported by the application stack.",
                verification="Review the HTTP response headers returned from a normal GET request to /.",
                limitation="Header presence alone does not confirm an exploitable issue.",
            )
        )

    return findings


def _check_cookie_flags(response: requests.Response) -> list[dict[str, Any]]:
    set_cookie = response.headers.get("Set-Cookie")
    if not set_cookie:
        return []

    findings: list[dict[str, Any]] = []
    cookie_header = set_cookie.lower()
    is_https = response.url.lower().startswith("https://")

    if is_https and "secure" not in cookie_header:
        findings.append(
            _finding(
                title="Cookie missing Secure flag",
                severity="Medium",
                category="Cookie security",
                affected_url=response.url,
                evidence="Set-Cookie header present without Secure flag.",
                recommendation="Add the Secure flag to cookies set over HTTPS.",
                verification="Review Set-Cookie headers returned from a normal GET request to /.",
                limitation="This basic check evaluates header text and does not assess individual cookie purpose.",
            )
        )

    if "httponly" not in cookie_header:
        findings.append(
            _finding(
                title="Cookie missing HttpOnly flag",
                severity="Medium",
                category="Cookie security",
                affected_url=response.url,
                evidence="Set-Cookie header present without HttpOnly flag.",
                recommendation="Add the HttpOnly flag to cookies that do not need client-side script access.",
                verification="Review Set-Cookie headers returned from a normal GET request to /.",
                limitation="This basic check evaluates header text and does not assess individual cookie purpose.",
            )
        )

    if "samesite" not in cookie_header:
        findings.append(
            _finding(
                title="Cookie missing SameSite flag",
                severity="Low",
                category="Cookie security",
                affected_url=response.url,
                evidence="Set-Cookie header present without SameSite flag.",
                recommendation="Add an appropriate SameSite attribute to cookies.",
                verification="Review Set-Cookie headers returned from a normal GET request to /.",
                limitation="This basic check evaluates header text and does not assess individual cookie purpose.",
            )
        )

    return findings


def _build_url(host: str, port: int) -> str:
    scheme = WEB_PORT_SCHEMES[port]
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    if default_port:
        return f"{scheme}://{host}/"
    return f"{scheme}://{host}:{port}/"


def _finding(
    title: str,
    severity: str,
    category: str,
    affected_url: str,
    evidence: str,
    recommendation: str,
    verification: str,
    limitation: str,
) -> dict[str, str]:
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "affected_url": affected_url,
        "evidence": evidence,
        "confidence": "medium",
        "recommendation": recommendation,
        "verification": verification,
        "limitation": limitation,
    }
