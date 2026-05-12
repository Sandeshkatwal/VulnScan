"""Safe HTTP security header auditing."""

from __future__ import annotations

from typing import Any

import requests

from scanner.finding import Finding, create_finding


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
) -> list[Finding]:
    """Run safe HTTP header checks against detected web services."""
    findings: list[Finding] = []

    for port_result in open_ports:
        port = int(port_result["port"])
        if port not in WEB_PORT_SCHEMES:
            continue

        url = _build_url(port_result["host"], port)
        findings.extend(_audit_url(url, timeout=timeout, max_redirects=max_redirects))

    return findings


def _audit_url(url: str, timeout: float, max_redirects: int) -> list[Finding]:
    session = requests.Session()
    session.max_redirects = max_redirects

    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.SSLError as exc:
        return [
            create_finding(
                title="HTTPS request failed due to SSL error",
                severity="Informational",
                category="HTTP audit error",
                affected_url=url,
                evidence=f"SSL error: {exc.__class__.__name__}",
                confidence="Medium",
                impact="HTTP header checks could not be completed for this URL.",
                recommendation="Review the TLS certificate and configuration if this HTTPS service is expected to be available.",
                verification="VulScan sent a normal HTTP GET request to / and the TLS handshake failed.",
                limitation="No further HTTP header checks were performed for this URL.",
                source="http_audit",
            )
        ]
    except requests.exceptions.TooManyRedirects:
        return [
            create_finding(
                title="HTTP request exceeded redirect limit",
                severity="Informational",
                category="HTTP audit error",
                affected_url=url,
                evidence=f"More than {max_redirects} redirects were encountered.",
                confidence="Medium",
                impact="HTTP header checks could not be completed because redirect handling stopped safely.",
                recommendation="Review redirect configuration for loops or excessive redirect chains.",
                verification="VulScan sent a normal HTTP GET request to / with a limited redirect count.",
                limitation="No further HTTP header checks were performed for this URL.",
                source="http_audit",
            )
        ]
    except requests.exceptions.RequestException as exc:
        return [
            create_finding(
                title="HTTP request failed",
                severity="Informational",
                category="HTTP audit error",
                affected_url=url,
                evidence=f"Request error: {exc.__class__.__name__}",
                confidence="Medium",
                impact="HTTP header checks could not be completed for this URL.",
                recommendation="Confirm the web service is reachable and intended to respond to HTTP GET requests.",
                verification="VulScan sent a normal HTTP GET request to /.",
                limitation="No further HTTP header checks were performed for this URL.",
                source="http_audit",
            )
        ]

    findings = _check_missing_headers(response)
    findings.extend(_check_information_disclosure(response))
    findings.extend(_check_cookie_flags(response))
    return findings


def _check_missing_headers(response: requests.Response) -> list[Finding]:
    findings: list[Finding] = []
    is_https = response.url.lower().startswith("https://")

    for header_name, check in MISSING_HEADER_CHECKS.items():
        if header_name == "Strict-Transport-Security" and not is_https:
            continue

        if header_name not in response.headers:
            findings.append(
                create_finding(
                    title=check["title"],
                    severity=check["severity"],
                    category="HTTP security headers",
                    affected_url=response.url,
                    evidence=f"{header_name} header was not present in the HTTP response.",
                    confidence="Medium",
                    impact="Missing browser security headers may reduce protection against common client-side attack classes.",
                    recommendation=check["recommendation"],
                    verification="Review the HTTP response headers returned from a normal GET request to /.",
                    limitation="Header presence is checked only on the final response after allowed redirects.",
                    source="http_audit",
                )
            )

    return findings


def _check_information_disclosure(response: requests.Response) -> list[Finding]:
    findings: list[Finding] = []

    server_header = response.headers.get("Server")
    if server_header:
        findings.append(
            create_finding(
                title="Server header disclosure",
                severity="Informational",
                category="Information disclosure",
                affected_url=response.url,
                evidence=f"Server header present: {server_header}",
                confidence="Medium",
                impact="Technology details may help an attacker fingerprint the service.",
                recommendation="Reduce or standardize Server header details where supported by the web server.",
                verification="Review the HTTP response headers returned from a normal GET request to /.",
                limitation="Header presence alone does not confirm a vulnerability.",
                source="http_audit",
            )
        )

    powered_by_header = response.headers.get("X-Powered-By")
    if powered_by_header:
        findings.append(
            create_finding(
                title="X-Powered-By header disclosure",
                severity="Low",
                category="Information disclosure",
                affected_url=response.url,
                evidence=f"X-Powered-By header present: {powered_by_header}",
                confidence="Medium",
                impact="Application stack details may help an attacker fingerprint the service.",
                recommendation="Remove or standardize X-Powered-By details where supported by the application stack.",
                verification="Review the HTTP response headers returned from a normal GET request to /.",
                limitation="Header presence alone does not confirm an exploitable issue.",
                source="http_audit",
            )
        )

    return findings


def _check_cookie_flags(response: requests.Response) -> list[Finding]:
    set_cookie = response.headers.get("Set-Cookie")
    if not set_cookie:
        return []

    findings: list[Finding] = []
    cookie_header = set_cookie.lower()
    is_https = response.url.lower().startswith("https://")

    if is_https and "secure" not in cookie_header:
        findings.append(
            create_finding(
                title="Cookie missing Secure flag",
                severity="Medium",
                category="Cookie security",
                affected_url=response.url,
                evidence="Set-Cookie header present without Secure flag.",
                confidence="Medium",
                impact="Cookies without Secure may be sent over unencrypted HTTP if the browser is directed there.",
                recommendation="Add the Secure flag to cookies set over HTTPS.",
                verification="Review Set-Cookie headers returned from a normal GET request to /.",
                limitation="This basic check evaluates header text and does not assess individual cookie purpose.",
                source="http_audit",
            )
        )

    if "httponly" not in cookie_header:
        findings.append(
            create_finding(
                title="Cookie missing HttpOnly flag",
                severity="Medium",
                category="Cookie security",
                affected_url=response.url,
                evidence="Set-Cookie header present without HttpOnly flag.",
                confidence="Medium",
                impact="Cookies without HttpOnly may be accessible to client-side scripts.",
                recommendation="Add the HttpOnly flag to cookies that do not need client-side script access.",
                verification="Review Set-Cookie headers returned from a normal GET request to /.",
                limitation="This basic check evaluates header text and does not assess individual cookie purpose.",
                source="http_audit",
            )
        )

    if "samesite" not in cookie_header:
        findings.append(
            create_finding(
                title="Cookie missing SameSite flag",
                severity="Low",
                category="Cookie security",
                affected_url=response.url,
                evidence="Set-Cookie header present without SameSite flag.",
                confidence="Medium",
                impact="Cookies without SameSite may have weaker cross-site request protections.",
                recommendation="Add an appropriate SameSite attribute to cookies.",
                verification="Review Set-Cookie headers returned from a normal GET request to /.",
                limitation="This basic check evaluates header text and does not assess individual cookie purpose.",
                source="http_audit",
            )
        )

    return findings


def _build_url(host: str, port: int) -> str:
    scheme = WEB_PORT_SCHEMES[port]
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    if default_port:
        return f"{scheme}://{host}/"
    return f"{scheme}://{host}:{port}/"

