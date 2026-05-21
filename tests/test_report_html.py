from datetime import datetime, timezone

from scanner.report_html import save_html_report
from scanner.windows_demo import DEMO_NOTICE, build_demo_scan_result, build_windows_demo_result
from scanner.windows_audit_profiles import resolve_windows_audit_profile


def test_html_report_renders_credentialed_audit_modules(tmp_path) -> None:
    scan_result = {
        "host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "scan_mode": "safe",
        "duration_seconds": 0.1,
        "open_ports": [],
        "findings": [],
        "http_findings": [],
        "tls_findings": [],
        "ssh_findings": [],
        "windows_findings": [],
        "ssh_audit": {"enabled": True, "status": "success"},
        "ssh_audit_summary": {"enabled": True, "status": "success"},
        "windows_audit_summary": {
            "enabled": True,
            "status": "success",
            "auth_method": "winrm",
            "windows_audit_profile": "standard",
            "profile_description": "Read-only Windows baseline.",
            "profile_enabled_sections": [
                "windows_service_reachability",
                "winrm_authentication",
                "windows_host_info",
                "windows_security_status",
                "windows_patch_status",
            ],
            "profile_skipped_sections": ["windows_policy_status", "windows_registry_audit"],
            "profile_manual_overrides": [],
            "profile_default_timeout_seconds": 120.0,
            "username_used": "auditor",
            "domain": "WORKGROUP",
            "smb_reachable": False,
            "winrm_http_reachable": True,
            "winrm_https_reachable": False,
            "rdp_reachable": False,
            "winrm_auth_attempted": True,
            "winrm_auth_status": "authenticated",
            "winrm_error_code": "WINRM_AUTH_SUCCESS",
            "winrm_endpoint_used": "http://127.0.0.1:5985/wsman",
            "winrm_transport": "ntlm",
            "safe_validation_command": "hostname",
            "validation_result_summary": "LABHOST",
            "windows_host_info_collected": True,
            "windows_host_info_status": "collected",
            "windows_host_info": {
                "hostname": "LABHOST",
                "current_identity": "workgroup\\auditor",
                "os_caption": "Microsoft Windows Server 2022 Standard",
                "os_version": "10.0.20348",
                "os_build": "20348",
                "os_architecture": "64-bit",
                "domain": "WORKGROUP",
                "workgroup": "",
                "powershell_version": "5.1",
                "last_boot_time": "2026-05-16T09:00:00Z",
                "timezone_display_name": "GMT Standard Time",
            },
            "windows_security_status_checked": True,
            "windows_security_status_status": "checked",
            "windows_security_status": {
                "firewall_profiles": [
                    {
                        "name": "Domain",
                        "enabled": "True",
                        "default_inbound_action": "Block",
                        "default_outbound_action": "Allow",
                    }
                ],
                "defender_service": {"status": "Running", "start_type": "Automatic"},
                "defender_status": {
                    "real_time_protection_enabled": "True",
                    "antivirus_enabled": "True",
                    "am_service_enabled": "True",
                    "antivirus_signature_last_updated": "2026-05-15T10:00:00Z",
                    "antispyware_signature_last_updated": "2026-05-15T10:00:00Z",
                },
                "security_status_limitations": [],
            },
            "findings_count": 1,
            "highest_windows_risk_score": 0,
            "highest_windows_risk_label": "Informational",
            "limitations": ["Validation only."],
        },
        "windows_audit_sections": [
            {
                "section_id": "windows_security_status",
                "section_name": "Windows Security Status",
                "source": "windows_security_audit",
                "status": "success",
                "checks_completed": 3,
                "checks_failed": 0,
                "checks_skipped": 0,
                "findings": [],
                "summary": {},
                "errors": [],
                "limitations": ["Read-only Firewall and Defender status commands only."],
                "duration_seconds": 0.2,
                "enabled_by_profile": True,
                "enabled_by_manual_flag": False,
                "skipped_reason": "",
            },
            {
                "section_id": "windows_registry_audit",
                "section_name": "Windows Registry Audit",
                "source": "windows_registry_audit",
                "status": "partial",
                "checks_completed": 1,
                "checks_failed": 1,
                "checks_skipped": 0,
                "findings": [],
                "summary": {},
                "errors": [],
                "limitations": ["Exact template-defined HKLM value reads only."],
                "duration_seconds": 0.3,
                "enabled_by_profile": False,
                "enabled_by_manual_flag": True,
                "skipped_reason": "",
            },
        ],
        "credentialed_audits": [
            {
                "source": "ssh_audit",
                "module_name": "Authenticated SSH Audit",
                "status": "success",
                "target": "127.0.0.1",
                "authenticated": True,
                "auth_method": "password",
                "username": "sadmin",
                "profile": "standard",
                "duration_seconds": 1.0,
                "checks_completed": 1,
                "checks_failed": 0,
                "checks_skipped": 0,
                "findings": [],
            },
            {
                "source": "windows_audit",
                "module_name": "Windows WinRM Authentication Check",
                "status": "success",
                "target": "127.0.0.1",
                "authenticated": True,
                "auth_method": "winrm",
                "username": "auditor",
                "profile": "foundation",
                "duration_seconds": 1.0,
                "checks_completed": 6,
                "checks_failed": 0,
                "checks_skipped": 0,
                "findings": [],
            }
        ],
    }

    path = save_html_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )

    html = path.read_text(encoding="utf-8")

    assert "Credentialed Audit Modules" in html
    assert "Authenticated SSH Audit" in html
    assert "Windows WinRM Authentication Check" in html
    assert "LABHOST" in html
    assert "Microsoft Windows Server 2022 Standard" in html
    assert "Windows Security Status" in html
    assert "Windows Audit Profile" in html
    assert "standard" in html
    assert "windows_patch_status" in html
    assert "Normalised Windows Audit Sections" in html
    assert "Windows Registry Audit" in html
    assert "partial" in html
    assert "Running" in html
    assert "SENSITIVE_VALUE" not in html


def test_html_report_redacts_windows_evidence_secrets(tmp_path) -> None:
    scan_result = {
        "host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "scan_mode": "safe",
        "duration_seconds": 0.1,
        "open_ports": [],
        "findings": [
            {
                "id": "FINDING-0001",
                "title": "Windows Test",
                "severity": "Informational",
                "category": "Windows Audit",
                "affected_host": "127.0.0.1",
                "affected_port": None,
                "affected_url": None,
                "service": "winrm",
                "evidence": "Observed Password=Secret123",
                "evidence_details": {"source": "unit", "observed_value": "Authorization: Basic dXNlcjpwYXNz"},
                "confidence": "High",
                "impact": "None.",
                "recommendation": "None.",
                "verification": "Unit test.",
                "limitation": "None.",
                "source": "windows_audit",
                "risk_score": 0,
                "risk_label": "Informational",
                "fix_priority": "Document and monitor",
                "created_at": "2026-05-16T10:00:00+00:00",
            }
        ],
        "http_findings": [],
        "tls_findings": [],
        "ssh_findings": [],
        "windows_findings": [],
        "ssh_audit": {"enabled": False, "status": "skipped"},
        "ssh_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_summary": {"enabled": True, "status": "success", "safe_detail": "AccessToken=HiddenValue"},
        "windows_audit_sections": [],
        "credentialed_audits": [],
    }

    path = save_html_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )

    html = path.read_text(encoding="utf-8")
    assert "Secret123" not in html
    assert "dXNlcjpwYXNz" not in html
    assert "HiddenValue" not in html


def test_html_report_shows_windows_demo_banner(tmp_path) -> None:
    plan = resolve_windows_audit_profile(profile_name="detailed", auth_method="winrm")
    profile_summary = {
        "windows_audit_profile": plan["profile_name"],
        "profile_description": plan["profile_description"],
        "profile_enabled_sections": plan["profile_enabled_sections"],
        "profile_skipped_sections": plan["profile_skipped_sections"],
        "profile_manual_overrides": plan["profile_manual_overrides"],
        "profile_default_timeout_seconds": plan["profile_default_timeout_seconds"],
        "profile_effective_audit_timeout_seconds": 180.0,
        "profile_section_labels": plan["section_labels"],
        "profile_section_enabled_by_profile": plan["enabled_by_profile"],
        "profile_section_enabled_by_manual_flag": plan["enabled_by_manual_flag"],
        "profile_section_skipped_reasons": plan["skipped_reasons"],
    }
    windows_result = build_windows_demo_result(
        target="demo-windows",
        profile_summary=profile_summary,
        audit_timeout_seconds=180.0,
    )
    scan_result = build_demo_scan_result("demo-windows")
    scan_result.update(
        {
            "scan_mode": "safe",
            "http_findings": [],
            "tls_findings": [],
            "ssh_findings": [],
            "ssh_audit": {"enabled": False, "status": "skipped"},
            "ssh_audit_summary": {"enabled": False, "status": "skipped"},
            "windows_audit": windows_result,
            "windows_findings": [],
            "windows_audit_sections": windows_result["windows_audit_sections"],
            "windows_audit_summary": windows_result["summary"],
            "windows_audit_consolidated_summary": windows_result["summary"],
            "credentialed_audits": [windows_result["credentialed_audit"]],
        }
    )
    from scanner.finding import assign_sequential_finding_ids

    scan_result["findings"] = assign_sequential_finding_ids(windows_result["findings"])
    scan_result["windows_findings"] = scan_result["findings"]

    path = save_html_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )
    html = path.read_text(encoding="utf-8")

    assert "Demo Mode: This report uses fake sample data. No real system was scanned." in html
    assert DEMO_NOTICE in html
    assert "WIN-DEMO-01" in html
    assert "Windows Audit Demo Mode" in html


def test_html_report_renders_web_dast_section(tmp_path) -> None:
    scan_result = {
        "host": "example.test",
        "resolved_ip": "",
        "scan_mode": "web-dast",
        "duration_seconds": 0.2,
        "open_ports": [],
        "findings": [],
        "http_findings": [],
        "tls_findings": [],
        "ssh_findings": [],
        "windows_findings": [],
        "web_findings": [
            {
                "id": "FINDING-0001",
                "title": "Password Form Discovered",
                "severity": "Informational",
                "category": "Web Form Discovery",
                "affected_host": None,
                "affected_port": None,
                "affected_url": "https://example.test/login",
                "service": "http",
                "evidence": "Password input field discovered.",
                "confidence": "High",
                "impact": "Login forms should use HTTPS.",
                "recommendation": "Ensure login forms use HTTPS.",
                "verification": "Review the discovered form.",
                "limitation": "This finding does not test authentication security.",
                "source": "web_crawler",
                "risk_score": 0,
                "risk_label": "Informational",
                "fix_priority": "Document and monitor",
                "created_at": "2026-05-18T10:00:00+00:00",
            }
        ],
        "web_dast_summary": {
            "enabled": True,
            "mode": "passive",
            "start_url": "https://example.test/",
            "normalized_start_url": "https://example.test/",
            "allowed_host": "example.test",
            "scan_profile": "passive",
            "sections_enabled": ["web_crawler", "web_headers", "web_cookies"],
            "sections_completed": ["web_crawler", "web_headers", "web_cookies"],
            "sections_partial": [],
            "sections_failed": [],
            "total_duration_seconds": 0.2,
            "total_requests": 1,
            "pages_crawled": 1,
            "forms_discovered": 1,
            "cookies_observed": 1,
            "sitemap_urls_found": 0,
            "robots_found": "unknown",
            "total_web_findings": 1,
            "highest_web_risk_score": 0,
            "highest_web_risk_label": "Informational",
            "passive_risk_rating": "Informational",
            "recommended_next_steps": ["Review cookie flags for sensitive/session cookies."],
            "limitations": ["Passive only."],
        },
        "web_dast_sections": [
            {
                "section_id": "web_crawler",
                "section_name": "Web Crawler",
                "source": "web_crawler",
                "status": "success",
                "enabled": True,
                "key_metrics": {"pages_crawled": 1, "forms_found": 1, "external_links": 1},
                "findings_count": 1,
                "duration_seconds": 0.2,
                "limitations": ["GET-only crawler."],
            },
            {
                "section_id": "web_headers",
                "section_name": "Web Header Audit",
                "source": "web_header_audit",
                "status": "success",
                "enabled": True,
                "key_metrics": {"pages_checked": 1, "missing_headers": 1},
                "findings_count": 1,
                "duration_seconds": 0.0,
                "limitations": ["Passive header checks only."],
            },
            {
                "section_id": "web_cookies",
                "section_name": "Web Cookie Audit",
                "source": "web_cookie_audit",
                "status": "success",
                "enabled": True,
                "key_metrics": {"cookies_observed": 1, "missing_samesite": 1},
                "findings_count": 1,
                "duration_seconds": 0.0,
                "limitations": ["Cookie values are not stored."],
            },
        ],
        "ssh_audit": {"enabled": False, "status": "skipped"},
        "ssh_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_sections": [],
        "credentialed_audits": [],
        "web_scan_summary": {
            "enabled": True,
            "start_url": "https://example.test/",
            "allowed_host": "example.test",
            "pages_crawled": 1,
            "pages_skipped": 0,
            "forms_discovered": 1,
            "password_forms_discovered": 1,
            "file_upload_forms_discovered": 0,
            "unique_external_links": 1,
            "errors_count": 0,
            "duration_seconds": 0.2,
            "limitations": ["Version 13.0 does not submit forms."],
        },
        "web_header_summary": {
            "enabled": True,
            "pages_checked": 1,
            "headers_checked": ["Content-Security-Policy"],
            "missing_header_counts": {"Content-Security-Policy": 1},
            "disclosure_header_counts": {},
            "cookie_issue_counts": {},
            "cookie_issues_count": 0,
            "findings_count": 1,
            "limitations": ["Passive header checks only."],
        },
        "web_header_results": [],
        "web_cookie_summary": {
            "enabled": True,
            "pages_checked": 1,
            "cookies_observed": 1,
            "unique_cookie_names": 1,
            "cookies_missing_secure": 0,
            "cookies_missing_httponly": 0,
            "cookies_missing_samesite": 1,
            "samesite_none_without_secure": 0,
            "persistent_cookie_issues": 0,
            "findings_count": 1,
            "limitations": ["Cookie values are not stored."],
        },
        "web_cookie_results": [
            {
                "cookie_name": "SESSIONID",
                "source_url": "https://example.test/",
                "secure": True,
                "httponly": True,
                "samesite": "",
                "path": "/",
                "domain": "",
                "expires_present": False,
                "max_age_present": False,
                "is_session_cookie": True,
                "is_https_context": True,
                "issues": ["Cookie Missing SameSite Attribute"],
            }
        ],
        "crawled_pages": [
            {
                "url": "https://example.test/",
                "status_code": 200,
                "title": "Home",
                "depth": 0,
                "content_type": "text/html",
                "response_time_seconds": 0.01,
                "links_found_count": 2,
                "forms_found_count": 1,
            }
        ],
        "discovered_forms": [
            {
                "page_url": "https://example.test/",
                "method": "POST",
                "action": "https://example.test/login",
                "input_names": ["username", "password"],
                "input_types": ["text", "password"],
                "has_password_field": True,
                "has_file_upload": False,
            }
        ],
    }

    path = save_html_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )
    html = path.read_text(encoding="utf-8")

    assert "Web DAST Report" in html
    assert "Web DAST Passive Report" in html
    assert "Scope and Safety Controls" in html
    assert "Crawl Summary" in html
    assert "https://example.test/" in html
    assert "Password Form Discovered" in html
    assert "Version 13.0 does not submit forms." in html
    assert "Web Header Audit" in html
    assert "Content-Security-Policy" in html
    assert "Web Cookie Audit" in html
    assert "Cookie Missing SameSite Attribute" in html


def test_html_report_renders_partial_web_dast_summary(tmp_path) -> None:
    scan_result = {
        "host": "example.test",
        "resolved_ip": "",
        "scan_mode": "web-dast",
        "duration_seconds": 0.1,
        "open_ports": [],
        "findings": [],
        "http_findings": [],
        "tls_findings": [],
        "ssh_findings": [],
        "windows_findings": [],
        "web_findings": [],
        "ssh_audit": {"enabled": False, "status": "skipped"},
        "ssh_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_sections": [],
        "credentialed_audits": [],
        "web_dast_summary": {
            "enabled": True,
            "mode": "passive",
            "start_url": "https://example.test/",
            "pages_crawled": 0,
            "total_requests": 0,
            "total_web_findings": 0,
            "highest_web_risk_score": 0,
            "highest_web_risk_label": "Informational",
            "passive_risk_rating": "None",
            "sections_completed": [],
            "sections_partial": [],
            "sections_failed": [],
            "recommended_next_steps": ["Continue with authorised deeper testing if in scope."],
            "limitations": ["Passive only."],
        },
        "web_dast_sections": [],
    }

    path = save_html_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )
    html = path.read_text(encoding="utf-8")

    assert "Web DAST Passive Report" in html
    assert "Continue with authorised deeper testing if in scope." in html


def test_html_report_renders_vulnerability_intelligence_section(tmp_path) -> None:
    scan_result = {
        "host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "scan_mode": "safe",
        "duration_seconds": 0.1,
        "open_ports": [],
        "software_inventory": {
            "items": [
                {
                    "host": "127.0.0.1",
                    "port": 22,
                    "protocol": "tcp",
                    "service_name": "ssh",
                    "product": None,
                    "version": None,
                    "source": "service_detect",
                    "evidence": "TCP connection successful",
                    "confidence": "Medium",
                }
            ],
            "total_items": 1,
            "sources_used": ["service_detect"],
            "limitations": ["Local inventory only."],
        },
        "vulnerability_intelligence": {
            "enabled": True,
            "ruleset_name": "Unit Rules",
            "ruleset_version": "1.0",
            "rules_loaded": 1,
            "inventory_items_checked": 1,
            "matches_found": 1,
            "cve_matches_count": 0,
            "version_rules_loaded": 1,
            "version_rules_evaluated": 1,
            "version_matches_found": 1,
            "unknown_version_count": 0,
            "insufficient_evidence_count": 0,
            "confirmed_version_match_count": 1,
            "local_cve_metadata_count": 0,
            "exploit_available_count": 0,
            "highest_cvss_score": None,
            "highest_epss_score": None,
            "highest_intel_risk_label": "Informational",
            "limitations": ["Local rules only."],
            "matches": [
                {
                    "rule_id": "R1",
                    "title": "SSH Service Exposed",
                    "matched_item": {"service_name": "ssh", "product": "openssh", "version": "8.9p1", "port": 22},
                    "match_status": "matched",
                    "match_confidence": "Medium",
                    "version_condition": {"operator": "version_less_than", "value": "9.6", "display": "less than 9.6"},
                    "cve": None,
                    "cvss_score": None,
                    "epss_score": None,
                    "fixed_version": "9.6",
                    "severity": "Informational",
                    "confidence": "Medium",
                    "recommendation": "Restrict SSH.",
                }
            ],
            "cve_feed_enabled": True,
            "cve_feed_name": "Unit CVE Feed",
            "cve_feed_version": "1.0",
            "cve_feed_items_loaded": 1,
            "cve_feed_items_evaluated": 1,
            "cve_feed_matches_found": 1,
            "cve_feed_insufficient_evidence_count": 0,
            "cve_feed_unknown_version_count": 0,
            "cve_feed_highest_cvss": 7.5,
            "cve_feed_exploit_available_count": 0,
            "cve_feed_limitations": ["Local feed only."],
            "cve_feed_matches": [
                {
                    "cve": "LOCAL-CVE-DEMO-0001",
                    "title": "Demo OpenSSH Version Below Policy Threshold",
                    "product": "openssh",
                    "version": "8.9p1",
                    "affected_condition": {"operator": "less_than", "value": "9.6", "display": "less_than 9.6"},
                    "fixed_version": "9.6",
                    "cvss_score": 7.5,
                    "epss_score": 0.72,
                    "epss_percentile": 0.94,
                    "epss_enriched": True,
                    "severity": "High",
                    "match_status": "matched",
                    "match_confidence": "High",
                    "exploit_available": False,
                }
            ],
            "epss_enabled": True,
            "epss_file": "data\\epss\\sample_epss.csv",
            "epss_records_loaded": 1,
            "epss_invalid_records": 0,
            "epss_duplicate_records": 0,
            "epss_matches_enriched": 1,
            "epss_missing_for_cve_count": 0,
            "highest_epss_percentile": 0.94,
            "high_epss_count": 1,
            "medium_epss_count": 0,
            "low_epss_count": 0,
            "epss_limitations": ["Local EPSS only."],
        },
        "findings": [],
        "http_findings": [],
        "tls_findings": [],
        "ssh_findings": [],
        "windows_findings": [],
        "vuln_intel_findings": [],
        "ssh_audit": {"enabled": False, "status": "skipped"},
        "ssh_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_sections": [],
        "credentialed_audits": [],
    }

    path = save_html_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )
    html = path.read_text(encoding="utf-8")

    assert "Software/Service Inventory" in html
    assert "Vulnerability Intelligence" in html
    assert "SSH Service Exposed" in html
    assert "less than 9.6" in html
    assert "Local CVE Feed Matches" in html
    assert "EPSS Metadata Summary" in html
    assert "LOCAL-CVE-DEMO-0001" in html
    assert "0.72" in html
    assert "0.94" in html
    assert "Demo OpenSSH Version Below Policy Threshold" in html
    assert "matched" in html
    assert "Local rules only." in html
