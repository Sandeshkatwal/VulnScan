import json
from datetime import datetime, timezone

from scanner.report_json import save_json_report
from scanner.windows_demo import DEMO_NOTICE, build_windows_demo_result, build_demo_scan_result
from scanner.windows_audit_profiles import resolve_windows_audit_profile


def test_json_report_includes_credentialed_audits_and_findings(tmp_path) -> None:
    scan_result = {
        "host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "scan_mode": "safe",
        "duration_seconds": 0.1,
        "open_ports": [],
        "findings": [
            {
                "id": "FINDING-0001",
                "title": "SSH Login Successful",
                "severity": "Informational",
                "category": "Credentialed Access",
                "affected_host": "127.0.0.1",
                "affected_port": 22,
                "affected_url": None,
                "service": "ssh",
                "evidence": "Authenticated SSH session established.",
                "confidence": "High",
                "impact": "Credentialed auditing can reduce false positives.",
                "recommendation": "Use least-privilege read-only credentials.",
                "verification": "Review SSH audit output.",
                "limitation": "Depends on account permissions.",
                "source": "ssh_audit",
                "risk_score": 0,
                "risk_label": "Informational",
                "fix_priority": "Document and monitor",
                "created_at": "2026-05-16T10:00:00+00:00",
            }
        ],
        "http_findings": [],
        "tls_findings": [],
        "ssh_findings": [],
        "windows_findings": [
            {
                "id": "FINDING-0002",
                "title": "WinRM Authentication Successful",
                "severity": "Informational",
                "category": "Windows Credentialed Access",
                "affected_host": "127.0.0.1",
                "affected_port": None,
                "affected_url": None,
                "service": "winrm",
                "evidence": "WinRM authentication succeeded.",
                "confidence": "High",
                "impact": "Credentialed Windows auditing can be performed in later versions.",
                "recommendation": "Use least-privilege accounts.",
                "verification": "Re-run VulScan.",
                "limitation": "Authentication success does not indicate vulnerability.",
                "source": "windows_audit",
                "risk_score": 0,
                "risk_label": "Informational",
                "fix_priority": "Document and monitor",
                "created_at": "2026-05-16T10:00:00+00:00",
            }
        ],
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
            "winrm_auth_status": "authenticated",
            "winrm_authenticated": True,
            "winrm_endpoint_used": "http://127.0.0.1:5985/wsman",
            "windows_host_info_collected": True,
            "windows_host_info": {
                "hostname": "LABHOST",
                "os_caption": "Microsoft Windows Server 2022 Standard",
                "os_version": "10.0.20348",
                "os_build": "20348",
                "domain": "WORKGROUP",
                "workgroup": "",
                "powershell_version": "5.1",
            },
            "windows_security_status_checked": True,
            "windows_security_status": {
                "firewall_profiles": [{"name": "Domain", "enabled": "True"}],
                "defender_service": {"status": "Running", "start_type": "Automatic"},
                "defender_status": {"real_time_protection_enabled": "True"},
                "security_status_limitations": [],
            },
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
                "limitations": [],
                "duration_seconds": 0.2,
                "enabled_by_profile": True,
                "enabled_by_manual_flag": False,
                "skipped_reason": "",
            }
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

    path = save_json_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )

    report = json.loads(path.read_text(encoding="utf-8"))

    assert report["credentialed_audits"][0]["source"] == "ssh_audit"
    assert report["credentialed_audits"][1]["source"] == "windows_audit"
    assert report["windows_audit_summary"]["winrm_auth_status"] == "authenticated"
    assert report["windows_audit_summary"]["windows_host_info"]["hostname"] == "LABHOST"
    assert report["windows_audit_summary"]["windows_security_status"]["defender_service"]["status"] == "Running"
    assert report["windows_audit_summary"]["windows_audit_profile"] == "standard"
    assert report["windows_audit_sections"][0]["section_id"] == "windows_security_status"
    assert report["windows_audit_sections"][0]["enabled_by_profile"] is True
    assert report["findings"][0]["title"] == "SSH Login Successful"


def test_json_report_redacts_windows_evidence_secrets(tmp_path) -> None:
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
                "evidence_details": {"source": "unit", "observed_value": "Authorization: Bearer fake-token"},
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
        "windows_audit_summary": {"enabled": True, "status": "success", "safe_detail": "pwd=HiddenValue"},
        "windows_audit_sections": [],
        "credentialed_audits": [],
    }

    path = save_json_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )

    serialized = path.read_text(encoding="utf-8")
    assert "Secret123" not in serialized
    assert "fake-token" not in serialized
    assert "HiddenValue" not in serialized


def test_json_report_includes_windows_demo_notice_and_sections(tmp_path) -> None:
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

    path = save_json_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )
    report = json.loads(path.read_text(encoding="utf-8"))

    assert report["demo_mode"] is True
    assert report["demo_notice"] == DEMO_NOTICE
    assert report["windows_audit_sections"]
    assert report["windows_audit_summary"]["demo_mode"] is True
    assert all("risk_score" in finding for finding in report["findings"])


def test_json_report_includes_web_dast_fields(tmp_path) -> None:
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
                "title": "Web Crawl Completed",
                "severity": "Informational",
                "category": "Web DAST",
                "affected_host": None,
                "affected_port": None,
                "affected_url": "https://example.test/",
                "service": "http",
                "evidence": "Crawler visited 1 pages and discovered 1 forms.",
                "confidence": "High",
                "impact": "Crawl results support review.",
                "recommendation": "Review discovered pages and forms.",
                "verification": "Review the report.",
                "limitation": "Forms are not submitted.",
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
            "sections_enabled": ["web_crawler", "web_headers"],
            "sections_completed": ["web_crawler", "web_headers"],
            "sections_partial": [],
            "sections_failed": [],
            "total_duration_seconds": 0.2,
            "total_requests": 1,
            "pages_crawled": 1,
            "forms_discovered": 1,
            "cookies_observed": 0,
            "sitemap_urls_found": 0,
            "robots_found": "unknown",
            "total_web_findings": 1,
            "highest_web_risk_score": 0,
            "highest_web_risk_label": "Informational",
            "passive_risk_rating": "Informational",
            "recommended_next_steps": ["Review and implement missing security headers."],
            "limitations": ["Passive only."],
        },
        "web_dast_sections": [
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
            }
        ],
        "ssh_audit": {"enabled": False, "status": "skipped"},
        "ssh_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_sections": [],
        "credentialed_audits": [],
        "web_scan_summary": {
            "enabled": True,
            "start_url": "https://example.test/",
            "normalized_start_url": "https://example.test/",
            "allowed_host": "example.test",
            "max_pages": 20,
            "max_depth": 2,
            "pages_crawled": 1,
            "pages_skipped": 0,
            "unique_internal_links": 0,
            "unique_external_links": 0,
            "forms_discovered": 1,
            "password_forms_discovered": 1,
            "file_upload_forms_discovered": 0,
            "errors_count": 0,
            "duration_seconds": 0.2,
            "limitations": ["GET-only crawler foundation."],
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
        "web_header_results": [
            {
                "url": "https://example.test/",
                "status_code": 200,
                "headers_checked": ["Content-Security-Policy"],
                "missing_headers": ["Content-Security-Policy"],
                "disclosure_headers": [],
                "cookie_issues": [],
            }
        ],
        "crawled_pages": [
            {
                "url": "https://example.test/",
                "method": "GET",
                "status_code": 200,
                "content_type": "text/html",
                "title": "Home",
                "depth": 0,
                "response_time_seconds": 0.01,
                "links_found_count": 0,
                "forms_found_count": 1,
                "internal_links": [],
                "external_links": [],
                "forms": [],
            }
        ],
        "discovered_forms": [
            {
                "page_url": "https://example.test/",
                "method": "POST",
                "action": "https://example.test/login",
                "input_names": ["password"],
                "input_types": ["password"],
                "has_password_field": True,
                "has_file_upload": False,
            }
        ],
    }

    path = save_json_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )
    report = json.loads(path.read_text(encoding="utf-8"))

    assert report["web_scan_summary"]["enabled"] is True
    assert report["web_scan_summary"]["allowed_host"] == "example.test"
    assert report["crawled_pages"][0]["title"] == "Home"
    assert report["discovered_forms"][0]["has_password_field"] is True
    assert report["web_findings"][0]["source"] == "web_crawler"
    assert report["web_dast_summary"]["mode"] == "passive"
    assert report["web_dast_sections"][0]["section_id"] == "web_headers"
    assert report["web_header_summary"]["missing_header_counts"]["Content-Security-Policy"] == 1
    assert report["web_header_results"][0]["missing_headers"] == ["Content-Security-Policy"]
    assert report["summary"]["total_web_findings"] == 1


def test_json_report_includes_vulnerability_intelligence_sections(tmp_path) -> None:
    scan_result = {
        "host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "scan_mode": "safe",
        "duration_seconds": 0.1,
        "open_ports": [],
        "software_inventory": {
            "items": [
                {
                    "asset": "127.0.0.1",
                    "host": "127.0.0.1",
                    "port": 22,
                    "protocol": "tcp",
                    "service_name": "ssh",
                    "product": None,
                    "version": None,
                    "source": "service_detect",
                    "evidence": "TCP connection successful",
                    "confidence": "Medium",
                    "metadata": {},
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
                    "title": "SSH",
                    "matched_item": {"service_name": "ssh", "product": "openssh", "version": "8.9p1", "port": 22},
                    "match_status": "matched",
                    "match_confidence": "Medium",
                    "version_condition": {"operator": "version_less_than", "value": "9.6", "display": "less than 9.6"},
                    "fixed_version": "9.6",
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
                    "severity": "High",
                    "match_status": "matched",
                    "match_confidence": "High",
                    "exploit_available": False,
                }
            ],
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

    path = save_json_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )
    report = json.loads(path.read_text(encoding="utf-8"))

    assert report["software_inventory"]["total_items"] == 1
    assert report["vulnerability_intelligence"]["matches_found"] == 1
    assert report["vulnerability_intelligence"]["matches"][0]["match_status"] == "matched"
    assert report["vulnerability_intelligence"]["matches"][0]["version_condition"]["operator"] == "version_less_than"
    assert report["vulnerability_intelligence"]["cve_feed_matches_found"] == 1
    assert report["vulnerability_intelligence"]["cve_feed_matches"][0]["cve"] == "LOCAL-CVE-DEMO-0001"
    assert report["summary"]["vulnerability_intelligence_matches"] == 1
    assert report["summary"]["vulnerability_intelligence_version_matches"] == 1
    assert report["summary"]["vulnerability_intelligence_cve_feed_matches"] == 1
