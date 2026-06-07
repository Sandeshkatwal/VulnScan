from datetime import datetime

from scanner.authenticated_crawler import authenticated_crawl
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report
from scanner.session_profiles import load_session_profile


def test_authenticated_crawl_json_and_html_reports_redact_auth_material(tmp_path) -> None:
    profile = load_session_profile("data/auth_profiles/sample_session_profile.redacted.json")
    result = authenticated_crawl("http://127.0.0.1:8000/dashboard", profile, {"dry_run": True, "max_pages": 1})
    scan_result = {
        "host": "http://127.0.0.1:8000/dashboard",
        "resolved_ip": "",
        "scan_mode": "authenticated_crawl",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": [],
        **result,
    }
    now = datetime.now()

    json_path = save_json_report(scan_result, "VulScan", "21.1", now, now, reports_dir=tmp_path)
    html_path = save_html_report(scan_result, "VulScan", "21.1", now, now, reports_dir=tmp_path)

    json_text = json_path.read_text(encoding="utf-8")
    html_text = html_path.read_text(encoding="utf-8")
    assert "authenticated_crawl_summary" in json_text
    assert "Authenticated Crawl" in html_text
    assert "Bearer [REDACTED]" not in json_text
    assert "Bearer [REDACTED]" not in html_text
    assert "raw cookies" in html_text.lower()
