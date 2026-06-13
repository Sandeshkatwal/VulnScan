from scanner.demo_data_loader import load_demo_dataset
from scanner.demo_mode import SAFE_TESTING_STATEMENT, build_demo_dataset
from scanner.demo_report_builder import build_demo_report


def test_demo_mode_safe_statement_says_no_live_requests() -> None:
    assert "No real target was scanned" in SAFE_TESTING_STATEMENT
    assert "no live requests were sent" in SAFE_TESTING_STATEMENT


def test_demo_data_contains_simulated_flags() -> None:
    dataset = build_demo_dataset()
    assert dataset["demo_mode"] is True
    assert all("simulated" in finding.get("tags", []) for finding in dataset["findings"])


def test_demo_report_contains_safe_statement() -> None:
    report = build_demo_report(markdown=True, html=True, json_export=True)
    assert report["demo_report"]["safe_testing_statement"]
    assert "authorised testing only" in report["demo_report"]["safe_testing_statement"].lower()
    assert report["simulated"] is True


def test_demo_dataset_loads_without_api() -> None:
    dataset = load_demo_dataset()
    assert dataset["safe_testing_statement"] == SAFE_TESTING_STATEMENT
