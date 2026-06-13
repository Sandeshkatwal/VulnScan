from scanner.health_check import run_health_checks


def test_health_check_returns_app_version_and_safety_info() -> None:
    result = run_health_checks()
    assert result["app_name"] == "VulScan"
    assert result["version"] == "22.2.0-beta"
    assert result["authorised_use_only"] is True
    assert "warnings" in result
