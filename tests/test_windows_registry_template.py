import json
from pathlib import Path

from scanner.windows_registry_audit import (
    DEFAULT_WINDOWS_REGISTRY_TEMPLATE,
    WindowsRegistryTemplateError,
    load_registry_template,
)


def _template(check_updates=None):
    check = {
        "id": "WIN-REG-TEST",
        "title": "Test Registry Indicator",
        "enabled": True,
        "hive": "HKLM",
        "path": "SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
        "value_name": "fDenyTSConnections",
        "expected": 1,
        "operator": "equals",
        "severity_if_mismatch": "Low",
        "category": "Windows Registry Security Indicator",
        "recommendation": "Review this indicator.",
        "limitation": "Indicator only.",
    }
    if check_updates:
        check.update(check_updates)
    return {
        "template_name": "Unit Test Template",
        "template_version": "1.0",
        "checks": [check],
    }


def test_default_registry_template_exists_and_loads() -> None:
    assert DEFAULT_WINDOWS_REGISTRY_TEMPLATE.exists()

    template = load_registry_template(DEFAULT_WINDOWS_REGISTRY_TEMPLATE)

    assert template["template_name"] == "Windows Basic Security Indicators"
    assert len(template["checks"]) == 5


def test_registry_template_loading(tmp_path: Path) -> None:
    template_path = tmp_path / "template.json"
    template_path.write_text(json.dumps(_template()), encoding="utf-8")

    template = load_registry_template(template_path)

    assert template["template_name"] == "Unit Test Template"
    assert template["checks"][0].hive == "HKLM"
    assert template["checks"][0].operator == "equals"


def test_registry_template_rejects_unsupported_hive(tmp_path: Path) -> None:
    template_path = tmp_path / "template.json"
    template_path.write_text(json.dumps(_template({"hive": "HKCU"})), encoding="utf-8")

    try:
        load_registry_template(template_path)
    except WindowsRegistryTemplateError as exc:
        assert exc.error_code == "WINDOWS_REGISTRY_UNSUPPORTED_HIVE"
    else:
        raise AssertionError("Expected unsupported hive to raise")


def test_registry_template_rejects_unsupported_operator(tmp_path: Path) -> None:
    template_path = tmp_path / "template.json"
    template_path.write_text(json.dumps(_template({"operator": "contains"})), encoding="utf-8")

    try:
        load_registry_template(template_path)
    except WindowsRegistryTemplateError as exc:
        assert exc.error_code == "WINDOWS_REGISTRY_UNSUPPORTED_OPERATOR"
    else:
        raise AssertionError("Expected unsupported operator to raise")
