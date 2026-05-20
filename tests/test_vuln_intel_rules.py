import json

import pytest

from scanner.vuln_intel import VulnIntelRulesError, load_ruleset, validate_ruleset


def test_loads_valid_local_rules_file(tmp_path) -> None:
    path = tmp_path / "rules.json"
    path.write_text(
        json.dumps(
            {
                "ruleset_name": "Unit Rules",
                "ruleset_version": "1.0",
                "rules": [
                    {
                        "rule_id": "UNIT-001",
                        "title": "SSH",
                        "match": {"service_name": "ssh"},
                        "severity": "Informational",
                        "confidence": "Medium",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    ruleset = load_ruleset(path)

    assert ruleset["ruleset_name"] == "Unit Rules"
    assert ruleset["rules"][0]["rule_id"] == "UNIT-001"


def test_rejects_invalid_rules_file_gracefully(tmp_path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(VulnIntelRulesError) as exc:
        load_ruleset(path)

    assert "not valid JSON" in str(exc.value)


def test_rejects_unsupported_match_fields() -> None:
    with pytest.raises(VulnIntelRulesError) as exc:
        validate_ruleset(
            {
                "ruleset_name": "Bad Rules",
                "ruleset_version": "1.0",
                "rules": [
                    {
                        "rule_id": "BAD-001",
                        "title": "Bad",
                        "match": {"unsafe_field": "value"},
                    }
                ],
            }
        )

    assert "unsupported match field" in str(exc.value)


def test_rejects_empty_ruleset() -> None:
    with pytest.raises(VulnIntelRulesError) as exc:
        validate_ruleset({"ruleset_name": "Empty", "ruleset_version": "1.0", "rules": []})

    assert "at least one rule" in str(exc.value)
