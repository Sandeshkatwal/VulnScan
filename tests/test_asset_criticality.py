import json

from scanner.asset_criticality import (
    load_asset_criticality_context,
    resolve_asset_criticality,
)


def test_load_valid_asset_criticality_context(tmp_path) -> None:
    path = tmp_path / "asset_context.json"
    path.write_text(
        json.dumps(
            {
                "context_name": "Unit Context",
                "context_version": "1.0",
                "assets": [
                    {
                        "asset": "127.0.0.1",
                        "criticality": "low",
                        "business_owner": "Lab",
                        "environment": "local",
                        "tags": ["lab"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    context = load_asset_criticality_context(path)

    assert context["loaded"] is True
    assert context["context_name"] == "Unit Context"
    assert context["asset_index"]["127.0.0.1"]["criticality"] == "low"


def test_missing_file_gracefully_defaults_to_unknown(tmp_path) -> None:
    context = load_asset_criticality_context(tmp_path / "missing.json")

    assert context["loaded"] is False
    assert context["asset_index"] == {}
    assert context["warnings"]


def test_invalid_json_gracefully_defaults_to_unknown(tmp_path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")

    context = load_asset_criticality_context(path)

    assert context["loaded"] is False
    assert context["warnings"]


def test_resolve_exact_ip_target(tmp_path) -> None:
    path = tmp_path / "asset_context.json"
    path.write_text(
        json.dumps({"assets": [{"asset": "127.0.0.1", "criticality": "low"}]}),
        encoding="utf-8",
    )

    resolved = resolve_asset_criticality("127.0.0.1", context=load_asset_criticality_context(path))

    assert resolved["criticality"] == "low"
    assert resolved["criticality_source"] == "file"


def test_resolve_hostname_case_insensitively(tmp_path) -> None:
    path = tmp_path / "asset_context.json"
    path.write_text(
        json.dumps({"assets": [{"asset": "Production-Web", "criticality": "critical"}]}),
        encoding="utf-8",
    )

    resolved = resolve_asset_criticality("production-web", context=load_asset_criticality_context(path))

    assert resolved["criticality"] == "critical"


def test_direct_criticality_overrides_file_mapping(tmp_path) -> None:
    path = tmp_path / "asset_context.json"
    path.write_text(
        json.dumps({"assets": [{"asset": "production-web", "criticality": "low"}]}),
        encoding="utf-8",
    )

    resolved = resolve_asset_criticality(
        "production-web",
        direct_value="critical",
        context=load_asset_criticality_context(path),
    )

    assert resolved["criticality"] == "critical"
    assert resolved["criticality_source"] == "direct"


def test_invalid_criticality_becomes_unknown(tmp_path) -> None:
    path = tmp_path / "asset_context.json"
    path.write_text(
        json.dumps({"assets": [{"asset": "host1", "criticality": "business-critical-plus"}]}),
        encoding="utf-8",
    )

    context = load_asset_criticality_context(path)
    resolved = resolve_asset_criticality("host1", context=context)

    assert resolved["criticality"] == "unknown"
    assert context["warnings"]
