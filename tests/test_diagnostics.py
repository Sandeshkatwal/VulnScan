import json

from scanner.diagnostics import build_diagnostics


def test_diagnostics_does_not_include_environment_secrets() -> None:
    result = build_diagnostics()
    payload = json.dumps(result).lower()
    assert "environment_variables_dumped" in payload
    assert "secret_values_dumped" in payload
    assert "vulscan_api_key" not in payload
    assert "authorization" not in payload
    assert result["summary"]["status"] in {"pass", "fail"}
