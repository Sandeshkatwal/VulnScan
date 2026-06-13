import json
from pathlib import Path

from typer.testing import CliRunner

from scanner.error_handling import VulScanUserError, safe_path_join, validate_json_file
from scanner.main import app


def test_cli_version_command_exists() -> None:
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0
    assert "22.1.0-beta" in result.output


def test_cli_reports_compose_missing_file_has_friendly_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    result = CliRunner().invoke(app, ["reports", "compose", "--title", "Regression", "--findings-file", str(missing)])
    assert result.exit_code == 1
    assert "Findings file not found" in result.output
    assert "Hint:" in result.output
    assert "Traceback" not in result.output


def test_validate_json_file_reports_invalid_json(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not-json", encoding="utf-8")
    try:
        validate_json_file(broken, "Regression JSON")
    except VulScanUserError as exc:
        assert "not valid JSON" in exc.message
        assert exc.hint and "line" in exc.hint
    else:  # pragma: no cover
        raise AssertionError("Expected VulScanUserError")


def test_safe_path_join_blocks_traversal(tmp_path: Path) -> None:
    try:
        safe_path_join(tmp_path, "..\\outside.txt")
    except VulScanUserError as exc:
        assert "Unsafe path" in exc.message
    else:  # pragma: no cover
        raise AssertionError("Expected unsafe path to be blocked")


def test_validate_json_file_accepts_valid_json(tmp_path: Path) -> None:
    sample = tmp_path / "valid.json"
    sample.write_text(json.dumps({"ok": True}), encoding="utf-8")
    assert validate_json_file(sample, "Sample") == {"ok": True}
