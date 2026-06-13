from pathlib import Path

from scripts.check_large_dataset_performance import main as check_main
from scripts.performance_baseline import main as baseline_main


def test_performance_baseline_script_creates_json_output(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert baseline_main() == 0
    assert (Path("reports") / "performance" / "performance_baseline.json").exists()


def test_large_dataset_check_creates_json_output(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert check_main() == 0
    assert (Path("reports") / "performance" / "large_dataset_check.json").exists()
