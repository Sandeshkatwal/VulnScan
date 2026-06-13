from scripts.generate_large_demo_dataset import build_large_demo_dataset, write_large_demo_dataset
from scanner.demo_mode import demo_dataset_contains_unsafe_values
from scanner.large_dataset_loader import load_large_demo_dataset


def test_large_demo_dataset_generated_with_simulated_true(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    write_large_demo_dataset(build_large_demo_dataset(5, 8, 2))
    dataset = load_large_demo_dataset()
    assert all(item["simulated"] is True for item in dataset["findings"])
    assert all(item["simulated"] is True for item in dataset["evidence"])


def test_large_demo_dataset_contains_no_secrets(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    write_large_demo_dataset(build_large_demo_dataset(5, 8, 2))
    dataset = load_large_demo_dataset()
    assert demo_dataset_contains_unsafe_values(dataset) is False
