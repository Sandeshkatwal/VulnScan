from scanner.demo_data_loader import load_demo_dataset, save_demo_dataset


def test_load_and_save_demo_dataset(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    paths = save_demo_dataset()
    dataset = load_demo_dataset()

    assert "dashboard_summary" in paths
    assert dataset["dashboard_summary"]["badge"] == "Portfolio Demo Mode — simulated redacted data."
    assert dataset["target"] == "https://demo.local"

