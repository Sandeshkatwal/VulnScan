from scanner.demo_report_builder import build_demo_report


def test_demo_report_generated_and_safe(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = build_demo_report(markdown=True, html=True, json_export=True)
    report = result["demo_report"]
    text = str(result)

    assert report["safe_testing_statement"]
    assert result["export_paths"]
    assert "secret-demo-token" not in text
    assert "password=" not in text.lower()
    assert "set-cookie:" not in text.lower()

