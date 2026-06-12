from scanner.demo_mode import build_demo_dataset, demo_dataset_contains_unsafe_values


def test_demo_dataset_contains_no_raw_secrets_and_findings_are_simulated():
    dataset = build_demo_dataset()

    assert dataset["demo_mode"] is True
    assert demo_dataset_contains_unsafe_values(dataset) is False
    assert all("simulated" in finding.get("tags", []) for finding in dataset["findings"])


def test_demo_evidence_redaction_status_passed():
    dataset = build_demo_dataset()
    evidence = dataset["evidence_vault"]["evidence_vault_items"]

    assert evidence
    assert all(item["redaction_status"] == "redacted" for item in evidence)
    assert all(item["secret_detection_status"] == "passed" for item in evidence)

