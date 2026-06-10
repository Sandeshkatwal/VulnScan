from scanner.evidence_timeline import add_evidence_timeline_event, build_evidence_timeline
from scanner.evidence_vault import create_evidence_item, link_evidence_to_finding, save_evidence_item


def test_timeline_events_added_on_create_redaction_and_link(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    item = create_evidence_item(evidence_id="ev1", title="Evidence", safe_summary="Safe")
    event_types = [event["event_type"] for event in item["timeline_events"]]
    assert "created" in event_types
    assert "redacted" in event_types
    save_evidence_item(item)
    linked = link_evidence_to_finding("ev1", "finding-001")
    assert "finding-001" in linked["linked_finding_ids"]
    timeline = build_evidence_timeline("ev1", [linked])
    assert any(event["event_type"] == "linked_to_finding" for event in timeline["timeline_events"])
