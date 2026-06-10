from scanner.business_logic_checklists import build_abuse_case_checklist


def test_generate_coupon_webhook_and_quota_checklists() -> None:
    coupon = build_abuse_case_checklist("coupon_discount")
    webhook = build_abuse_case_checklist("notification_webhook")
    quota = build_abuse_case_checklist("quota_rate_limit")
    assert any("stacking" in item["item"] for item in coupon["items"])
    assert any("signature" in item["item"] for item in webhook["items"])
    assert any("limit enforcement" in item["item"] for item in quota["items"])
