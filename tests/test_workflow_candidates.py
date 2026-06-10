from scanner.workflow_candidates import assess_business_logic_workflow_candidates


def _candidate(url: str) -> dict:
    return assess_business_logic_workflow_candidates([{"url": url, "method": "POST"}], [])[0]


def test_detect_checkout_payment_workflow_candidate() -> None:
    candidate = _candidate("http://127.0.0.1:8000/checkout")
    assert candidate["workflow_type"] == "checkout_payment"
    assert candidate["candidate_score"] >= 60


def test_detect_approval_rejection_workflow_candidate() -> None:
    assert _candidate("http://127.0.0.1:8000/api/approve")["workflow_type"] == "approval_rejection"


def test_detect_coupon_discount_workflow_candidate() -> None:
    assert _candidate("http://127.0.0.1:8000/coupon/apply")["workflow_type"] == "coupon_discount"


def test_detect_quota_rate_limit_workflow_candidate() -> None:
    assert _candidate("http://127.0.0.1:8000/api/usage/limit")["workflow_type"] == "quota_rate_limit"


def test_detect_webhook_callback_workflow_candidate() -> None:
    assert _candidate("http://127.0.0.1:8000/webhook/callback")["workflow_type"] == "notification_webhook"


def test_detect_account_lifecycle_and_import_export_candidates() -> None:
    assert _candidate("http://127.0.0.1:8000/invite")["workflow_type"] == "account_lifecycle"
    assert _candidate("http://127.0.0.1:8000/export")["workflow_type"] == "import_export"
