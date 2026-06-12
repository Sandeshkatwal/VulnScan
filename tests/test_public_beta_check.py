from scripts.public_beta_check import run_public_beta_check


def test_public_beta_check_returns_readiness_summary() -> None:
    result = run_public_beta_check()
    assert "public_beta_readiness_score" in result
    assert result["label"] in {"Ready for Public Beta", "Almost Ready", "Needs Work", "Blocked"}
    assert isinstance(result["passed_checks"], list)
    assert isinstance(result["blocking_issues"], list)
