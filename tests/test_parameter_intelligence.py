from scanner.parameter_intelligence import classify_parameter, is_sensitive_parameter_name


def test_classifies_redirect_parameter() -> None:
    result = classify_parameter("next")
    assert result["parameter_type"] == "redirect"
    assert result["potential_issue"] == "Open Redirect Candidate"


def test_classifies_idor_parameter() -> None:
    result = classify_parameter("account_id")
    assert result["parameter_type"] == "idor"
    assert result["potential_issue"] == "IDOR Candidate"


def test_classifies_path_traversal_parameter() -> None:
    result = classify_parameter("file")
    assert result["parameter_type"] == "path_traversal"
    assert result["potential_issue"] == "Path Traversal Candidate"


def test_classifies_ssrf_parameter() -> None:
    result = classify_parameter("webhook")
    assert result["parameter_type"] == "ssrf"
    assert result["potential_issue"] == "SSRF Candidate"


def test_classifies_debug_parameter() -> None:
    result = classify_parameter("debug")
    assert result["parameter_type"] == "debug_config"
    assert result["potential_issue"] == "Debug/Configuration Exposure Candidate"


def test_identifies_sensitive_parameter_names() -> None:
    assert is_sensitive_parameter_name("token") is True
    assert is_sensitive_parameter_name("password") is True
