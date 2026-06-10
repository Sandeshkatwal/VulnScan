from scanner.request_template_builder import build_redacted_request_template, detect_destructive_template, detect_state_changing_request


def test_build_redacted_get_request_template() -> None:
    template = build_redacted_request_template(
        {"url": "http://127.0.0.1:8000/users/123?user_id=123", "method": "GET", "headers": {"Authorization": "Bearer secret"}, "cookies": {"sessionid": "secret"}},
        {"parameter_name": "user_id"},
    )
    assert template["method"] == "GET"
    assert template["query_parameters"]["user_id"][0] == "{ORIGINAL_VALUE_REDACTED}"
    assert template["path_parameters"]["id"] == "{ORIGINAL_VALUE_REDACTED}"
    assert template["headers_redacted"]["Authorization"] == "{ORIGINAL_VALUE_REDACTED}"
    assert template["cookies_redacted"] == ["sessionid"]
    assert "secret" not in str(template)


def test_build_redacted_post_template_marked_state_changing() -> None:
    template = build_redacted_request_template(
        {"url": "http://127.0.0.1:8000/profile", "method": "POST", "form_fields": {"csrf_token": "raw", "display_name": "demo"}},
        {"parameter_name": "display_name"},
    )
    assert template["state_changing"] is True
    assert template["blocked_by_default"] is True
    assert template["safe_to_review_manually"] is False
    assert "csrf_token" in template["sensitive_fields_redacted"]
    assert "raw" not in str(template)


def test_detect_destructive_endpoint_and_state_changing() -> None:
    assert detect_state_changing_request({"method": "DELETE"}) is True
    assert detect_destructive_template({"method": "GET", "url_template": "http://127.0.0.1:8000/admin/delete-user"}) is True


def test_redacts_bearer_cookie_and_token_values() -> None:
    template = build_redacted_request_template(
        {
            "url": "http://127.0.0.1:8000/auth/callback?state=abc&token=def",
            "headers": {"Authorization": "Bearer raw-token"},
            "cookies": "sessionid=raw-cookie; theme=light",
            "json_body": {"token": "raw", "nested": {"nonce": "raw2"}},
        },
        {"parameter_name": "state"},
    )
    assert "raw-token" not in str(template)
    assert "raw-cookie" not in str(template)
    assert "raw2" not in str(template)
    assert template["query_parameters"]["state"][0] == "{ORIGINAL_VALUE_REDACTED}"
    assert template["query_parameters"]["token"][0] == "{ORIGINAL_VALUE_REDACTED}"
