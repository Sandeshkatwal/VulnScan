from scanner.authenticated_evidence import redact_request_for_logs, redact_response_for_storage


def test_redacts_request_auth_headers_and_cookies() -> None:
    result = redact_request_for_logs(
        {
            "method": "GET",
            "url": "http://127.0.0.1:8000/dashboard",
            "headers": {"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz123456", "X-API-Key": "abcdef1234567890"},
            "cookies": {"sessionid": "abcdef1234567890"},
        }
    )

    assert result["headers"]["Authorization"] == "[REDACTED]"
    assert result["headers"]["X-API-Key"] == "[REDACTED]"
    assert result["cookies"]["sessionid"] == "[REDACTED]"
    assert "abcdefghijklmnopqrstuvwxyz" not in str(result)


def test_redacts_response_set_cookie_and_snippet() -> None:
    result = redact_response_for_storage(
        {
            "url": "http://127.0.0.1:8000/dashboard",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {"Set-Cookie": "sessionid=abcdef1234567890"},
            "snippet": "token=abcdefghijklmnopqrstuvwxyz123456",
        }
    )

    assert result["headers"]["Set-Cookie"] == "[REDACTED]"
    assert "abcdefghijklmnopqrstuvwxyz" not in str(result)
