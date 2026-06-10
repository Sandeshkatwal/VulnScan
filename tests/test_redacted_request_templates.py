from scanner.redacted_request_templates import redact_request_template


def test_redacted_request_template_helper_removes_sensitive_values() -> None:
    template = redact_request_template(
        {
            "headers": {"Authorization": "Bearer raw"},
            "cookies": {"sessionid": "raw"},
            "form_fields": {"password": "raw"},
            "json_body": {"csrf": "raw", "name": "demo"},
        }
    )
    assert "raw" not in str(template)
    assert "Authorization" in template["sensitive_fields_redacted"]
    assert "password" in template["sensitive_fields_redacted"]
