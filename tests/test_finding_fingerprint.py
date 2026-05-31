from scanner.finding_fingerprint import (
    build_finding_fingerprint,
    normalise_path_for_fingerprint,
    normalise_url_for_fingerprint,
)


def test_same_url_with_different_parameter_values_creates_same_fingerprint() -> None:
    first = build_finding_fingerprint({"url": "http://127.0.0.1:8000/account?id=123", "issue_type": "idor_candidate", "parameter_names": ["id"]})
    second = build_finding_fingerprint({"url": "http://127.0.0.1:8000/account?id=456", "issue_type": "idor_candidate", "parameter_names": ["id"]})

    assert first["fingerprint_hash"] == second["fingerprint_hash"]
    assert "123" not in str(first)
    assert "456" not in str(second)


def test_numeric_and_uuid_path_segments_are_normalised() -> None:
    assert normalise_path_for_fingerprint("/users/123") == "/users/{id}"
    assert normalise_path_for_fingerprint("/orders/550e8400-e29b-41d4-a716-446655440000") == "/orders/{uuid}"


def test_query_parameter_values_are_not_stored() -> None:
    result = normalise_url_for_fingerprint("HTTPS://Example.COM/account?token=secret-value&id=123#frag")

    assert result["host"] == "example.com"
    assert result["parameter_names"] == ["id", "token"]
    assert "secret-value" not in result["normalised_url"]
    assert "frag" not in result["normalised_url"]


def test_sensitive_parameter_values_are_ignored_in_fingerprint_data() -> None:
    fingerprint = build_finding_fingerprint(
        {
            "url": "http://127.0.0.1:8000/reset?token=demo-secret",
            "issue_type": "sensitive_token_parameter",
            "parameter_names": ["token"],
        }
    )

    assert fingerprint["parameter_names"] == ["token"]
    assert "demo-secret" not in str(fingerprint)


def test_fingerprint_hash_is_stable_across_runs() -> None:
    item = {
        "url": "http://127.0.0.1:8000/api/users/123?b=2&a=1",
        "issue_type": "access_control_candidate",
        "parameter_names": ["b", "a"],
        "source": "endpoint_discovery",
    }

    first = build_finding_fingerprint(item)
    second = build_finding_fingerprint(item)

    assert first["fingerprint_hash"] == second["fingerprint_hash"]
    assert first["path_normalised"] == "/api/users/{id}"
    assert first["parameter_names"] == ["a", "b"]
    assert first["issue_type"] == "access_control"
