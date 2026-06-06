from scanner.access_control_candidates import (
    assess_api_access_control_candidates,
    assess_function_level_candidates,
    assess_object_identifier_candidates,
    assess_role_permission_indicators,
    assess_sensitive_resource_candidates,
    assess_tenant_boundary_candidates,
    build_a01_candidate_fingerprint,
    build_a01_evidence_template,
    build_a01_manual_validation_plan,
    normalise_object_id_path,
    score_a01_candidate,
)


def test_detects_object_id_parameters_and_does_not_store_values() -> None:
    evidence = assess_object_identifier_candidates(
        endpoint_results=[{"url": "http://example.test/account?id=123&token=secret"}],
        parameter_results=[
            {"url": "http://example.test/accounts?account_id=999", "parameter_name": "account_id"},
            {"url": "http://example.test/users?user_id=42", "parameter_name": "user_id"},
            {"url": "http://example.test/orders?order_id=777", "parameter_name": "order_id"},
            {"url": "http://example.test/invoices?invoice_id=2024-001", "parameter_name": "invoice_id"},
        ],
    )
    names = {item["affected_parameter"] for item in evidence}
    assert {"id", "account_id", "user_id", "order_id", "invoice_id"} <= names
    serialised = str(evidence)
    assert "999" not in serialised
    assert "777" not in serialised
    assert "secret" not in serialised


def test_normalises_numeric_uuid_and_invoice_object_id_paths() -> None:
    assert normalise_object_id_path("/users/123")["normalised_path"] == "/users/{id}"
    assert normalise_object_id_path("/invoices/2024-001")["normalised_path"] == "/invoices/{id}"
    uuid_path = "/users/550e8400-e29b-41d4-a716-446655440000"
    result = normalise_object_id_path(uuid_path)
    assert result["normalised_path"] == "/users/{uuid}"
    assert result["identifier_kind"] == "uuid"


def test_detects_function_level_admin_management_settings_and_roles() -> None:
    evidence = assess_function_level_candidates(
        [
            {"url": "http://example.test/admin/users"},
            {"url": "http://example.test/management/settings"},
            {"url": "http://example.test/api/roles/update"},
        ]
    )
    rules = {item["rule_id"] for item in evidence}
    assert "admin_endpoint_detected" in rules
    assert "management_endpoint_detected" in rules
    assert "role_endpoint_detected" in rules or "delete_update_action_endpoint_detected" in rules
    assert all("Candidate" in item["safe_evidence_summary"] or "Candidate" in item["limitation"] for item in evidence)


def test_detects_tenant_export_role_and_api_candidates() -> None:
    tenant = assess_tenant_boundary_candidates(
        endpoint_results=[{"url": "http://example.test/orgs/123/workspace"}],
        parameter_results=[{"url": "http://example.test/projects?workspace_id=abc", "parameter_name": "workspace_id"}],
    )
    sensitive = assess_sensitive_resource_candidates(
        endpoint_results=[{"url": "http://example.test/api/reports/export?report_id=1"}],
        parameter_results=[{"url": "http://example.test/api/reports/export?report_id=1", "parameter_name": "report_id"}],
    )
    roles = assess_role_permission_indicators(
        endpoint_results=[],
        parameter_results=[
            {"url": "http://example.test/users?role=admin", "parameter_name": "role"},
            {"url": "http://example.test/users?is_admin=true", "parameter_name": "is_admin"},
            {"url": "http://example.test/users?permission=edit", "parameter_name": "permission"},
        ],
    )
    api = assess_api_access_control_candidates(
        endpoint_results=[{"url": "http://example.test/api/v1/users/123"}, {"url": "http://example.test/graphql"}],
        parameter_results=[],
    )
    assert tenant and tenant[0]["access_control_candidate_type"] == "tenant boundary candidate"
    assert sensitive and sensitive[0]["candidate_score"] >= 70
    assert {item["affected_parameter"] for item in roles} == {"role", "is_admin", "permission"}
    assert any(item["rule_id"] == "rest_object_endpoint_detected" or item["rule_id"] == "api_user_endpoint_detected" for item in api)
    assert any(item["rule_id"] == "graphql_endpoint_access_control_review" for item in api)


def test_candidate_scoring_and_manual_plan_template_and_fingerprint() -> None:
    high = score_a01_candidate(url="http://example.test/api/reports/export?report_id=1", parameter_names=["report_id"])
    static = score_a01_candidate(url="http://example.test/assets/app.js?id=1", parameter_names=["id"])
    assert high >= 70
    assert static < 20
    item = {
        "title": "Object-level authorization candidate: account_id",
        "affected_url": "http://example.test/accounts?account_id",
        "affected_parameter": "account_id",
        "access_control_candidate_type": "object-level authorization candidate",
        "manual_test_plan_id": "horizontal_access_control_review",
    }
    plan = build_a01_manual_validation_plan(item)
    tenant_plan = build_a01_manual_validation_plan({"manual_test_plan_id": "tenant_boundary_review"})
    template = build_a01_evidence_template(item)
    fingerprint = build_a01_candidate_fingerprint({**item, "object_type_hint": "account"})
    assert plan["plan_id"] == "horizontal_access_control_review"
    assert tenant_plan["plan_id"] == "tenant_boundary_review"
    assert "Candidate" in template["why_it_may_matter"] or template["candidate_title"]
    assert fingerprint["owasp_category"] == "a01:2025"
