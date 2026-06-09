import pytest

from scanner.permission_matrix import PermissionMatrixError, load_permission_matrix, normalise_permission_action, validate_permission_matrix


def test_load_permission_matrix():
    matrix = load_permission_matrix("data/roles/sample_permission_matrix.json")
    assert matrix["matrix_name"] == "Sample Access-Control Matrix"
    assert matrix["role_action_rules"]


def test_validate_expected_permission_values():
    payload = {"matrix_id": "x", "matrix_name": "x", "target": "local", "role_action_rules": [{"role_id": "standard_user", "action_id": "view", "expected_permission": "not-real"}]}
    result = validate_permission_matrix(payload)
    assert result["valid"] is False
    assert "Unsupported expected_permission" in result["errors"][0]


def test_delete_action_is_destructive():
    action = normalise_permission_action({"action_id": "delete", "action_type": "delete", "http_method": "DELETE", "sensitivity": "critical"})
    assert action["destructive"] is True
    assert action["state_changing"] is True


def test_permission_matrix_rejects_credential_fields():
    with pytest.raises(PermissionMatrixError):
        load_permission_matrix("data/roles/../sample_permission_matrix.json")
