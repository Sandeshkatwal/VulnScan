import pytest

from scanner.role_profiles import RoleProfileError, load_role_profiles, normalise_role_profile, validate_role_profiles


def test_load_sample_roles():
    roles = load_role_profiles("data/roles/sample_roles.json")
    assert {role["role_id"] for role in roles} >= {"standard_user", "admin_user", "tenant_a_user"}


def test_validate_role_profile_without_credentials():
    result = validate_role_profiles([{"role_id": "safe", "role_name": "safe", "role_label": "Safe", "user_type": "custom"}])
    assert result["valid"] is True
    assert result["roles"][0]["role_label"] == "Safe"


def test_reject_role_profile_containing_password_fields():
    with pytest.raises(RoleProfileError):
        normalise_role_profile({"role_id": "bad", "role_name": "bad", "role_label": "Bad", "user_type": "custom", "password": "nope"})


def test_reject_role_profile_containing_raw_token_fields():
    with pytest.raises(RoleProfileError):
        normalise_role_profile({"role_id": "bad", "role_name": "bad", "role_label": "Bad", "user_type": "custom", "session_token": "nope"})
