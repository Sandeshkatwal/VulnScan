import pytest
from pydantic import ValidationError

from scanner.api_models import ScanRequest


def test_scan_request_model_does_not_include_password_fields() -> None:
    fields = ScanRequest.model_fields if hasattr(ScanRequest, "model_fields") else ScanRequest.__fields__

    assert "password" not in fields
    assert "ssh_password" not in fields
    assert "windows_password" not in fields
    assert "private_key" not in fields
    assert "token" not in fields


@pytest.mark.parametrize(
    "unsafe_field",
    [
        "password",
        "token",
        "secret",
        "private_key",
        "ssh_password",
        "windows_password",
        "api_key",
        "bearer",
        "authorization",
    ],
)
def test_scan_request_model_rejects_unsafe_fields(unsafe_field: str) -> None:
    payload = {"target": "127.0.0.1", unsafe_field: "unit-test-value"}

    with pytest.raises(ValidationError):
        if hasattr(ScanRequest, "model_validate"):
            ScanRequest.model_validate(payload)
        else:
            ScanRequest.parse_obj(payload)
