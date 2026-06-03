from __future__ import annotations

from scanner.tls_metadata import metadata_from_certificate


def test_tls_metadata_handles_expired_certificate_fixture() -> None:
    cert = {
        "subject": ((("commonName", "expired.example.test"),),),
        "issuer": ((("commonName", "Example CA"),),),
        "notBefore": "Jan 01 00:00:00 2020 GMT",
        "notAfter": "Jan 01 00:00:00 2021 GMT",
    }
    metadata = metadata_from_certificate(cert, hostname="expired.example.test")
    assert metadata["metadata_available"] is True
    assert metadata["expired"] is True


def test_tls_metadata_handles_self_signed_mock() -> None:
    cert = {
        "subject": ((("commonName", "self.example.test"),),),
        "issuer": ((("commonName", "self.example.test"),),),
        "notAfter": "Jan 01 00:00:00 2030 GMT",
    }
    metadata = metadata_from_certificate(cert, hostname="self.example.test")
    assert metadata["self_signed_indicator"] is True


def test_tls_metadata_hostname_mismatch_mock() -> None:
    cert = {
        "subject": ((("commonName", "other.example.test"),),),
        "issuer": ((("commonName", "Example CA"),),),
        "notAfter": "Jan 01 00:00:00 2030 GMT",
    }
    metadata = metadata_from_certificate(cert, hostname="expected.example.test")
    assert metadata["hostname_match"] is False
