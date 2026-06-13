from scanner.version import VERSION, version_metadata


def test_version_is_public_beta() -> None:
    assert VERSION == "22.1.0-beta"
    metadata = version_metadata()
    assert metadata["app_name"] == "VulScan"
    assert metadata["release_channel"] == "public-beta"
    assert metadata["authorised_use_only"] is True
