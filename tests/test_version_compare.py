from scanner.vuln_intel import compare_versions, parse_version


def test_compare_simple_versions_correctly() -> None:
    assert compare_versions("8.9", "9.6") == -1
    assert compare_versions("9.6", "9.6") == 0
    assert compare_versions("10.0.22631", "9.6") == 1


def test_compare_versions_with_suffix() -> None:
    assert parse_version("8.9p1") == (8, 9, 1)
    assert compare_versions("8.9p1", "9.6") == -1


def test_invalid_version_is_safe() -> None:
    assert parse_version("not-a-version") is None
    assert compare_versions("not-a-version", "9.6") is None
