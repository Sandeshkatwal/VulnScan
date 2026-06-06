from pathlib import Path

from scanner.sbom_import import load_sbom, normalise_sbom_components, parse_cyclonedx_sbom, parse_spdx_sbom


def test_loads_and_parses_minimal_cyclonedx_sbom() -> None:
    data = load_sbom(Path("data/sbom/sample_cyclonedx_sbom.json"))
    components = parse_cyclonedx_sbom(data)
    normalised = normalise_sbom_components(components)
    jquery = next(item for item in normalised if item["name"] == "jquery")
    assert jquery["version"] == "3.6.0"
    assert jquery["purl"] == "pkg:npm/jquery@3.6.0"
    assert jquery["cpe"].startswith("cpe:2.3:a:jquery")
    assert jquery["hashes_present"] is True
    assert "abc123" not in str(jquery)


def test_parses_minimal_spdx_sbom() -> None:
    data = load_sbom(Path("data/sbom/sample_spdx_sbom.json"))
    components = parse_spdx_sbom(data)
    bootstrap = next(item for item in components if item["name"] == "bootstrap")
    assert bootstrap["version"] == "5.3.0"
    assert bootstrap["purl"] == "pkg:npm/bootstrap@5.3.0"
