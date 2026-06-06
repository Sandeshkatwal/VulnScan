from scanner.component_exposure import (
    assess_build_artifact_indicators,
    assess_component_version_exposure,
    assess_dependency_metadata_exposure,
    assess_javascript_library_hints,
    assess_third_party_script_indicators,
)


def test_detects_javascript_library_hints_and_versions() -> None:
    evidence = assess_javascript_library_hints(
        [
            "https://cdn.example.test/jquery-3.6.0.min.js",
            "/assets/bootstrap@5.3.0/dist/js/bootstrap.min.js",
            "/static/react/18.2.0/react.production.min.js",
            "/static/vue.global.js",
        ]
    )
    names = {item["component_name"] for item in evidence}
    assert {"jquery", "bootstrap", "react", "vue"} <= names
    jquery = next(item for item in evidence if item["component_name"] == "jquery")
    assert jquery["component_version"] == "3.6.0"
    assert jquery["evidence_strength"] == "weak_indicator"


def test_detects_server_headers_and_generator_meta() -> None:
    evidence = assess_component_version_exposure(
        {"Server": "nginx/1.24.0", "X-Powered-By": "Express/4.18.2"},
        '<meta name="generator" content="WordPress 6.4.2">',
        [],
    )
    components = {item["component_name"].lower() for item in evidence}
    assert "nginx" in components
    assert "express" in components
    assert "wordpress" in components
    assert all("does not prove vulnerability" in item["safe_evidence_summary"].lower() or item["rule_id"] == "generator_meta_tag_detected" for item in evidence)


def test_detects_dependency_metadata_only_from_discovered_urls() -> None:
    empty = assess_dependency_metadata_exposure([], [])
    evidence = assess_dependency_metadata_exposure(
        endpoint_results=[
            {"url": "http://example.test/package.json"},
            {"url": "http://example.test/package-lock.json"},
            {"url": "http://example.test/yarn.lock"},
            {"url": "http://example.test/composer.lock"},
            {"url": "http://example.test/requirements.txt"},
            {"url": "http://example.test/go.mod"},
        ],
        urls=[],
    )
    assert empty == []
    rules = {item["rule_id"] for item in evidence}
    assert {"package_json_exposed", "package_lock_exposed", "yarn_lock_exposed", "composer_lock_exposed", "requirements_txt_exposed", "go_mod_exposed"} <= rules
    assert all("did not brute-force" in item["safe_evidence_summary"] for item in evidence)


def test_detects_source_maps_without_storing_content_and_third_party_scripts() -> None:
    source_maps = assess_build_artifact_indicators([{"url": "http://example.test/static/app.js.map"}])
    third_party = assess_third_party_script_indicators(["https://cdn.thirdparty.test/lib.js"], target="http://example.test")
    assert source_maps[0]["rule_id"] in {"source_map_detected", "source_map_exposed"}
    assert "content" not in source_maps[0]
    assert third_party[0]["rule_id"] == "third_party_script_manual_review"
    assert third_party[0]["evidence_strength"] == "informational"
