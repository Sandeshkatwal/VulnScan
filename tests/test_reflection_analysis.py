from scanner.reflection_analysis import (
    build_reflection_url,
    classify_reflection_context,
    generate_safe_marker,
    is_safe_marker,
    observe_safe_reflection,
    snippet_around_marker,
)


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def read(self, _size: int) -> bytes:
        return self.body


def test_safe_marker_contains_only_safe_characters() -> None:
    marker = generate_safe_marker()
    assert marker.startswith("VULSCAN_SAFE_MARKER_")
    assert is_safe_marker(marker)
    assert "script" not in marker.lower()
    assert "'" not in marker and '"' not in marker
    assert "$(" not in marker and "{{" not in marker


def test_safe_reflection_modifies_only_selected_get_parameter() -> None:
    marker = "VULSCAN_SAFE_MARKER_TEST"
    url = build_reflection_url("http://example.test/search?q=old&sort=asc", "q", marker)
    assert url == "http://example.test/search?q=VULSCAN_SAFE_MARKER_TEST&sort=asc"


def test_reflection_context_hints() -> None:
    marker = "VULSCAN_SAFE_MARKER_TEST"
    assert classify_reflection_context(f"<p>{marker}</p>", marker) == "html_text"
    assert classify_reflection_context(f'<input value="{marker}">', marker) == "attribute_like"
    assert classify_reflection_context(f"const value = '{marker}'; window.location = value", marker) == "script_like"
    assert classify_reflection_context(f'{{"q":"{marker}"}}', marker) == "json_like"


def test_observe_safe_reflection_uses_mocked_response_and_stores_snippet_only() -> None:
    captured = {}

    def opener(request, timeout=5):
        captured["url"] = request.full_url
        return FakeResponse(("prefix token=secret " + "A" * 100 + " VULSCAN_SAFE_MARKER_TEST suffix").encode())

    def fake_marker() -> str:
        return "VULSCAN_SAFE_MARKER_TEST"

    import scanner.reflection_analysis as module

    original = module.generate_safe_marker
    module.generate_safe_marker = fake_marker
    try:
        result = observe_safe_reflection("http://example.test/search?q=old&sort=asc", "q", request_delay=0, opener=opener)
    finally:
        module.generate_safe_marker = original

    assert "q=VULSCAN_SAFE_MARKER_TEST" in captured["url"]
    assert "sort=asc" in captured["url"]
    assert result["marker_reflected"] is True
    assert result["full_body_stored"] is False
    assert "secret" not in result["redacted_snippet"]


def test_snippet_redacts_secrets_and_does_not_store_full_body() -> None:
    marker = "VULSCAN_SAFE_MARKER_TEST"
    body = "A" * 1000 + f" token=abc123 {marker} " + "B" * 1000
    snippet = snippet_around_marker(body, marker)
    assert marker in snippet
    assert "abc123" not in snippet
    assert len(snippet) < len(body)
