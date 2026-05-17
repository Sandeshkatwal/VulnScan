from scanner.web_crawler import WebFormResult, WebPageResult


def test_web_form_result_serializes_to_dict() -> None:
    result = WebFormResult(
        page_url="https://example.test/login",
        method="POST",
        action="https://example.test/login",
        input_names=["username", "password"],
        input_types=["text", "password"],
        has_password_field=True,
        has_file_upload=False,
    )

    serialized = result.to_dict()

    assert serialized["page_url"] == "https://example.test/login"
    assert serialized["has_password_field"] is True


def test_web_page_result_serializes_to_dict_without_raw_body() -> None:
    result = WebPageResult(
        url="https://example.test/",
        method="GET",
        status_code=200,
        content_type="text/html",
        title="Home",
        depth=0,
        response_time_seconds=0.01,
        links_found_count=1,
        forms_found_count=0,
        internal_links=["https://example.test/about"],
        external_links=[],
        forms=[],
    )

    serialized = result.to_dict()

    assert serialized["url"] == "https://example.test/"
    assert "text/html" == serialized["content_type"]
    assert "raw_body" not in serialized
