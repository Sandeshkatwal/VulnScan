import pytest

from scanner.pagination import PaginationError, apply_filters, apply_sort, build_paginated_response, paginate_items


def test_paginate_items_returns_correct_page() -> None:
    response = paginate_items(list(range(60)), page=2, page_size=10)
    assert response["items"] == list(range(10, 20))
    assert response["page"] == 2


def test_page_size_default_is_25() -> None:
    response = paginate_items(list(range(30)))
    assert response["page_size"] == 25
    assert len(response["items"]) == 25


def test_max_page_size_enforced() -> None:
    response = paginate_items(list(range(150)), page_size=500)
    assert response["page_size"] == 100
    assert response["page_size_capped"] is True


def test_invalid_page_handled_safely() -> None:
    with pytest.raises(PaginationError):
        paginate_items([], page=0)


def test_empty_list_pagination_works() -> None:
    response = paginate_items([])
    assert response["items"] == []
    assert response["total"] == 0
    assert response["total_pages"] == 0


def test_sorting_works() -> None:
    rows = [{"title": "B"}, {"title": "A"}]
    assert apply_sort(rows, "title", "asc")[0]["title"] == "A"


def test_filtering_by_severity_works() -> None:
    rows = [{"severity": "High"}, {"severity": "Low"}]
    assert apply_filters(rows, {"severity": "High"}) == [{"severity": "High"}]


def test_filtering_by_owasp_category_works() -> None:
    rows = [{"owasp_categories": ["A01:2025"]}, {"owasp_categories": ["A07:2025"]}]
    assert apply_filters(rows, {"owasp_category": "A01:2025"}) == [{"owasp_categories": ["A01:2025"]}]


def test_build_paginated_response_includes_model_fields() -> None:
    response = build_paginated_response([{"title": "A"}])
    assert set(
        [
            "items",
            "total",
            "page",
            "page_size",
            "total_pages",
            "has_next",
            "has_previous",
            "next_page",
            "previous_page",
            "sort_by",
            "sort_direction",
            "filters_applied",
        ]
    ).issubset(response)
