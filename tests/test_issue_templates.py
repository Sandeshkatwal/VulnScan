from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_issue_templates_exist() -> None:
    assert (ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml").is_file()
    assert (ROOT / ".github" / "ISSUE_TEMPLATE" / "feature_request.yml").is_file()
    assert (ROOT / ".github" / "ISSUE_TEMPLATE" / "documentation_issue.yml").is_file()


def test_pull_request_template_exists() -> None:
    assert (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").is_file()


def test_beta_docs_exist_and_readme_mentions_beta_safety() -> None:
    assert (ROOT / "docs" / "beta" / "KNOWN_LIMITATIONS.md").is_file()
    assert (ROOT / "docs" / "beta" / "PUBLIC_BETA_NOTES.md").is_file()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Public Beta" in readme
    assert "Authorised Testing Only" in readme or "authorised testing" in readme.lower()
