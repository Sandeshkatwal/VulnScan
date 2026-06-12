import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_required_release_docs_exist():
    required = [
        "README.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "docs/release/RELEASE_CHECKLIST.md",
        "docs/release/RELEASE_NOTES_TEMPLATE.md",
        "docs/interview/TALKING_POINTS.md",
        "docs/interview/FAQ.md",
        "docs/diagrams/ARCHITECTURE.md",
    ]
    for item in required:
        assert (ROOT / item).exists(), item


def test_verify_release_script_works():
    result = subprocess.run([sys.executable, "scripts/verify_release.py"], cwd=ROOT, text=True, capture_output=True, check=False)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


def test_generate_project_summary_script_works():
    result = subprocess.run([sys.executable, "scripts/generate_project_summary.py"], cwd=ROOT, text=True, capture_output=True, check=False)

    assert result.returncode == 0
    assert "OWASP-focused" in result.stdout

