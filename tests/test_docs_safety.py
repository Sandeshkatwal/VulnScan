import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_readme_contains_safety_and_demo_instructions_without_secrets():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Authorised Security Assessment" in readme
    assert "Portfolio Demo Mode" in readme
    assert "demo generate --json" in readme
    assert "not an exploitation framework" in readme
    assert "secret-demo-token" not in readme
    assert "password=" not in readme.lower()


def test_demo_safety_script_works():
    result = subprocess.run([sys.executable, "scripts/check_demo_safety.py"], cwd=ROOT, text=True, capture_output=True, check=False)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


def test_docs_link_script_works():
    result = subprocess.run([sys.executable, "scripts/check_docs_links.py"], cwd=ROOT, text=True, capture_output=True, check=False)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout

