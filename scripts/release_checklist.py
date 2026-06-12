"""Print the VulScan release checklist."""

from __future__ import annotations


ITEMS = [
    "Backend tests pass",
    "Dashboard build passes",
    "Demo data safety check passes",
    "Evidence redaction tests pass",
    "No secrets in repository",
    "README links checked",
    "Screenshots updated or placeholders documented",
    "Demo walkthrough tested",
    "GitHub Actions pass",
    "Version tag created",
    "Release notes written",
]


def main() -> int:
    print("VulScan Release Checklist")
    for item in ITEMS:
        print(f"[ ] {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

