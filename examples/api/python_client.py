"""Small local client example for the VulScan API.

Run from the project root after starting the local API. The optional API key is
read from VULSCAN_API_KEY and is sent only as an HTTP header.
"""

from __future__ import annotations

import os
import time
from typing import Any

import requests


DEFAULT_BASE_URL = "http://127.0.0.1:8088"


class VulScanClient:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, api_key: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers: dict[str, str] = {}
        if api_key:
            self.headers["X-VulScan-API-Key"] = api_key

    def health(self) -> dict[str, Any]:
        response = requests.get(f"{self.base_url}/health", timeout=10)
        response.raise_for_status()
        return response.json()

    def create_scan(self, target: str = "127.0.0.1") -> dict[str, Any]:
        payload = {
            "target": target,
            "scan_mode": "safe",
            "json_report": True,
            "html_report": False,
            "save_db": True,
            "vuln_intel": False,
            "prioritise": True,
            "fix_first_dashboard": True,
        }
        response = requests.post(f"{self.base_url}/scans", json=payload, headers=self.headers, timeout=10)
        response.raise_for_status()
        return response.json()

    def get_job(self, job_id: str) -> dict[str, Any]:
        response = requests.get(f"{self.base_url}/jobs/{job_id}", headers=self.headers, timeout=10)
        response.raise_for_status()
        return response.json()

    def wait_for_job(self, job_id: str, timeout_seconds: int = 60) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            job = self.get_job(job_id)
            if job.get("status") not in {"queued", "running"}:
                return job
            time.sleep(2)
        raise TimeoutError(f"Timed out waiting for job {job_id}.")

    def get_findings(self, job_id: str) -> dict[str, Any]:
        response = requests.get(
            f"{self.base_url}/jobs/{job_id}/findings",
            params={"limit": 20, "compact": "true"},
            headers=self.headers,
            timeout=10,
        )
        response.raise_for_status()
        return response.json()


def main() -> None:
    client = VulScanClient(api_key=os.environ.get("VULSCAN_API_KEY"))
    print(client.health())
    job = client.create_scan("127.0.0.1")
    job_id = str(job["job_id"])
    print(client.wait_for_job(job_id))
    print(client.get_findings(job_id))


if __name__ == "__main__":
    main()
