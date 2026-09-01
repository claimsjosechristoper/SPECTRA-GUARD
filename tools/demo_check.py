"""Simple demo validation script for the SPECTRA-GUARD FastAPI dashboard.

This avoids any active RF or network interference. It simply checks the health of
key API endpoints and prints PASS/FAIL for each one.
"""

from __future__ import annotations

import json
import sys
from typing import Any
from urllib import error, request

BASE_URL = "http://127.0.0.1:8000"

ENDPOINTS = [
    "/api/status",
    "/api/rf/spectrum",
    "/api/rf/anomalies",
    "/api/ml/rf/status",
    "/api/ml/rf/predict/latest",
    "/api/firmware/status",
    "/api/network/status",
    "/api/network/risk",
    "/api/device/risk",
    "/api/alerts",
]


def fetch_json(url: str) -> tuple[bool, Any]:
    """Perform a GET request and return whether it succeeded and the parsed payload."""
    try:
        with request.urlopen(url, timeout=15) as response:
            payload = response.read().decode("utf-8")
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                data = payload
            return True, data
    except (error.HTTPError, error.URLError, TimeoutError, OSError) as exc:
        return False, {"error": str(exc)}


def main() -> int:
    """Run the endpoint smoke test and print PASS/FAIL."""
    print(f"Checking SPECTRA-GUARD API at {BASE_URL}")
    for endpoint in ENDPOINTS:
        ok, payload = fetch_json(f"{BASE_URL}{endpoint}")
        if ok:
            status_text = "PASS"
        else:
            status_text = "FAIL"
        print(f"{status_text}: {endpoint}")
        if not ok:
            print(f"  detail: {payload}")
    return 0 if all(fetch_json(f"{BASE_URL}{endpoint}")[0] for endpoint in ENDPOINTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
