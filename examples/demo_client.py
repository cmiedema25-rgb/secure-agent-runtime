"""Demonstrate capability-scoped execution against a running runtime API."""

from __future__ import annotations

import sys

import httpx

BASE_URL = "http://127.0.0.1:8000"


def main() -> int:
    with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
        session_response = client.post(
            "/v1/sessions",
            json={"capabilities": ["math.add", "text.word_count"]},
        )
        session_response.raise_for_status()
        session = session_response.json()
        session_id = session["session_id"]

        allowed = client.post(
            "/v1/execute",
            json={
                "session_id": session_id,
                "tool": "math.add",
                "arguments": {"a": 20, "b": 22},
            },
        )
        allowed.raise_for_status()
        print("allowed:", allowed.json())

        denied = client.post(
            "/v1/execute",
            json={
                "session_id": session_id,
                "tool": "text.summarize",
                "arguments": {"text": "This capability was never granted."},
            },
        )
        print("denied status:", denied.status_code)
        print("denied response:", denied.json())

        integrity = client.get("/v1/audit/verify")
        integrity.raise_for_status()
        print("audit:", integrity.json())

        return 0 if allowed.json()["result"] == 42 and denied.status_code == 403 else 1


if __name__ == "__main__":
    sys.exit(main())
