from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from sentinel.protection_client import ProtectionServiceClient


REQUIRED_MODE = "active_reversible"


def is_ready(status) -> bool:
    return bool(
        isinstance(status, dict)
        and status.get("mode") == REQUIRED_MODE
        and status.get("dns_etw") is True
        and status.get("pid_scoped_dns") is True
        and status.get("shared_ip_guard") is True
        and status.get("mitm_https") is False
        and status.get("auto_block") is False
    )


def run(*, timeout_seconds: float = 10.0, poll_seconds: float = 0.5) -> dict:
    deadline = time.monotonic() + max(0.5, float(timeout_seconds))
    attempts = 0
    last_status = None
    last_error = ""
    while True:
        attempts += 1
        client = ProtectionServiceClient(timeout=2.0)
        try:
            last_status = client.web_status()
            last_error = client.last_error or ""
        except Exception as exc:
            last_status = None
            last_error = str(exc)
        if is_ready(last_status):
            return {
                "product": "BC Sentinel",
                "milestone": "v0.11.0-beta.1",
                "passed": True,
                "attempts": attempts,
                "status": last_status,
                "last_error": last_error,
            }
        if time.monotonic() >= deadline:
            return {
                "product": "BC Sentinel",
                "milestone": "v0.11.0-beta.1",
                "passed": False,
                "attempts": attempts,
                "status": last_status,
                "last_error": last_error,
                "reason": "Protection Service Web/DNS ETW readiness not reached before timeout",
            }
        time.sleep(max(0.1, float(poll_seconds)))


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.11 Beta1 live service readiness gate")
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    parser.add_argument("--poll-seconds", type=float, default=0.5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(timeout_seconds=args.timeout_seconds, poll_seconds=args.poll_seconds)
    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
