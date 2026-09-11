from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import monotonic, sleep, time
from typing import Any

from tools.v011_beta2_b2_live_acceptance import ProductionClient

PROFILE = "v0.11.0-beta.2-service-startup-probe-v1"


def _compact_error(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}"
    return text if len(text) <= 1000 else text[:1000] + "..."


def run(output: Path, *, timeout_seconds: float = 20.0, interval_seconds: float = 0.5) -> int:
    timeout = max(1.0, min(float(timeout_seconds), 120.0))
    interval = max(0.1, min(float(interval_seconds), 5.0))
    client = ProductionClient()
    started_wall = time()
    started = monotonic()
    attempts: list[dict[str, Any]] = []
    ready_status: dict[str, Any] | None = None

    while True:
        elapsed = monotonic() - started
        try:
            status = client.call("edr_status")
            ready_status = dict(status) if isinstance(status, dict) else {"raw": status}
            attempts.append({
                "elapsed_seconds": round(elapsed, 3),
                "ok": True,
                "service_ingested": int((ready_status or {}).get("service_ingested") or 0),
                "service_ingest_errors": int((ready_status or {}).get("service_ingest_errors") or 0),
            })
            break
        except Exception as exc:
            attempts.append({
                "elapsed_seconds": round(elapsed, 3),
                "ok": False,
                "error": _compact_error(exc),
            })
        if elapsed >= timeout:
            break
        sleep(interval)

    unique_errors: list[str] = []
    for item in attempts:
        error = str(item.get("error") or "")
        if error and error not in unique_errors:
            unique_errors.append(error)

    result = {
        "profile": PROFILE,
        "passed": ready_status is not None,
        "diagnostic_only": True,
        "client_surface": getattr(client, "surface", "ProtectionServiceClient.request"),
        "started_at": started_wall,
        "timeout_seconds": timeout,
        "interval_seconds": interval,
        "attempt_count": len(attempts),
        "ready_after_seconds": round(monotonic() - started, 3) if ready_status is not None else None,
        "unique_errors": unique_errors[:20],
        "attempts": attempts[-80:],
        "status": ready_status,
        "diagnosis": (
            "named_pipe_ready" if ready_status is not None
            else "named_pipe_not_available_within_timeout"
        ),
    }
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({
        "profile": PROFILE,
        "passed": result["passed"],
        "attempt_count": result["attempt_count"],
        "ready_after_seconds": result["ready_after_seconds"],
        "diagnosis": result["diagnosis"],
        "last_error": unique_errors[-1] if unique_errors else "",
    }, indent=2, ensure_ascii=False))
    return 0 if ready_status is not None else 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Poll BC Sentinel Protection Service named-pipe readiness with bounded startup diagnostics")
    parser.add_argument("--output", default="acceptance-v011-beta2-b2-service-startup-probe.json")
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument("--interval-seconds", type=float, default=0.5)
    args = parser.parse_args()
    return run(Path(args.output), timeout_seconds=args.timeout_seconds, interval_seconds=args.interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
