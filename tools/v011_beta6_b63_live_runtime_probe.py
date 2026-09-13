from __future__ import annotations

import argparse
import json
from threading import Thread
from time import monotonic, sleep

from sentinel import home_smart_scan as smart
from sentinel import smart_scan_provider_loader as provider_loader


def build_report(*, execute: bool = False, cancel_after_seconds: float = 0.0) -> dict:
    load_result = provider_loader.load_default_provider()
    provider = load_result.provider
    capabilities = dict(provider.capabilities())
    capability_contract = smart.validate_provider_capabilities(provider)
    report = {
        "checkpoint": "B6-3.4-smart-scan-performance-scope",
        "provider_load": load_result.to_dict(),
        "provider_capabilities": capabilities,
        "provider_contract": capability_contract,
        "accepted": bool(
            load_result.accepted
            and capability_contract.get("passed")
            and capability_contract.get("available")
            and capability_contract.get("accepted")
        ),
        "executed": False,
        "cancel_after_seconds": max(0.0, float(cancel_after_seconds or 0.0)),
    }
    if not execute or not report["accepted"]:
        return report

    progress: list[dict] = []
    coordinator = smart.SmartScanCoordinator(provider)
    cancellation = {
        "requested": False,
        "request_accepted": False,
        "requested_after_seconds": max(0.0, float(cancel_after_seconds or 0.0)),
    }

    cancel_thread: Thread | None = None
    if cancel_after_seconds > 0:
        def request_controlled_cancel() -> None:
            deadline = monotonic() + 30.0
            while coordinator.state != smart.STATE_RUNNING and monotonic() < deadline:
                sleep(0.01)
            if coordinator.state != smart.STATE_RUNNING:
                return
            sleep(float(cancel_after_seconds))
            cancellation["requested"] = True
            cancellation["request_accepted"] = bool(coordinator.request_cancel())

        cancel_thread = Thread(
            target=request_controlled_cancel,
            name="BCS-B634-LiveCancelProbe",
            daemon=True,
        )
        cancel_thread.start()

    result = coordinator.run_sync(lambda item: progress.append(item.to_dict()))
    if cancel_thread is not None:
        cancel_thread.join(timeout=2.0)

    report.update(
        {
            "executed": True,
            "result": result.to_dict(),
            "progress": progress,
            "cancellation": cancellation,
            "no_destructive_authority": not (
                result.automatic_quarantine
                or result.automatic_repair
                or result.automatic_destructive_action
            ),
        }
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B6-3.4 pinned runtime Smart Scan performance/scope preflight")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Explicitly run the accepted Smart Scan plan after pinned runtime validation.",
    )
    parser.add_argument(
        "--cancel-after-seconds",
        type=float,
        default=0.0,
        help="For explicit live cancellation acceptance only: request cancellation after the scan reaches RUNNING and this delay elapses.",
    )
    parser.add_argument("--output", default="", help="Optional JSON output path")
    args = parser.parse_args()

    if args.cancel_after_seconds < 0:
        parser.error("--cancel-after-seconds must be >= 0")
    if args.cancel_after_seconds > 0 and not args.execute:
        parser.error("--cancel-after-seconds requires --execute")

    report = build_report(execute=args.execute, cancel_after_seconds=args.cancel_after_seconds)
    text = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True)
    print(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")

    if not report.get("accepted"):
        return 2
    if args.execute:
        state = str((report.get("result") or {}).get("state") or "")
        if state in {smart.STATE_FAILED, smart.STATE_INCOMPLETE}:
            return 3
        if args.cancel_after_seconds > 0:
            cancellation = report.get("cancellation") or {}
            if not cancellation.get("request_accepted") or state != smart.STATE_CANCELLED:
                return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
