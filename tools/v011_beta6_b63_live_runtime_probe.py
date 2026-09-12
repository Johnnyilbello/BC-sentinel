from __future__ import annotations

import argparse
import json

from sentinel import home_smart_scan as smart
from sentinel import smart_scan_live_provider as live


def build_report(*, execute: bool = False) -> dict:
    provider = live.create_provider()
    capabilities = dict(provider.capabilities())
    capability_contract = smart.validate_provider_capabilities(provider)
    report = {
        "checkpoint": "B6-3.2-pinned-static-scanner-runtime",
        "provider_capabilities": capabilities,
        "provider_contract": capability_contract,
        "accepted": bool(
            capability_contract.get("passed")
            and capability_contract.get("available")
            and capability_contract.get("accepted")
        ),
        "executed": False,
    }
    if not execute or not report["accepted"]:
        return report

    progress: list[dict] = []
    coordinator = smart.SmartScanCoordinator(provider)
    result = coordinator.run_sync(lambda item: progress.append(item.to_dict()))
    report.update(
        {
            "executed": True,
            "result": result.to_dict(),
            "progress": progress,
            "no_destructive_authority": not (
                result.automatic_quarantine
                or result.automatic_repair
                or result.automatic_destructive_action
            ),
        }
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B6-3.2 pinned full-runtime preflight")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Explicitly run Smart Scan after the pinned runtime passes capability validation.",
    )
    parser.add_argument("--output", default="", help="Optional JSON output path")
    args = parser.parse_args()

    report = build_report(execute=args.execute)
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
