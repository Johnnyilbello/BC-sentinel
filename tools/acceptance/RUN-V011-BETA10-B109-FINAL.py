from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel import beta10_final_acceptance as final


def _load(path: Path, label: str) -> tuple[object | None, list[str]]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")), []
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, [f"b109_runner:{label}_unreadable_or_invalid_json"]


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B10-9 final competitive acceptance composition")
    parser.add_argument("--trust-report", required=True, type=Path)
    parser.add_argument("--pilot-report", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    trust_report, trust_failures = _load(args.trust_report, "trust_report")
    pilot_report, pilot_failures = _load(args.pilot_report, "pilot_report")
    if trust_failures or pilot_failures:
        result = {
            "schema": final.SCHEMA,
            "profile": final.PROFILE,
            "passed": False,
            "freeze_eligible": False,
            "failures": [*trust_failures, *pilot_failures],
            "external_market_superiority_claimed": False,
        }
    else:
        result = final.build_final_report(trust_report, pilot_report)

    payload = json.dumps(result, indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
