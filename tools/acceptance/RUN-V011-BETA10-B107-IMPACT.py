from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel.beta10_operational_impact import measure_operational_impact


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B10-7 operational impact acceptance runner")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        evidence = json.loads(args.evidence.read_text(encoding="utf-8-sig"))
        report = measure_operational_impact(evidence, repeats=args.repeats)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        report = {
            "passed": False,
            "failures": [f"b107_runner:{type(exc).__name__}"],
        }

    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
