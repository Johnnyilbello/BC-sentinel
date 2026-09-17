from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from sentinel import beta10_trust_center as trust
from sentinel import beta10_trust_center_ui as trust_ui


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B10-8 Trust Center acceptance runner")
    parser.add_argument("--impact-report", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--smoke-ui", action="store_true")
    args = parser.parse_args()

    impact_report = None
    if args.impact_report is not None:
        try:
            impact_report = json.loads(args.impact_report.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            result = {"passed": False, "failures": ["b108_runner:impact_report_unreadable"]}
            print(json.dumps(result, indent=2, sort_keys=True))
            return 1

    snapshot = trust.build_trust_center_snapshot(impact_report=impact_report)
    validation = trust.validate_snapshot(snapshot)
    result = {
        "passed": bool(snapshot.get("passed")) and bool(validation.get("passed")),
        "failures": list(dict.fromkeys([*(snapshot.get("failures") or []), *(validation.get("failures") or [])])),
        "profile": snapshot.get("profile"),
        "coverage_summary": snapshot.get("coverage_summary"),
        "verified_scenarios": snapshot.get("verified_scenarios"),
        "scenario_count": len(snapshot.get("scenarios") or []),
        "capability_count": len(snapshot.get("capabilities") or []),
        "impact_status": (snapshot.get("operational_impact") or {}).get("status"),
        "impact_metrics": (snapshot.get("operational_impact") or {}).get("metrics"),
        "presentation_can_promote_coverage": False,
        "general_response_execution_available": bool((snapshot.get("response") or {}).get("general_execution_available")),
        "reversible_response_scope": (snapshot.get("response") or {}).get("reversible_pilot_scope"),
        "new_authority_expanded": bool((snapshot.get("authority") or {}).get("new_authority_expanded")),
        "broad_protection_claimed": bool(snapshot.get("broad_protection_claimed")),
    }

    if args.smoke_ui and result["passed"]:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        smoke = trust_ui.smoke_test_window(snapshot)
        result["ui_smoke"] = smoke
        if smoke.get("passed") is not True:
            result["passed"] = False
            result["failures"].append("b108_runner:ui_smoke_failed")

    payload = json.dumps(result, indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
