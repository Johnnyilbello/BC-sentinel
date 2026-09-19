from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel import beta12_final_freeze as b129
from sentinel import beta12_product_integration as b128
from sentinel import beta12_product_integration_ui as ui


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--impact-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    impact = json.loads(args.impact_report.read_text(encoding="utf-8-sig"))
    snapshot = b128.build_product_snapshot(impact_report=impact)
    snapshot_validation = b128.validate_snapshot(snapshot)
    if not snapshot.get("passed") or not snapshot_validation.get("passed"):
        print(json.dumps({
            "passed": False,
            "stage": "product_snapshot",
            "snapshot_failures": snapshot.get("failures", []),
            "validation_failures": snapshot_validation.get("failures", []),
        }, indent=2, sort_keys=True))
        return 1

    smoke = ui.smoke_test_window(snapshot)
    report = b129.build_final_report(
        impact_report=impact,
        product_snapshot=snapshot,
        ui_smoke=smoke,
    )

    payload = {
        "snapshot": snapshot,
        "ui_smoke": smoke,
        "final_report": report,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    print(json.dumps({
        "passed": report["passed"],
        "freeze_eligible": report["freeze_eligible"],
        "freeze_evidence_digest": report["freeze_evidence_digest"],
        "coverage_summary": report["coverage_summary"],
        "verified_scenarios": report["verified_scenarios"],
        "operational_metrics": report["operational_metrics"],
        "scenario_count": report["scenario_count"],
        "capability_count": report["capability_count"],
        "trust_center_page_count": report["trust_center_page_count"],
        "trust_center_no_horizontal_overflow": report["trust_center_no_horizontal_overflow"],
        "product_evidence_digest": report["product_evidence_digest"],
        "ui_smoke": smoke,
    }, indent=2, sort_keys=True))
    return 0 if report["passed"] and report["freeze_eligible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
