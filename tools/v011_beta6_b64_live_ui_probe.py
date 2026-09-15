from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel.home_threat_cards_ui import B64SmartScanPage
from sentinel.home_threat_cards_window import B64SecurityOverviewWindow
from tools import v011_beta6_b63_live_ui_probe as b63_probe

CHECKPOINT = "B6-4-live-threat-card-ui"


def run_probe(*, timeout_seconds: float, hold_seconds: float) -> dict:
    observed: dict = {
        "set_result_seen": False,
        "card_count": 0,
        "threat_section_visible": False,
        "per_card_advanced_available": False,
        "per_card_advanced_payload_present": False,
        "severity_matches_result": False,
        "confidence_matches_result": False,
    }

    original_set_result = B64SmartScanPage.set_result

    def instrumented_set_result(self, result):
        original_set_result(self, result)
        observed["set_result_seen"] = True
        observed["card_count"] = len(self.threat_card_widgets)
        observed["threat_section_visible"] = self.threat_section.isVisible()
        if self.threat_card_widgets:
            first = self.threat_card_widgets[0]
            observed["per_card_advanced_available"] = first.advanced_button is not None
            observed["severity_matches_result"] = bool(
                result.findings and first.model.severity == result.findings[0].severity
            )
            observed["confidence_matches_result"] = bool(
                result.findings and first.model.confidence == result.findings[0].confidence
            )
            first.advanced_button.setChecked(True)
            payload = first.advanced_text.toPlainText()
            observed["per_card_advanced_payload_present"] = (
                bool(payload)
                and result.provider_provenance in payload
                and result.findings[0].finding_id in payload
            )

    B64SmartScanPage.set_result = instrumented_set_result
    original_window = b63_probe.B63SecurityOverviewWindow
    b63_probe.B63SecurityOverviewWindow = B64SecurityOverviewWindow
    try:
        evidence = b63_probe.run_probe(
            mode="complete",
            cancel_after_seconds=2.0,
            timeout_seconds=timeout_seconds,
            hold_seconds=hold_seconds,
        )
    finally:
        B64SmartScanPage.set_result = original_set_result
        b63_probe.B63SecurityOverviewWindow = original_window

    base_passed, base_failures = b63_probe.evaluate_evidence(evidence)
    failures = list(base_failures)
    final = dict(evidence.get("final") or {})
    findings_count = int(final.get("findings_count") or 0)

    if not base_passed:
        failures.append("b63_live_ui_contract_not_green")
    if str(final.get("state") or "") != "COMPLETED_FINDINGS":
        failures.append("live_finding_required_for_b64_card_acceptance")
    if findings_count < 1:
        failures.append("no_live_findings_to_render")
    if observed["set_result_seen"] is not True:
        failures.append("b64_set_result_not_observed")
    if observed["card_count"] != findings_count:
        failures.append("threat_card_count_mismatch")
    if observed["threat_section_visible"] is not True:
        failures.append("threat_section_not_visible")
    if observed["per_card_advanced_available"] is not True:
        failures.append("per_card_advanced_control_missing")
    if observed["per_card_advanced_payload_present"] is not True:
        failures.append("per_card_advanced_evidence_missing")
    if observed["severity_matches_result"] is not True:
        failures.append("display_severity_differs_from_result")
    if observed["confidence_matches_result"] is not True:
        failures.append("display_confidence_differs_from_result")

    return {
        "checkpoint": CHECKPOINT,
        "passed": not failures,
        "failures": failures,
        "base_b63_live_ui_passed": base_passed,
        "findings_count": findings_count,
        "state": final.get("state"),
        "coverage": final.get("coverage"),
        "scan_page_horizontal_scroll_max": final.get("scan_page_horizontal_scroll_max"),
        "dashboard_horizontal_scroll_max": final.get("horizontal_scroll_max"),
        "observed": observed,
        "no_destructive_authority": final.get("no_destructive_authority") is True,
        "base_evidence": evidence,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B6-4 live threat card UI acceptance")
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--hold-seconds", type=float, default=2.0)
    parser.add_argument("--output", default="acceptance-v011-beta6-b64-live-ui.json")
    args = parser.parse_args(argv)

    evidence = run_probe(
        timeout_seconds=max(10.0, float(args.timeout_seconds)),
        hold_seconds=max(0.0, float(args.hold_seconds)),
    )
    text = json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True)
    print(text)
    Path(args.output).write_text(text + "\n", encoding="utf-8")
    return 0 if evidence["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
