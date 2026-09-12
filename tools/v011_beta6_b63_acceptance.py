from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

from PySide6.QtWidgets import QApplication

from sentinel import home_security_model as security_model
from sentinel import home_smart_scan as smart
from sentinel import home_smart_scan_window as ui


class AcceptanceProvider:
    def __init__(self, *, finding: bool = False, incomplete: bool = False) -> None:
        self.finding = finding
        self.incomplete = incomplete
        self.plan_calls = 0
        self.run_calls = 0

    def capabilities(self):
        return {
            "available": True,
            "accepted": True,
            "provider_name": "b63-acceptance-fixture",
            "provider_profile": "b63-acceptance-v1",
            "provider_provenance": "deterministic_acceptance",
            "automatic_quarantine": False,
            "automatic_repair": False,
            "automatic_destructive_action": False,
        }

    def build_plan(self):
        self.plan_calls += 1
        return smart.SmartScanPlan(
            provider_name="b63-acceptance-fixture",
            provider_profile="b63-acceptance-v1",
            provider_provenance="deterministic_acceptance",
            checks=(
                smart.SmartScanCheck("file", "File evidence", "Fixture", True, "acceptance"),
                smart.SmartScanCheck(
                    "behavior", "Behavior evidence", "Fixture", not self.incomplete, "acceptance"
                ),
            ),
        )

    def run(self, plan, progress_callback, cancel_check):
        self.run_calls += 1
        progress_callback(smart.SmartScanProgress(50, 1, 2, "file", "fixture"))
        findings = ()
        if self.finding:
            findings = (
                smart.SmartScanFinding(
                    "acceptance-finding",
                    "Harmless acceptance finding",
                    smart.SEVERITY_HIGH,
                    "fixture",
                    "Deterministic acceptance evidence",
                    "file",
                    evidence={"acceptance": True},
                ),
            )
        results = [
            smart.SmartScanCheckResult(
                "file", smart.CHECK_COMPLETED, "complete", findings=findings, evidence={"file": True}
            )
        ]
        if self.incomplete:
            results.append(
                smart.SmartScanCheckResult(
                    "behavior",
                    smart.CHECK_UNAVAILABLE,
                    "fixture unavailable",
                    evidence={"reason": "acceptance_fixture"},
                )
            )
        else:
            results.append(
                smart.SmartScanCheckResult(
                    "behavior", smart.CHECK_COMPLETED, "complete", evidence={"behavior": True}
                )
            )
        progress_callback(smart.SmartScanProgress(100, 2, 2, "behavior", "done"))
        return smart.SmartScanProviderResult(tuple(results), {"provider": "raw-acceptance"})


def _evidence() -> dict:
    def item(layer_id: str, status: str, verified: bool = False):
        return security_model.LayerEvidence(
            layer_id,
            status,
            verified,
            "acceptance",
            {"acceptance": True},
            "b63_acceptance",
        )

    return {
        security_model.LAYER_MALWARE: item(
            security_model.LAYER_MALWARE, security_model.STATUS_ENGINE_AVAILABLE
        ),
        security_model.LAYER_BEHAVIOR: item(
            security_model.LAYER_BEHAVIOR, security_model.STATUS_ENGINE_AVAILABLE
        ),
        security_model.LAYER_WEB: item(
            security_model.LAYER_WEB, security_model.STATUS_ENGINE_AVAILABLE
        ),
        security_model.LAYER_RECOVERY: item(
            security_model.LAYER_RECOVERY, security_model.STATUS_READY, True
        ),
    }


def _geometry(window: ui.B63SecurityOverviewWindow, width: int, height: int) -> dict:
    app = QApplication.instance() or QApplication([])
    window.resize(width, height)
    window.show()
    app.processEvents()
    window._apply_responsive_layout(force=True)
    app.processEvents()
    window._sync_all_scroll_widths()
    app.processEvents()
    return {
        "outer_hscroll": window.page_scroll.horizontalScrollBar().maximum(),
        "scan_hscroll": window.scan_scroll.horizontalScrollBar().maximum(),
        "page_count": window.stack.count(),
        "sidebar": window.sidebar.width(),
    }


def run_acceptance() -> dict:
    parent = ui.base_ui.self_check()
    contract = smart.validate_b63_safety_contract()

    unavailable = smart.SmartScanCoordinator()
    unavailable_result = unavailable.run_sync()

    clean_provider = AcceptanceProvider()
    clean_coordinator = smart.SmartScanCoordinator(clean_provider)
    progress: list[int] = []
    clean_result = clean_coordinator.run_sync(lambda item: progress.append(item.percent))

    finding_result = smart.SmartScanCoordinator(AcceptanceProvider(finding=True)).run_sync()
    incomplete_result = smart.SmartScanCoordinator(AcceptanceProvider(incomplete=True)).run_sync()

    app = QApplication.instance() or QApplication([])
    default_window = ui.B63SecurityOverviewWindow(status_provider=_evidence)
    enabled_provider = AcceptanceProvider()
    enabled_window = ui.B63SecurityOverviewWindow(
        status_provider=_evidence, smart_scan_provider=enabled_provider
    )
    try:
        default_large = _geometry(default_window, 1600, 980)
        default_tablet = _geometry(default_window, 760, 760)
        enabled_large = _geometry(enabled_window, 1600, 980)

        checks = {
            "parent_b62_green": parent.get("passed") is True,
            "b63_contract_green": contract.get("passed") is True,
            "startup_scan_dispatch_false": contract.get("startup_scan_dispatch") is False,
            "navigation_scan_dispatch_false": contract.get("navigation_scan_dispatch") is False,
            "refresh_scan_dispatch_false": contract.get("refresh_scan_dispatch") is False,
            "no_destructive_authority": (
                contract.get("automatic_quarantine") is False
                and contract.get("automatic_repair") is False
                and contract.get("automatic_destructive_action") is False
                and contract.get("format_authority") is False
                and contract.get("reimage_authority") is False
            ),
            "default_provider_unavailable_truthful": (
                unavailable.is_available() is False
                and unavailable_result.state == smart.STATE_INCOMPLETE
                and unavailable_result.coverage == smart.COVERAGE_INCOMPLETE
            ),
            "clean_requires_complete_coverage": (
                clean_result.state == smart.STATE_COMPLETED_CLEAN
                and clean_result.coverage == smart.COVERAGE_COMPLETE
                and clean_result.completed_checks == clean_result.total_checks == 2
            ),
            "findings_preserved": (
                finding_result.state == smart.STATE_COMPLETED_FINDINGS
                and len(finding_result.findings) == 1
                and finding_result.findings[0].evidence == {"acceptance": True}
            ),
            "incomplete_never_clean": (
                incomplete_result.state == smart.STATE_INCOMPLETE
                and incomplete_result.coverage == smart.COVERAGE_INCOMPLETE
            ),
            "progress_monotonic": progress == sorted(progress) and progress and progress[-1] == 100,
            "default_ui_does_not_enable_fake_scan": (
                default_window.smart_scan_button.isEnabled() is False
                and default_window.sidebar_scan_button.isEnabled() is False
                and default_window.scan_page.quick_scan.isEnabled() is False
            ),
            "accepted_provider_enables_only_smart_scan": (
                enabled_window.smart_scan_button.isEnabled() is True
                and enabled_window.sidebar_scan_button.isEnabled() is True
                and enabled_window.scan_page.quick_scan.isEnabled() is True
                and enabled_window.full_scan_button.isEnabled() is False
                and enabled_window.scan_page.full_scan.isEnabled() is False
            ),
            "ui_construction_is_passive": enabled_provider.plan_calls == 0 and enabled_provider.run_calls == 0,
            "six_page_shell_preserved": default_large["page_count"] == enabled_large["page_count"] == 6,
            "desktop_no_horizontal_overflow": (
                default_large["outer_hscroll"] == 0
                and default_large["scan_hscroll"] == 0
                and enabled_large["outer_hscroll"] == 0
                and enabled_large["scan_hscroll"] == 0
            ),
            "tablet_no_horizontal_overflow": (
                default_tablet["outer_hscroll"] == 0 and default_tablet["scan_hscroll"] == 0
            ),
        }
    finally:
        default_window.close()
        enabled_window.close()
        app.processEvents()

    failures = [name for name, passed in checks.items() if not passed]
    return {
        "schema": smart.SCHEMA,
        "profile": smart.PROFILE,
        "checkpoint": "B6-3-smart-scan-orchestration-foundation",
        "passed": not failures,
        "failures": failures,
        "checks": checks,
        "states": {
            "unavailable": unavailable_result.state,
            "clean": clean_result.state,
            "findings": finding_result.state,
            "incomplete": incomplete_result.state,
        },
        "note": (
            "Deterministic B6-3 orchestration acceptance. It proves explicit/passive Smart Scan behavior, "
            "coverage truth, non-destructive authority and Home integration. The synchronized GitHub tree "
            "does not contain the complete historical live scanner runtime, so real Windows provider acceptance "
            "remains mandatory before B6-3 checkpoint stabilization."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B6-3 deterministic acceptance")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run_acceptance()
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if result["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
