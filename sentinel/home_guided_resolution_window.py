from __future__ import annotations

import argparse
import json
import os
import sys

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from sentinel import guided_resolution_action_plan as action_plan
from sentinel import guided_resolution_provider_loader as resolution_provider
from sentinel import home_guided_resolution as guided
from sentinel import home_threat_cards_window as b64
from sentinel import home_smart_scan_window as b63
from sentinel import ui_quality_refinement as ui_quality
from sentinel.home_guided_resolution_ui import B65SmartScanPage

PROFILE = action_plan.PROFILE
WINDOW_TITLE = b63.WINDOW_TITLE


class B65SecurityOverviewWindow(b64.B64SecurityOverviewWindow):
    def __init__(self) -> None:
        # B6-5.1 performs only the fixed, side-effect-free capability probe.
        # B6-5.2 adds only a planning contract; neither checkpoint exposes execution.
        self.guided_resolution_provider_load = resolution_provider.load_default_provider()
        super().__init__()

    def _apply_theme(self) -> None:
        super()._apply_theme()
        app = QApplication.instance()
        if app is not None:
            font = QFont()
            font.setFamilies(["Segoe UI Variable Text", "Segoe UI", "Plus Jakarta Sans"])
            font.setPointSize(10)
            app.setFont(font)
        self.setStyleSheet(self.styleSheet() + ui_quality.quality_stylesheet())

    def _install_b63_scan_surface(self) -> None:
        old_scroll = self.scan_scroll
        old_index = self.stack.indexOf(old_scroll)
        self.stack.removeWidget(old_scroll)
        if old_scroll in self.secondary_scrolls:
            self.secondary_scrolls.remove(old_scroll)
        old_scroll.deleteLater()

        self.scan_page = B65SmartScanPage(
            start_callback=self._start_smart_scan,
            cancel_callback=self._cancel_smart_scan,
            provider_available=self.smart_scan_coordinator.is_available(),
            unavailable_reason=str(self.smart_scan_contract.get("reason") or ""),
        )
        self.scan_scroll = b63.base_ui._PageScroll(self.scan_page)
        self.secondary_scrolls.insert(0, self.scan_scroll)
        self.stack.insertWidget(old_index if old_index >= 0 else 1, self.scan_scroll)
        self._apply_responsive_layout(force=True)


def self_check() -> dict:
    parent = b64.self_check()
    contract = guided.validate_b650_guided_resolution_contract()
    provider_load = resolution_provider.load_default_provider()
    provider_payload = provider_load.to_dict()
    planning_contract = action_plan.validate_b652_planning_contract()
    ui_contract = ui_quality.validate_ui_quality_contract()
    failures: list[str] = []
    if parent.get("passed") is not True:
        failures.append("b64_parent_not_green")
    if contract.get("passed") is not True:
        failures.append("b650_guided_resolution_contract_not_green")
    if contract.get("execution_available") is not False:
        failures.append("b650_execution_authority_exposed")
    if provider_load.loaded is not True or provider_load.accepted is not True:
        failures.append("b651_capability_provider_not_accepted")
    if provider_payload.get("execution_available") is not False:
        failures.append("b651_execution_authority_exposed")
    if provider_payload.get("automatic_action") is not False:
        failures.append("b651_automatic_action_exposed")
    if provider_payload.get("destructive_authority") is not False:
        failures.append("b651_destructive_authority_exposed")
    if planning_contract.get("passed") is not True:
        failures.append("b652_action_plan_contract_not_green")
    if planning_contract.get("execution_authorized") is not False:
        failures.append("b652_execution_authority_exposed")
    if planning_contract.get("journal_write_authority") is not False:
        failures.append("b652_journal_write_authority_exposed")
    if planning_contract.get("rollback_execution_authority") is not False:
        failures.append("b652_rollback_execution_authority_exposed")
    if ui_contract.get("passed") is not True:
        failures.append("ui_quality_contract_not_green")
    return {
        "profile": PROFILE,
        "schema": action_plan.SCHEMA,
        "passed": not failures,
        "failures": failures,
        "parent_b64": parent,
        "guided_resolution_contract": contract,
        "capability_provider": provider_payload,
        "action_plan_contract": planning_contract,
        "ui_quality": ui_contract,
        "window_created": False,
        "startup_scan_dispatch": False,
        "navigation_scan_dispatch": False,
        "refresh_scan_dispatch": False,
        "capability_provider_boundary_verified": provider_load.accepted,
        "remediation_provider_boundary_verified": False,
        "execution_available": False,
        "confirmation_issued": False,
        "journal_write_authority": False,
        "rollback_execution_authority": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_destructive_action": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B6-5.2 planning-only Guided Resolution Home")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--offscreen-smoke", action="store_true")
    args = parser.parse_args(argv)

    if args.self_check and not args.offscreen_smoke:
        payload = self_check()
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if payload["passed"] else 4

    if args.offscreen_smoke:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

    app = QApplication.instance() or QApplication(sys.argv[:1])
    window = B65SecurityOverviewWindow()
    if args.offscreen_smoke:
        window.show()
        app.processEvents()
        provider_payload = window.guided_resolution_provider_load.to_dict()
        planning_contract = action_plan.validate_b652_planning_contract()
        ui_contract = ui_quality.validate_ui_quality_contract()
        payload = {
            "profile": PROFILE,
            "passed": (
                window.stack.count() == 6
                and window.guided_resolution_provider_load.accepted is True
                and provider_payload.get("execution_available") is False
                and provider_payload.get("destructive_authority") is False
                and planning_contract.get("passed") is True
                and planning_contract.get("execution_authorized") is False
                and ui_contract.get("passed") is True
            ),
            "window_title": window.windowTitle(),
            "page_count": window.stack.count(),
            "smart_scan_provider_available": window.smart_scan_coordinator.is_available(),
            "capability_provider": provider_payload,
            "action_plan_contract": planning_contract,
            "ui_quality": ui_contract,
            "startup_scan_dispatch": False,
            "capability_provider_boundary_verified": window.guided_resolution_provider_load.accepted,
            "remediation_provider_boundary_verified": False,
            "execution_available": False,
            "confirmation_issued": False,
            "journal_write_authority": False,
            "rollback_execution_authority": False,
            "automatic_destructive_action": False,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        window.close()
        return 0 if payload["passed"] else 4

    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
