from __future__ import annotations

import argparse
import json
import os
import sys
import warnings

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication, QMessageBox, QPushButton

from sentinel import guided_resolution_action_plan as action_plan
from sentinel import guided_resolution_confirmation as confirmation
from sentinel import guided_resolution_execution_gate as execution_gate
from sentinel import guided_resolution_fixture_execution as fixture_execution
from sentinel import guided_resolution_provider_loader as resolution_provider
from sentinel import guided_resolution_real_file_execution as real_file_execution
from sentinel import home_guided_resolution as guided
from sentinel import home_quarantine as b658
from sentinel import home_quarantine_integrity as home_quarantine
from sentinel import home_threat_cards_window as b64
from sentinel import home_smart_scan_window as b63
from sentinel import ui_live_polish
from sentinel import ui_quality_refinement as ui_quality
from sentinel.home_quarantine_ui import B657SmartScanPage

PROFILE = home_quarantine.PROFILE
WINDOW_TITLE = b63.WINDOW_TITLE


class B65SecurityOverviewWindow(b64.B64SecurityOverviewWindow):
    def __init__(self) -> None:
        # B6-5.9 keeps the accepted B6-5.8 quarantine/restore authority exactly
        # as-is and adds only read-only visibility for degraded persistent state.
        self.guided_resolution_provider_load = resolution_provider.load_default_provider()
        self.home_quarantine_controller = home_quarantine.HomeQuarantineController(
            self.guided_resolution_provider_load
        )

        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=r"libpyside: Failed to disconnect.*",
                category=RuntimeWarning,
            )
            super().__init__()

        # Verified rows keep the explicit restore action. Degraded rows are also
        # rendered, but contain no restore_key and therefore receive no button.
        self.quarantine_page.rows_provider = self.home_quarantine_controller.quarantine_rows
        self._refresh_quarantine_rows()
        ui_live_polish.apply_window_live_polish(self)

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

        self.scan_page = B657SmartScanPage(
            start_callback=self._start_smart_scan,
            cancel_callback=self._cancel_smart_scan,
            provider_available=self.smart_scan_coordinator.is_available(),
            unavailable_reason=str(self.smart_scan_contract.get("reason") or ""),
            quarantine_controller=self.home_quarantine_controller,
            quarantine_changed_callback=self._refresh_quarantine_rows,
        )
        self.scan_scroll = b63.base_ui._PageScroll(self.scan_page)
        self.secondary_scrolls.insert(0, self.scan_scroll)
        self.stack.insertWidget(old_index if old_index >= 0 else 1, self.scan_scroll)
        self._apply_responsive_layout(force=True)

    def _install_quarantine_restore_actions(self) -> None:
        rows = self.home_quarantine_controller.quarantine_rows()
        for row_index, payload in enumerate(rows):
            key = str(payload.get("restore_key") or "")
            if not key:
                # B6-5.9 degraded integrity rows deliberately have no restore
                # key, so no mutating control can be attached to them.
                continue
            button = QPushButton("Ripristina file")
            button.setObjectName("SecondaryAction")
            button.setAccessibleName(
                f"Ripristina {payload.get('file') or 'il file'} dalla quarantena"
            )
            button.setToolTip(
                "Ripristina il file nella posizione originale dopo una nuova verifica SHA-256."
            )
            button.clicked.connect(
                lambda checked=False, finding_id=key: self._restore_from_quarantine_page(
                    finding_id
                )
            )
            self.quarantine_page.table.setCellWidget(row_index, 6, button)

    def _restore_from_quarantine_page(self, finding_id: str) -> None:
        answer = QMessageBox.question(
            self,
            "Ripristina file",
            "Vuoi ripristinare questo file nella posizione originale?\n\n"
            "BC Sentinel verificherà nuovamente quarantena, snapshot e SHA-256 "
            "prima di eseguire il ripristino.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        try:
            rollback = self.home_quarantine_controller.rollback(finding_id)
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Ripristino non eseguito",
                "BC Sentinel ha bloccato il ripristino perché lo stato persistente "
                f"non ha superato tutte le verifiche.\n\nDettaglio: {exc}",
            )
            self._refresh_quarantine_rows()
            return

        self._refresh_quarantine_rows()
        QMessageBox.information(
            self,
            "File ripristinato",
            "Ripristino completato e SHA-256 verificato."
            if rollback.state == "RESTORED_VERIFIED"
            else "Ripristino completato.",
        )

    def _refresh_quarantine_rows(self) -> None:
        if hasattr(self, "quarantine_page"):
            self.quarantine_page.refresh()
            self._install_quarantine_restore_actions()


def self_check() -> dict:
    parent = b64.self_check()
    contract = guided.validate_b650_guided_resolution_contract()
    provider_load = resolution_provider.load_default_provider()
    provider_payload = provider_load.to_dict()
    planning_contract = action_plan.validate_b652_planning_contract()
    confirmation_contract = confirmation.validate_b653_confirmation_contract()
    execution_contract = execution_gate.validate_b654_execution_gate_contract()
    fixture_execution_contract = fixture_execution.validate_b655_fixture_execution_contract()
    real_file_contract = real_file_execution.validate_b656_contract()
    b657_contract = b658.validate_b657_contract()
    b658_contract = b658.validate_b658_contract()
    b659_contract = home_quarantine.validate_b659_contract()
    ui_contract = ui_quality.validate_ui_quality_contract()
    live_ui_contract = ui_live_polish.validate_live_ui_polish_contract()
    failures: list[str] = []

    checks = {
        "b64_parent_green": parent.get("passed") is True,
        "b650_guided_resolution_green": contract.get("passed") is True,
        "b651_passive_provider_accepted": provider_load.loaded is True and provider_load.accepted is True,
        "b651_execution_still_disabled": provider_payload.get("execution_available") is False,
        "b652_planning_green": planning_contract.get("passed") is True,
        "b653_confirmation_green": confirmation_contract.get("passed") is True,
        "b653_confirmation_not_execution": confirmation_contract.get("confirmation_is_execution_authority") is False,
        "b654_execution_gate_green": execution_contract.get("passed") is True,
        "b654_broad_execution_disabled": execution_contract.get("execution_api") is False,
        "b655_fixture_green": fixture_execution_contract.get("passed") is True,
        "b655_home_execution_disabled": fixture_execution_contract.get("live_home_execution_authorized") is False,
        "b656_real_file_green": real_file_contract.get("passed") is True,
        "b656_general_home_execution_disabled": real_file_contract.get("live_home_execution_authorized") is False,
        "b657_home_quarantine_green": b657_contract.get("passed") is True,
        "b658_persistent_restore_green": b658_contract.get("passed") is True,
        "b658_persistent_restore_enabled": b658_contract.get("persistent_restore_after_restart") is True,
        "b658_restart_discovery_read_only": b658_contract.get("restart_discovery_read_only") is True,
        "b658_quarantine_page_restore": b658_contract.get("quarantine_page_restore_action_available") is True,
        "b659_integrity_visibility_green": b659_contract.get("passed") is True,
        "b659_degraded_state_visible": b659_contract.get("degraded_persistent_state_visible") is True,
        "b659_integrity_audit_read_only": b659_contract.get("integrity_audit_read_only") is True,
        "b659_blocked_rows_not_actionable": b659_contract.get("blocked_rows_have_no_restore_key") is True,
        "b659_general_home_execution_disabled": b659_contract.get("general_home_execution_authorized") is False,
        "ui_quality_green": ui_contract.get("passed") is True,
        "ui_live_polish_green": live_ui_contract.get("passed") is True,
    }
    failures.extend(name for name, passed in checks.items() if not passed)

    return {
        "profile": PROFILE,
        "schema": home_quarantine.SCHEMA,
        "passed": not failures,
        "failures": failures,
        "checks": checks,
        "parent_b64": parent,
        "guided_resolution_contract": contract,
        "capability_provider": provider_payload,
        "action_plan_contract": planning_contract,
        "confirmation_contract": confirmation_contract,
        "execution_gate_contract": execution_contract,
        "fixture_execution_contract": fixture_execution_contract,
        "real_file_execution_contract": real_file_contract,
        "b657_home_quarantine_contract": b657_contract,
        "b658_home_quarantine_contract": b658_contract,
        "b659_quarantine_integrity_contract": b659_contract,
        "ui_quality": ui_contract,
        "ui_live_polish": live_ui_contract,
        "window_created": False,
        "startup_scan_dispatch": False,
        "navigation_scan_dispatch": False,
        "refresh_scan_dispatch": False,
        "capability_provider_boundary_verified": provider_load.accepted,
        # General remediation remains closed. B6-5.9 adds visibility only; it
        # does not open a new execution or destructive action class.
        "remediation_provider_boundary_verified": False,
        "execution_available": False,
        "live_home_execution_authorized": False,
        "home_quarantine_action_available": True,
        "live_home_quarantine_authorized": True,
        "persistent_restore_after_restart": True,
        "degraded_persistent_state_visible": True,
        "confirmation_issued": False,
        "confirmation_is_execution_authority": False,
        "execution_nonce_issued": False,
        "journal_write_authority": False,
        "rollback_execution_authority": False,
        "automatic_cleanup": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_destructive_action": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="BC Sentinel B6-5.9 quarantine integrity visibility"
    )
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
        payload = self_check()
        payload.update(
            {
                "window_created": True,
                "window_title": window.windowTitle(),
                "page_count": window.stack.count(),
                "scan_page_b657": isinstance(window.scan_page, B657SmartScanPage),
                "quarantine_rows_provider_connected": callable(window.quarantine_page.rows_provider),
                "persistent_restore_after_restart": True,
                "degraded_persistent_state_visible": True,
                "startup_scan_dispatch": False,
                "automatic_quarantine": False,
            }
        )
        payload["passed"] = bool(
            payload["passed"]
            and window.stack.count() == 6
            and isinstance(window.scan_page, B657SmartScanPage)
            and callable(window.quarantine_page.rows_provider)
            and window.refresh_button.property("semanticIcon") == "status_refresh"
            and window.quarantine_page.refresh_button.property("semanticIcon") == "list_refresh"
        )
        print(json.dumps(payload, indent=2, sort_keys=True))
        window.close()
        return 0 if payload["passed"] else 4

    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
