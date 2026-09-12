from __future__ import annotations

"""B6-3 development Home that adds explicit Smart Scan to the accepted B6-2 shell.

The B6-2 window remains the predecessor regression barrier. This module layers
Smart Scan onto the same Home experience without changing startup behavior or
adding remediation authority.  When no provider is injected by tests/packaging,
the Home uses the fail-closed fixed-module loader from
``smart_scan_provider_loader``. Loading a provider never plans or starts a scan.
"""

import argparse
import json
import os
import sys
from typing import Callable, Mapping

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QApplication

from sentinel import home_security_ui as base_ui
from sentinel import home_smart_scan as smart
from sentinel import smart_scan_provider_loader
from sentinel.home_smart_scan_ui import SmartScanPage
from sentinel.ui_design_system import COLORS, apply_icon

PROFILE = smart.PROFILE
WINDOW_TITLE = base_ui.WINDOW_TITLE


class _SmartScanThread(QThread):
    progress = Signal(object)
    result_ready = Signal(object)
    worker_error = Signal(str)

    def __init__(self, coordinator: smart.SmartScanCoordinator, parent=None) -> None:
        super().__init__(parent)
        self.coordinator = coordinator

    def run(self) -> None:
        try:
            result = self.coordinator.run_sync(lambda item: self.progress.emit(item))
            self.result_ready.emit(result)
        except Exception as exc:  # defensive UI boundary; coordinator already normalizes provider failures
            self.worker_error.emit(f"{type(exc).__name__}: {exc}")


class B63SecurityOverviewWindow(base_ui.SecurityOverviewWindow):
    """Single Home shell with the B6-3 Smart Scan development surface enabled by capability."""

    def __init__(
        self,
        status_provider: Callable[[], Mapping] | None = None,
        smart_scan_provider: smart.SmartScanProvider | None = None,
    ) -> None:
        super().__init__(status_provider=status_provider)

        if smart_scan_provider is None:
            load_result = smart_scan_provider_loader.load_default_provider()
            effective_provider = load_result.provider
            self.smart_scan_provider_load = load_result.to_dict()
        else:
            effective_provider = smart_scan_provider
            capability = smart.validate_provider_capabilities(effective_provider)
            self.smart_scan_provider_load = {
                "loaded": True,
                "accepted": bool(
                    capability.get("passed")
                    and capability.get("available")
                    and capability.get("accepted")
                ),
                "reason": "explicit_provider_injected",
                "module_name": "",
                "factory_name": "",
                "provider_name": str(capability.get("provider_name") or ""),
                "provider_profile": str(capability.get("provider_profile") or ""),
                "provider_provenance": str(capability.get("provider_provenance") or ""),
            }

        self.smart_scan_coordinator = smart.SmartScanCoordinator(effective_provider)
        self.smart_scan_contract = self.smart_scan_coordinator.capabilities()
        self.smart_scan_worker: _SmartScanThread | None = None
        self.last_smart_scan_result: smart.SmartScanResult | None = None
        self._install_b63_scan_surface()
        self._configure_smart_scan_actions()

    def _install_b63_scan_surface(self) -> None:
        old_scroll = self.scan_scroll
        old_index = self.stack.indexOf(old_scroll)
        self.stack.removeWidget(old_scroll)
        if old_scroll in self.secondary_scrolls:
            self.secondary_scrolls.remove(old_scroll)
        old_scroll.deleteLater()

        self.scan_page = SmartScanPage(
            start_callback=self._start_smart_scan,
            cancel_callback=self._cancel_smart_scan,
            provider_available=self.smart_scan_coordinator.is_available(),
            unavailable_reason=str(self.smart_scan_contract.get("reason") or ""),
        )
        self.scan_scroll = base_ui._PageScroll(self.scan_page)
        self.secondary_scrolls.insert(0, self.scan_scroll)
        self.stack.insertWidget(old_index if old_index >= 0 else 1, self.scan_scroll)
        self._apply_responsive_layout(force=True)

    @staticmethod
    def _disconnect(button) -> None:
        try:
            button.clicked.disconnect()
        except (RuntimeError, TypeError):
            pass

    def _configure_smart_scan_actions(self) -> None:
        available = self.smart_scan_coordinator.is_available()
        reason = str(self.smart_scan_contract.get("reason") or "")

        self._disconnect(self.smart_scan_button)
        self.smart_scan_button.clicked.connect(self._start_smart_scan)
        self.smart_scan_button.setEnabled(available)
        self.smart_scan_button.setObjectName("PrimaryAction" if available else "PrimaryDisabled")
        self.smart_scan_button.setAccessibleName(
            "Avvia Smart Scan" if available else "Smart Scan non disponibile"
        )
        self.smart_scan_button.setToolTip(
            "Avvia Smart Scan" if available else reason or "Provider Smart Scan non disponibile"
        )
        apply_icon(
            self.smart_scan_button,
            "bolt",
            "#062016" if available else COLORS["disabled_text"],
            18,
        )
        self.smart_scan_button.style().unpolish(self.smart_scan_button)
        self.smart_scan_button.style().polish(self.smart_scan_button)

        self._disconnect(self.sidebar_scan_button)
        self.sidebar_scan_button.clicked.connect(self._start_smart_scan)
        self.sidebar_scan_button.setEnabled(available)
        self.sidebar_scan_button.setToolTip(
            "Avvia Smart Scan" if available else reason or "Provider Smart Scan non disponibile"
        )

        self.full_scan_button.setEnabled(False)
        self.scan_page.configure_provider(available, reason)

    def _set_scan_launch_enabled(self, enabled: bool) -> None:
        allowed = bool(enabled and self.smart_scan_coordinator.is_available())
        self.smart_scan_button.setEnabled(allowed)
        self.sidebar_scan_button.setEnabled(allowed)
        if self.scan_page is not None:
            self.scan_page.quick_scan.setEnabled(allowed)

    def _start_smart_scan(self) -> None:
        if not self.smart_scan_coordinator.is_available():
            self.statusBar().showMessage(
                "Smart Scan non disponibile: manca un provider live accettato.", 5000
            )
            return
        if self.smart_scan_worker is not None and self.smart_scan_worker.isRunning():
            self.statusBar().showMessage("Smart Scan è già in corso.", 3500)
            return
        if self.smart_scan_coordinator.state == smart.STATE_RUNNING:
            self.statusBar().showMessage("Smart Scan è già in corso.", 3500)
            return

        self.scan_page.set_running()
        self._set_scan_launch_enabled(False)
        self._navigate("Scansione")
        self.statusBar().showMessage("Smart Scan avviata su richiesta dell'utente.")

        worker = _SmartScanThread(self.smart_scan_coordinator, self)
        worker.progress.connect(self._on_smart_scan_progress)
        worker.result_ready.connect(self._on_smart_scan_result)
        worker.worker_error.connect(self._on_smart_scan_worker_error)
        worker.finished.connect(self._on_smart_scan_worker_finished)
        self.smart_scan_worker = worker
        worker.start()

    def _cancel_smart_scan(self) -> None:
        if self.smart_scan_coordinator.request_cancel():
            self.scan_page.cancel_scan.setEnabled(False)
            self.scan_page.task_subtitle.setText(
                "Annullamento richiesto. BC Sentinel sta attendendo che il controllo corrente si arresti in modo sicuro."
            )
            self.statusBar().showMessage("Annullamento Smart Scan richiesto.", 3500)

    def _on_smart_scan_progress(self, progress: smart.SmartScanProgress) -> None:
        self.scan_page.set_progress(progress)

    def _on_smart_scan_result(self, result: smart.SmartScanResult) -> None:
        self.last_smart_scan_result = result
        self.scan_page.set_result(result)
        self.statusBar().showMessage(result.summary, 6000)

    def _on_smart_scan_worker_error(self, message: str) -> None:
        # This is a GUI-worker boundary failure, not a security verdict.
        self.scan_page.task_title.setText("Smart Scan non completata")
        self.scan_page.task_subtitle.setText(
            "Il worker della Home non ha completato il flusso. Nessuna remediation è stata eseguita."
        )
        self.scan_page.coverage_label.setText(f"Errore worker: {message}")
        self.scan_page.coverage_label.setVisible(True)
        self.statusBar().showMessage("Errore del worker Smart Scan.", 6000)

    def _on_smart_scan_worker_finished(self) -> None:
        self._set_scan_launch_enabled(True)
        if self.smart_scan_worker is not None:
            self.smart_scan_worker.deleteLater()
            self.smart_scan_worker = None

    def closeEvent(self, event) -> None:  # noqa: N802
        if self.smart_scan_worker is not None and self.smart_scan_worker.isRunning():
            self.smart_scan_coordinator.request_cancel()
            self.smart_scan_worker.wait(1500)
        super().closeEvent(event)


def self_check() -> dict:
    """Passive B6-3 self-check. It never constructs a window or calls plan/run."""
    parent = base_ui.self_check()
    contract = smart.validate_b63_safety_contract()
    failures: list[str] = []
    if parent.get("passed") is not True:
        failures.append("b62_parent_not_green")
    if contract.get("passed") is not True:
        failures.append("b63_contract_not_green")
    return {
        "profile": PROFILE,
        "schema": smart.SCHEMA,
        "passed": not failures,
        "failures": failures,
        "parent_b62": parent,
        "contract": contract,
        "window_created": False,
        "startup_scan_dispatch": False,
        "navigation_scan_dispatch": False,
        "refresh_scan_dispatch": False,
        "smart_scan_enabled": False,
        "full_scan_enabled": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B6-3 Smart Scan development Home")
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
    window = B63SecurityOverviewWindow()
    if args.offscreen_smoke:
        window.resize(1600, 980)
        window.show()
        app.processEvents()
        window._apply_responsive_layout(force=True)
        app.processEvents()
        window._sync_all_scroll_widths()
        app.processEvents()
        payload = self_check()
        payload.update(
            {
                "window_created": True,
                "window_title": window.windowTitle(),
                "page_count": window.stack.count(),
                "smart_scan_enabled": window.smart_scan_button.isEnabled(),
                "full_scan_enabled": window.full_scan_button.isEnabled(),
                "scan_page_quick_enabled": window.scan_page.quick_scan.isEnabled(),
                "horizontal_scroll_max": window.page_scroll.horizontalScrollBar().maximum(),
                "scan_page_horizontal_scroll_max": window.scan_scroll.horizontalScrollBar().maximum(),
                "provider_available": window.smart_scan_coordinator.is_available(),
                "provider_load": dict(window.smart_scan_provider_load),
            }
        )
        print(json.dumps(payload, indent=2, sort_keys=True))
        window.close()
        return 0 if payload["passed"] else 4

    window.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
