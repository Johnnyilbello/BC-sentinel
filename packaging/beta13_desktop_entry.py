from __future__ import annotations

"""BC Sentinel Beta13 desktop entrypoint for packaged/installed builds."""

import argparse
import json
import os
from pathlib import Path
import sys
from collections.abc import Sequence

from sentinel import beta11_first_run_health as first_run_health
from sentinel import beta12_product_integration as product
from sentinel import beta13_installer as installer
from sentinel import beta13_safe_response as response


PRODUCT_NAME = installer.PRODUCT_NAME
PRODUCT_VERSION = installer.PRODUCT_VERSION
PROFILE = installer.PROFILE


def _notification_store() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    return base / "BCSentinel" / "notifications.json"


def _load_ui_stack():
    from PySide6.QtWidgets import QApplication, QMessageBox
    from sentinel import beta13_response_ui as response_ui
    return QApplication, QMessageBox, response_ui


def _snapshot() -> dict:
    snapshot = product.build_product_snapshot()
    validation = product.validate_snapshot(snapshot)
    if not snapshot["passed"] or not validation["passed"]:
        raise RuntimeError("B13 desktop entrypoint refused invalid product snapshot")
    return snapshot


def _self_check() -> dict:
    failures: list[str] = []
    health_contract = first_run_health.self_check()
    if not health_contract["passed"]:
        failures.extend("first_run:" + item for item in health_contract["failures"])

    installer_contract = installer.self_check()
    if not installer_contract["passed"]:
        failures.extend("installer:" + item for item in installer_contract["failures"])

    snapshot = _snapshot()
    if snapshot["coverage_summary"] != {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}:
        failures.append("product:coverage_mismatch")

    return {
        "passed": not failures,
        "failures": failures,
        "product": PRODUCT_NAME,
        "version": PRODUCT_VERSION,
        "profile": PROFILE,
        "source_checkpoint": installer.SOURCE_CHECKPOINT,
        "source_checkpoint_commit": installer.SOURCE_CHECKPOINT_COMMIT,
        "product_snapshot_valid": True,
        "first_run_health_contract_valid": health_contract["passed"],
        "installer_contract_valid": installer_contract["passed"],
        "notification_store_outside_install_root": True,
        "automatic_quarantine": False,
        "service_or_driver_required": False,
        "network_required_for_startup": False,
        "cloud_required_for_startup": False,
    }


def _show_health_failure(report: dict) -> None:
    try:
        QApplication, QMessageBox, _ = _load_ui_stack()
        app = QApplication.instance() or QApplication([sys.argv[0]])
        app.setApplicationName(PRODUCT_NAME)
        app.setApplicationVersion(PRODUCT_VERSION)
        app.setOrganizationName(installer.PUBLISHER)
        QMessageBox.critical(
            None,
            "BC Sentinel — Controllo iniziale",
            "Il controllo iniziale ha rilevato prerequisiti critici non validi. "
            "Nessuna modifica automatica del sistema è stata eseguita.",
        )
    except Exception:
        return


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-json", action="store_true")
    parser.add_argument("--health-json", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.identity_json:
        print(json.dumps({
            "product": PRODUCT_NAME,
            "version": PRODUCT_VERSION,
            "profile": PROFILE,
            "source_checkpoint": installer.SOURCE_CHECKPOINT,
            "source_checkpoint_commit": installer.SOURCE_CHECKPOINT_COMMIT,
            "install_scope": installer.INSTALL_SCOPE,
        }, indent=2, sort_keys=True))
        return 0

    if args.self_check:
        report = _self_check()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["passed"] else 1

    health = first_run_health.live_health_report()
    validation = first_run_health.validate_health_report(health)
    blocked = bool(validation) or health["overall_status"] == first_run_health.BLOCKED

    if args.health_json:
        print(json.dumps(health, indent=2, sort_keys=True))
        return 2 if blocked else 0

    if blocked:
        if not args.smoke:
            _show_health_failure(health)
        return 2

    QApplication, _, response_ui = _load_ui_stack()
    snapshot = _snapshot()
    center = response.NotificationCenter(_notification_store())

    if args.smoke:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        smoke = response_ui.smoke_test_window(snapshot)
        report = {
            "passed": bool(smoke["passed"]),
            "profile": PROFILE,
            "page_count": smoke["page_count"],
            "alerts_selected": smoke["alerts_selected"],
            "horizontal_overflow": smoke["horizontal_overflow"],
            "automatic_quarantine": False,
            "service_or_driver_required": False,
            "network_required_for_startup": False,
            "cloud_required_for_startup": False,
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["passed"] else 1

    app = QApplication.instance() or QApplication([sys.argv[0]])
    app.setApplicationName(PRODUCT_NAME)
    app.setApplicationVersion(PRODUCT_VERSION)
    app.setOrganizationName(installer.PUBLISHER)

    window = response_ui.B13ConsumerWindow(
        snapshot=snapshot,
        notification_center=center,
    )
    window.setWindowTitle(PRODUCT_NAME)
    window.setProperty("bcSentinelRuntimeProfile", PROFILE)
    window.setProperty("bcSentinelSourceCheckpoint", installer.SOURCE_CHECKPOINT)
    window.setProperty("bcSentinelSourceCommit", installer.SOURCE_CHECKPOINT_COMMIT)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
