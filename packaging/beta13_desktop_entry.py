from __future__ import annotations

"""BC Sentinel Beta13 desktop entrypoint for packaged/installed builds."""

import argparse
import json
import os
from pathlib import Path
import sys
from time import time
from collections.abc import Sequence

from sentinel import beta11_first_run_health as first_run_health
from sentinel import beta12_product_integration as product
from sentinel import beta13_commercial_readiness as commercial
from sentinel import beta13_installer as installer
from sentinel import beta13_safe_response as response


PRODUCT_NAME = installer.PRODUCT_NAME
PRODUCT_VERSION = installer.PRODUCT_VERSION
PROFILE = commercial.PROFILE


def _notification_store() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    return base / "BCSentinel" / "notifications.json"


def _trial_store() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    return base / "BCSentinel" / "commercial" / "trial.json"


def _load_ui_stack():
    from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
    from sentinel import beta13_commercial_ui as commercial_ui
    return QApplication, QFileDialog, QMessageBox, commercial_ui


def _snapshot() -> dict:
    snapshot = product.build_product_snapshot()
    validation = product.validate_snapshot(snapshot)
    if not snapshot["passed"] or not validation["passed"]:
        raise RuntimeError("B13 desktop entrypoint refused invalid product snapshot")
    return snapshot


def _commercial_state(*, now: float | None = None) -> commercial.CommercialState:
    current = time() if now is None else float(now)
    trial = commercial.load_trial(_trial_store(), now=current, initialize_if_missing=True)

    raw_token = str(os.environ.get("BC_SENTINEL_LICENSE_TOKEN_JSON", "") or "").strip()
    raw_key = str(os.environ.get("BC_SENTINEL_LICENSE_PUBLIC_KEY", "") or "").strip()
    entitlement = None
    if raw_token:
        try:
            token = json.loads(raw_token)
        except json.JSONDecodeError:
            token = None
        entitlement = commercial.verify_signed_entitlement(
            token,
            public_key=raw_key or None,
            now=current,
        )

    state = commercial.resolve_commercial_state(
        trial=trial,
        entitlement=entitlement,
    )
    if state.protection_enabled is not True:
        raise RuntimeError("B13-6 commercial state attempted to disable core protection")
    return state


def _self_check() -> dict:
    failures: list[str] = []
    health_contract = first_run_health.self_check()
    if not health_contract["passed"]:
        failures.extend("first_run:" + item for item in health_contract["failures"])

    installer_contract = installer.self_check()
    if not installer_contract["passed"]:
        failures.extend("installer:" + item for item in installer_contract["failures"])

    commercial_contract = commercial.self_check()
    if not commercial_contract["passed"]:
        failures.extend("commercial:" + item for item in commercial_contract["failures"])

    snapshot = _snapshot()
    if snapshot["coverage_summary"] != {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}:
        failures.append("product:coverage_mismatch")

    state = commercial.evaluate_trial(
        {
            "schema": commercial.TRIAL_SCHEMA,
            "started_at": 1_800_000_000.0,
            "trial_days": commercial.DEFAULT_TRIAL_DAYS,
        },
        now=1_800_000_000.0,
    )
    if state.protection_enabled is not True:
        failures.append("commercial:core_protection_disabled")

    readiness = commercial.projected_readiness()
    if readiness["pillar_counts"] != {"READY": 9, "PARTIAL": 0, "BLOCKED": 1}:
        failures.append("commercial:readiness_counts_invalid")
    if readiness["release_blockers"] != ["CODE_SIGNING"]:
        failures.append("commercial:readiness_blockers_invalid")

    return {
        "passed": not failures,
        "failures": failures,
        "product": PRODUCT_NAME,
        "version": PRODUCT_VERSION,
        "profile": PROFILE,
        "source_checkpoint": commercial.SOURCE_CHECKPOINT,
        "source_checkpoint_commit": commercial.SOURCE_CHECKPOINT_COMMIT,
        "product_snapshot_valid": True,
        "first_run_health_contract_valid": health_contract["passed"],
        "installer_contract_valid": installer_contract["passed"],
        "commercial_contract_valid": commercial_contract["passed"],
        "commercial_status": state.status,
        "core_protection_enabled": state.protection_enabled,
        "readiness_projection": readiness,
        "notification_store_outside_install_root": True,
        "trial_store_outside_install_root": True,
        "automatic_quarantine": False,
        "service_or_driver_required": False,
        "network_required_for_startup": False,
        "cloud_required_for_startup": False,
        "license_failure_may_disable_core_protection": False,
    }


def _show_health_failure(report: dict) -> None:
    try:
        QApplication, _, QMessageBox, _ = _load_ui_stack()
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


def _interactive_export(state: commercial.CommercialState) -> None:
    QApplication, QFileDialog, QMessageBox, _ = _load_ui_stack()
    app = QApplication.instance() or QApplication([sys.argv[0]])
    del app
    destination, _ = QFileDialog.getSaveFileName(
        None,
        "Esporta diagnostica BC Sentinel",
        "BC-Sentinel-support-diagnostics.json",
        "JSON (*.json)",
    )
    if not destination:
        return
    try:
        result = commercial.export_diagnostics(
            destination,
            commercial_state=state,
        )
        QMessageBox.information(
            None,
            "Diagnostica esportata",
            "File diagnostico creato. SHA-256: " + str(result["sha256"]),
        )
    except Exception as exc:
        QMessageBox.critical(
            None,
            "Export diagnostica non riuscito",
            "BC Sentinel non ha creato il file diagnostico: " + str(exc),
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-json", action="store_true")
    parser.add_argument("--health-json", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--diagnostics-json")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.identity_json:
        print(json.dumps({
            "product": PRODUCT_NAME,
            "version": PRODUCT_VERSION,
            "profile": PROFILE,
            "source_checkpoint": commercial.SOURCE_CHECKPOINT,
            "source_checkpoint_commit": commercial.SOURCE_CHECKPOINT_COMMIT,
            "install_scope": installer.INSTALL_SCOPE,
        }, indent=2, sort_keys=True))
        return 0

    if args.self_check:
        report = _self_check()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["passed"] else 1

    if args.diagnostics_json:
        state = _commercial_state()
        result = commercial.export_diagnostics(
            args.diagnostics_json,
            commercial_state=state,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

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

    QApplication, _, _, commercial_ui = _load_ui_stack()
    snapshot = _snapshot()
    center = response.NotificationCenter(_notification_store())
    state = _commercial_state()

    if args.smoke:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        smoke = commercial_ui.smoke_test_window(
            snapshot,
            commercial_state=state,
        )
        report = {
            "passed": bool(smoke["passed"]),
            "profile": PROFILE,
            "page_count": smoke["page_count"],
            "commercial_selected": smoke["commercial_selected"],
            "policy_card_count": smoke["policy_card_count"],
            "diagnostic_export_button_enabled": smoke["diagnostic_export_button_enabled"],
            "horizontal_overflow": smoke["horizontal_overflow"],
            "core_protection_enabled": smoke["core_protection_enabled"],
            "automatic_quarantine": False,
            "service_or_driver_required": False,
            "network_required_for_startup": False,
            "cloud_required_for_startup": False,
            "license_failure_may_disable_core_protection": False,
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["passed"] else 1

    app = QApplication.instance() or QApplication([sys.argv[0]])
    app.setApplicationName(PRODUCT_NAME)
    app.setApplicationVersion(PRODUCT_VERSION)
    app.setOrganizationName(installer.PUBLISHER)

    window = commercial_ui.B136ConsumerWindow(
        snapshot=snapshot,
        notification_center=center,
        commercial_state=state,
        on_export_diagnostics=lambda: _interactive_export(state),
    )
    window.setWindowTitle(PRODUCT_NAME)
    window.setProperty("bcSentinelRuntimeProfile", PROFILE)
    window.setProperty("bcSentinelSourceCheckpoint", commercial.SOURCE_CHECKPOINT)
    window.setProperty("bcSentinelSourceCommit", commercial.SOURCE_CHECKPOINT_COMMIT)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
