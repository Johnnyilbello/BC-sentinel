from __future__ import annotations

"""Canonical BC Sentinel Beta11 desktop entrypoint."""

import argparse
import json
import os
import sys
from collections.abc import Sequence

from sentinel import beta11_first_run_health as first_run_health
from sentinel import beta11_runtime_identity as identity


def _load_ui_stack():
    # Kept lazy so --identity-json / --health-json can diagnose runtime state
    # before constructing the Qt application or importing the full UI.
    from PySide6.QtWidgets import QApplication, QMessageBox
    from sentinel import beta10_trust_center as trust
    from sentinel import beta10_trust_center_ui as product_ui

    return QApplication, QMessageBox, trust, product_ui


def _validated_snapshot(trust_module=None) -> dict:
    if trust_module is None:
        _, _, trust_module, _ = _load_ui_stack()
    snapshot = trust_module.build_trust_center_snapshot()
    validation = trust_module.validate_snapshot(snapshot)
    if not validation["passed"]:
        raise RuntimeError("B11-1 refused invalid Trust Center snapshot: " + ";".join(validation["failures"]))
    return snapshot


def _self_check() -> dict:
    result = identity.self_check()
    failures = list(result["failures"])

    health_contract = first_run_health.self_check()
    if not health_contract["passed"]:
        failures.extend(f"b114:{item}" for item in health_contract["failures"])

    live_health = first_run_health.live_health_report()
    live_validation = first_run_health.validate_health_report(live_health)
    if live_validation:
        failures.extend(live_validation)
    if live_health["overall_status"] == first_run_health.BLOCKED:
        failures.append("b114:live_first_run_health_blocked")

    _, _, trust, product_ui = _load_ui_stack()
    snapshot = _validated_snapshot(trust)
    validation = trust.validate_snapshot(snapshot)
    if not validation["passed"]:
        failures.append("b111:trust_center_snapshot_invalid")
    if product_ui.TrustCenterWindow.__name__ != identity.CANONICAL_UI_CLASS:
        failures.append("b111:canonical_window_binding_invalid")

    output = dict(result)
    output["trust_center_snapshot_valid"] = validation["passed"]
    output["canonical_window_binding_valid"] = product_ui.TrustCenterWindow.__name__ == identity.CANONICAL_UI_CLASS
    output["first_run_health_contract_valid"] = health_contract["passed"]
    output["first_run_health_status"] = live_health["overall_status"]
    output["first_run_health_ready_to_start"] = live_health["ready_to_start"]
    output["first_run_health_mutates_system"] = False
    output["automatic_repair_available"] = False
    output["passed"] = not failures
    output["failures"] = failures
    return output


def _health_failure_text(report: dict) -> str:
    lines = [
        "BC Sentinel non può avviarsi perché il controllo iniziale ha rilevato prerequisiti critici non validi.",
        "",
    ]
    failed = [item for item in report.get("checks", []) if item.get("critical") and item.get("status") == "FAIL"]
    for item in failed[:8]:
        lines.append(f"• {item.get('check_id')}: {item.get('summary')}")
    guidance = report.get("repair_guidance") or []
    if guidance:
        lines.extend(["", "Indicazioni:"])
        for item in guidance[:6]:
            lines.append(f"• {item.get('operator_action')}")
    lines.extend(["", "Nessuna riparazione o modifica del sistema è stata eseguita automaticamente."])
    return "\n".join(lines)


def _show_blocking_health_dialog(report: dict) -> None:
    try:
        QApplication, QMessageBox, _, _ = _load_ui_stack()
        app = QApplication.instance() or QApplication([sys.argv[0]])
        app.setApplicationName(identity.PRODUCT_NAME)
        app.setApplicationVersion(identity.PRODUCT_VERSION)
        app.setOrganizationName("BC TECH Studio")
        QMessageBox.critical(None, "BC Sentinel — Controllo iniziale", _health_failure_text(report))
    except Exception:
        # A missing Qt runtime may itself be the critical failure. The JSON
        # diagnostic path remains available when a console is present.
        return


def _live_health_or_block(*, show_dialog: bool) -> tuple[dict, bool]:
    report = first_run_health.live_health_report()
    validation = first_run_health.validate_health_report(report)
    blocked = bool(validation) or report["overall_status"] == first_run_health.BLOCKED
    if validation:
        report = dict(report)
        report["validation_failures"] = list(validation)
        report["overall_status"] = first_run_health.BLOCKED
        report["ready_to_start"] = False
    if blocked and show_dialog:
        _show_blocking_health_dialog(report)
    return report, blocked


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-json", action="store_true")
    parser.add_argument("--health-json", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.identity_json:
        print(json.dumps(identity.runtime_identity(), indent=2, sort_keys=True))
        return 0

    if args.health_json:
        report, blocked = _live_health_or_block(show_dialog=False)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 2 if blocked else 0

    if args.self_check:
        result = _self_check()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1

    health_report, blocked = _live_health_or_block(show_dialog=not args.smoke)
    if blocked:
        print(json.dumps(health_report, indent=2, sort_keys=True), file=sys.stderr)
        return 2

    QApplication, _, trust, product_ui = _load_ui_stack()
    snapshot = _validated_snapshot(trust)

    if args.smoke:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        smoke = product_ui.smoke_test_window(snapshot)
        result = {
            "passed": bool(smoke["passed"]),
            "profile": identity.PROFILE,
            "canonical_entrypoint": identity.CANONICAL_ENTRYPOINT,
            "canonical_ui_module": identity.CANONICAL_UI_MODULE,
            "canonical_ui_class": identity.CANONICAL_UI_CLASS,
            "page_count": smoke["page_count"],
            "trust_center_selected": smoke["trust_center_selected"],
            "horizontal_overflow": smoke["horizontal_overflow"],
            "nav_enabled": smoke["nav_enabled"],
            "first_run_health_status": health_report["overall_status"],
            "first_run_health_ready_to_start": health_report["ready_to_start"],
            "first_run_health_mutates_system": False,
            "automatic_repair_available": False,
            "startup_authority_expanded": False,
            "coverage_promoted": False,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1

    app = QApplication.instance() or QApplication([sys.argv[0]])
    app.setApplicationName(identity.PRODUCT_NAME)
    app.setApplicationVersion(identity.PRODUCT_VERSION)
    app.setOrganizationName("BC TECH Studio")

    window = product_ui.TrustCenterWindow(trust_snapshot=snapshot)
    window.setWindowTitle(identity.PRODUCT_NAME)
    window.setProperty("bcSentinelRuntimeProfile", identity.PROFILE)
    window.setProperty("bcSentinelSourceCheckpoint", identity.SOURCE_CHECKPOINT)
    window.setProperty("bcSentinelSourceCommit", identity.SOURCE_CHECKPOINT_COMMIT)
    window.setProperty("bcSentinelFirstRunHealthProfile", first_run_health.PROFILE)
    window.setProperty("bcSentinelFirstRunHealthStatus", health_report["overall_status"])
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
