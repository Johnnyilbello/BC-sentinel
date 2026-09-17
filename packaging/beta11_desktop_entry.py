from __future__ import annotations

"""Canonical BC Sentinel Beta11 desktop entrypoint."""

import argparse
import json
import os
import sys
from collections.abc import Sequence

from PySide6.QtWidgets import QApplication

from sentinel import beta10_trust_center as trust
from sentinel import beta10_trust_center_ui as product_ui
from sentinel import beta11_runtime_identity as identity


def _validated_snapshot() -> dict:
    snapshot = trust.build_trust_center_snapshot()
    validation = trust.validate_snapshot(snapshot)
    if not validation["passed"]:
        raise RuntimeError("B11-1 refused invalid Trust Center snapshot: " + ";".join(validation["failures"]))
    return snapshot


def _self_check() -> dict:
    result = identity.self_check()
    failures = list(result["failures"])
    snapshot = _validated_snapshot()
    validation = trust.validate_snapshot(snapshot)
    if not validation["passed"]:
        failures.append("b111:trust_center_snapshot_invalid")
    if product_ui.TrustCenterWindow.__name__ != identity.CANONICAL_UI_CLASS:
        failures.append("b111:canonical_window_binding_invalid")
    output = dict(result)
    output["trust_center_snapshot_valid"] = validation["passed"]
    output["canonical_window_binding_valid"] = product_ui.TrustCenterWindow.__name__ == identity.CANONICAL_UI_CLASS
    output["passed"] = not failures
    output["failures"] = failures
    return output


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-json", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.identity_json:
        print(json.dumps(identity.runtime_identity(), indent=2, sort_keys=True))
        return 0

    if args.self_check:
        result = _self_check()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1

    snapshot = _validated_snapshot()

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
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
