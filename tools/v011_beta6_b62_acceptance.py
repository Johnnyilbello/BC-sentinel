from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

from PySide6.QtWidgets import QApplication

from sentinel import home_security_model as model
from sentinel import home_security_ui as ui


def _active_fixture() -> dict:
    def evidence(layer_id: str, status: str, runtime_verified: bool) -> model.LayerEvidence:
        return model.LayerEvidence(
            layer_id=layer_id,
            status=status,
            runtime_verified=runtime_verified,
            summary=f"acceptance:{layer_id}:{status}",
            raw={"fixture": "b62_acceptance", "status": status},
            provenance="b62_acceptance_fixture",
        )

    return {
        model.LAYER_MALWARE: evidence(model.LAYER_MALWARE, model.STATUS_ACTIVE, True),
        model.LAYER_BEHAVIOR: evidence(model.LAYER_BEHAVIOR, model.STATUS_ACTIVE, True),
        model.LAYER_WEB: evidence(model.LAYER_WEB, model.STATUS_ACTIVE, True),
        model.LAYER_RECOVERY: evidence(model.LAYER_RECOVERY, model.STATUS_READY, True),
    }


def _partial_fixture() -> dict:
    payload = _active_fixture()
    payload[model.LAYER_WEB] = model.LayerEvidence(
        layer_id=model.LAYER_WEB,
        status=model.STATUS_ENGINE_AVAILABLE,
        runtime_verified=False,
        summary="engine present but runtime proof intentionally absent",
        raw={"fixture": "missing_runtime_proof"},
        provenance="b62_acceptance_fixture",
    )
    return payload


def run_acceptance() -> dict:
    contract = model.validate_b62_safety_contract()
    default_snapshot = model.build_snapshot()
    verified_snapshot = model.build_snapshot(_active_fixture)
    partial_snapshot = model.build_snapshot(_partial_fixture)

    app = QApplication.instance() or QApplication([])
    window = ui.SecurityOverviewWindow()
    try:
        default_runtime_cards = [
            card for card in default_snapshot.cards
            if card.card_id in model.REQUIRED_RUNTIME_LAYERS
        ]
        checks = {
            "parent_b61_contract_green": contract.get("passed") is True,
            "startup_scan_dispatch_false": contract.get("startup_scan_dispatch") is False,
            "startup_rescue_dispatch_false": contract.get("startup_rescue_dispatch") is False,
            "no_destructive_authority": contract.get("destructive_authority_added") is False,
            "default_posture_unverified": default_snapshot.posture == model.POSTURE_UNVERIFIED,
            "default_never_claims_active": bool(default_runtime_cards) and all(
                card.status != model.STATUS_ACTIVE and card.runtime_verified is False
                for card in default_runtime_cards
            ),
            "explicit_verified_fixture_can_protect": verified_snapshot.posture == model.POSTURE_PROTECTED,
            "missing_runtime_proof_blocks_protected": partial_snapshot.posture == model.POSTURE_UNVERIFIED,
            "smart_scan_disabled_in_model": default_snapshot.smart_scan_enabled is False,
            "window_constructs": window.windowTitle() == ui.WINDOW_TITLE,
            "four_protection_cards": len(window.card_widgets) == 4,
            "smart_scan_disabled_in_ui": window.smart_scan_button.isEnabled() is False,
            "recovery_action_available": window.card_widgets[model.LAYER_RECOVERY].action_button.isEnabled() is True,
            "neutral_default_visual_posture": window.hero.property("posture") == model.POSTURE_UNVERIFIED,
            "dark_surface_contract": (
                ui.COLOR_TOKENS["canvas"].lower() != "#ffffff"
                and "#PageViewport" in window.styleSheet()
                and "#SecurityRoot" in window.styleSheet()
            ),
            "spacing_tokens_exact": ui.SPACING_TOKENS == {
                "xs": 4,
                "sm": 8,
                "md": 12,
                "lg": 16,
                "xl": 20,
                "2xl": 24,
                "3xl": 32,
                "4xl": 40,
            },
            "motion_tokens_within_contract": (
                120 <= ui.MOTION_TOKENS["micro"] <= 160
                and 180 <= ui.MOTION_TOKENS["state"] <= 220
                and 220 <= ui.MOTION_TOKENS["panel"] <= 280
                and ui.MOTION_TOKENS["page"] <= 320
            ),
            "minimum_window_contract": window.minimumWidth() >= 980 and window.minimumHeight() >= 700,
        }
    finally:
        window.close()
        app.processEvents()

    failures = [name for name, passed in checks.items() if not passed]
    return {
        "schema": model.SCHEMA,
        "profile": model.PROFILE,
        "checkpoint": "B6-2-home-security-overview",
        "passed": not failures,
        "failures": failures,
        "checks": checks,
        "default_posture": default_snapshot.posture,
        "verified_fixture_posture": verified_snapshot.posture,
        "partial_fixture_posture": partial_snapshot.posture,
        "smart_scan_enabled": default_snapshot.smart_scan_enabled,
        "note": "Deterministic/local B6-2 acceptance only. Real Windows visual acceptance remains required before checkpoint acceptance.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B6-2 deterministic acceptance")
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
