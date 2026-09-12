from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

from PySide6.QtWidgets import QApplication, QBoxLayout, QFrame, QLabel

from sentinel import home_security_model as model
from sentinel import home_security_ui as ui
from sentinel.ui_design_system import COLORS
from sentinel.ui_pages import StatusBadge


def _evidence(*, active: bool = False, missing_web: bool = False) -> dict[str, model.LayerEvidence]:
    status = model.STATUS_ACTIVE if active else model.STATUS_ENGINE_AVAILABLE
    verified = active
    payload = {
        model.LAYER_MALWARE: model.LayerEvidence(
            model.LAYER_MALWARE, status, verified, "fixture", {"fixture": True}, "acceptance"
        ),
        model.LAYER_BEHAVIOR: model.LayerEvidence(
            model.LAYER_BEHAVIOR, status, verified, "fixture", {"fixture": True}, "acceptance"
        ),
        model.LAYER_WEB: model.LayerEvidence(
            model.LAYER_WEB, status, verified, "fixture", {"fixture": True}, "acceptance"
        ),
        model.LAYER_RECOVERY: model.LayerEvidence(
            model.LAYER_RECOVERY, model.STATUS_READY, True, "fixture", {"fixture": True}, "acceptance"
        ),
    }
    if missing_web:
        payload[model.LAYER_WEB] = model.LayerEvidence(
            model.LAYER_WEB,
            model.STATUS_UNAVAILABLE,
            False,
            "missing fixture",
            {"reason": "missing"},
            "acceptance",
        )
    return payload


def _geometry(window: ui.SecurityOverviewWindow, width: int, height: int) -> dict:
    app = QApplication.instance() or QApplication([])
    window.resize(width, height)
    window.show()
    app.processEvents()
    window._apply_responsive_layout(force=True)
    app.processEvents()
    window._sync_all_scroll_widths()
    app.processEvents()
    return {
        "sidebar": window.sidebar.width(),
        "host": window.page_host.width(),
        "viewport": window.page_scroll.viewport().width(),
        "hscroll": window.page_scroll.horizontalScrollBar().maximum(),
        "hero": window.hero.width(),
        "modules": window.modules_panel.width(),
        "hero_vertical": window.hero_layout.direction() == QBoxLayout.Direction.TopToBottom,
        "mode": window._layout_mode,
        "card_widths": [card.width() for card in window.card_widgets.values()],
        "metric_widths": [card.width() for card in window.metric_cards],
        "secondary_hscrolls": [scroll.horizontalScrollBar().maximum() for scroll in window.secondary_scrolls],
    }


def run_acceptance() -> dict:
    contract = model.validate_b62_safety_contract()
    default_snapshot = model.build_snapshot()
    verified_snapshot = model.build_snapshot(lambda: _evidence(active=True))
    partial_snapshot = model.build_snapshot(lambda: _evidence(active=True, missing_web=True))

    app = QApplication.instance() or QApplication([])
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        large = _geometry(window, 1600, 980)
        laptop = _geometry(window, 1080, 820)
        tablet = _geometry(window, 760, 760)
        default_runtime = [
            card for card in default_snapshot.cards if card.card_id in model.REQUIRED_RUNTIME_LAYERS
        ]
        style = window.styleSheet()
        secondary_selectors = (
            "#SecondaryPageScroll",
            "#SecondaryPageViewport",
            "#SecondaryPageHost",
        )
        protection_rows = window.protection_page.findChildren(QFrame, "ProtectionRow")
        protection_badges = window.protection_page.findChildren(StatusBadge)
        setting_sections = window.settings_page.findChildren(QFrame, "SettingsPanel")
        runtime_meta = window.protection_page.findChildren(QLabel, "SettingMeta")
        scan_panel = window.scan_page.findChild(QFrame, "TaskPanel")

        checks = {
            "parent_b61_contract_green": contract.get("passed") is True,
            "startup_scan_dispatch_false": contract.get("startup_scan_dispatch") is False,
            "startup_rescue_dispatch_false": contract.get("startup_rescue_dispatch") is False,
            "no_destructive_authority": contract.get("destructive_authority_added") is False,
            "default_posture_unverified": default_snapshot.posture == model.POSTURE_UNVERIFIED,
            "default_never_claims_active": bool(default_runtime)
            and all(card.status != model.STATUS_ACTIVE and card.runtime_verified is False for card in default_runtime),
            "explicit_verified_fixture_can_protect": verified_snapshot.posture == model.POSTURE_PROTECTED,
            "missing_runtime_proof_blocks_protected": partial_snapshot.posture == model.POSTURE_UNVERIFIED,
            "smart_scan_disabled_in_model": default_snapshot.smart_scan_enabled is False,
            "smart_scan_disabled_in_ui": window.smart_scan_button.isEnabled() is False,
            "full_scan_disabled_in_ui": window.full_scan_button.isEnabled() is False,
            "six_stitch_pages_present": window.stack.count() == 6 and tuple(window.nav_buttons) == ui.PAGE_ORDER,
            "all_nav_icons_present": all(not button.icon().isNull() for button in window.nav_buttons.values()),
            "dark_surface_contract": ui.COLOR_TOKENS["canvas"].lower() == "#0f1412"
            and "#PageViewport" in style,
            "secondary_dark_surface_contract": all(selector in style for selector in secondary_selectors)
            and COLORS["bg_app"] in style,
            "dashboard_structure_preserved": window.hero.objectName() == "PostureHero"
            and window.modules_panel.objectName() == "ModulesPanel"
            and len(window.metric_cards) == 3
            and len(window.card_widgets) == 4,
            "stitch_accent_exact": ui.COLOR_TOKENS["accent"].lower() == "#10b981",
            "spacing_tokens_exact": ui.SPACING_TOKENS
            == {"xs": 4, "sm": 8, "md": 16, "lg": 24, "xl": 32, "xxl": 48},
            "motion_tokens_within_contract": 120 <= ui.MOTION_TOKENS["micro"] <= 160
            and 180 <= ui.MOTION_TOKENS["state"] <= 220
            and 220 <= ui.MOTION_TOKENS["panel"] <= 280
            and ui.MOTION_TOKENS["page"] <= 320,
            "large_sidebar_260": large["sidebar"] == 260,
            "large_no_horizontal_overflow": large["hscroll"] == 0
            and large["host"] == large["viewport"]
            and all(value == 0 for value in large["secondary_hscrolls"]),
            "large_hero_fluid": large["hero"] >= 1200 and large["modules"] >= 1200,
            "large_two_column_modules": large["mode"] == "desktop"
            and all(width >= 500 for width in large["card_widths"]),
            "laptop_compact_reflow": laptop["sidebar"] == 220 and laptop["hero_vertical"] is True,
            "laptop_no_horizontal_overflow": laptop["hscroll"] == 0
            and laptop["host"] == laptop["viewport"]
            and all(value == 0 for value in laptop["secondary_hscrolls"]),
            "tablet_icon_rail": tablet["sidebar"] == 76 and tablet["mode"] == "mobile",
            "tablet_no_horizontal_overflow": tablet["hscroll"] == 0
            and tablet["host"] == tablet["viewport"]
            and all(value == 0 for value in tablet["secondary_hscrolls"]),
            "scan_empty_composition_bounded": scan_panel is not None
            and scan_panel.maximumHeight() <= 410,
            "quarantine_empty_composition_bounded": window.quarantine_page.empty.maximumHeight() <= 220,
            "history_empty_composition_bounded": window.history_page.empty.maximumHeight() <= 220,
            "quarantine_no_fake_rows": window.quarantine_page.table.rowCount() == 0,
            "history_no_fake_rows": window.history_page.table.rowCount() == 0,
            "protection_hierarchy_present": len(protection_rows) == 4
            and len(protection_badges) == 4
            and len(runtime_meta) >= 4,
            "settings_four_sections_present": len(setting_sections) == 4,
            "recovery_action_available": window.card_widgets[model.LAYER_RECOVERY].action_button.isEnabled() is True,
        }
    finally:
        window.close()
        app.processEvents()

    failures = [name for name, passed in checks.items() if not passed]
    return {
        "schema": model.SCHEMA,
        "profile": model.PROFILE,
        "checkpoint": "B6-2-dashboard-visual-consistency-refinement",
        "passed": not failures,
        "failures": failures,
        "checks": checks,
        "default_posture": default_snapshot.posture,
        "verified_fixture_posture": verified_snapshot.posture,
        "partial_fixture_posture": partial_snapshot.posture,
        "smart_scan_enabled": default_snapshot.smart_scan_enabled,
        "geometry": {"large": large, "laptop": laptop, "tablet": tablet},
        "note": (
            "Deterministic/local B6-2 acceptance for the Dashboard-derived visual consistency pass. "
            "Verifies runtime truth, six-page shell, explicit dark secondary surfaces, intentional empty "
            "states, Protection/Settings hierarchy and zero horizontal overflow. Real Windows visual "
            "acceptance is still required before stabilization."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B6-2 Dashboard visual consistency acceptance")
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
