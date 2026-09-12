from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

from PySide6.QtWidgets import QApplication, QFrame, QLabel

from sentinel import home_security_model as model
from sentinel import home_security_ui as ui
from sentinel.ui_design_system import COLORS, INTERACTION, TYPOGRAPHY
from sentinel.ui_pages import EmptyState, PageHeader, SettingsRow, StatusBadge


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _evidence() -> dict:
    def item(layer_id: str, status: str, verified: bool) -> model.LayerEvidence:
        return model.LayerEvidence(
            layer_id=layer_id,
            status=status,
            runtime_verified=verified,
            summary=f"fixture:{layer_id}:{status}",
            raw={"fixture": True},
            provenance="visual_consistency_test",
        )

    return {
        model.LAYER_MALWARE: item(model.LAYER_MALWARE, model.STATUS_ENGINE_AVAILABLE, False),
        model.LAYER_BEHAVIOR: item(model.LAYER_BEHAVIOR, model.STATUS_ENGINE_AVAILABLE, False),
        model.LAYER_WEB: item(model.LAYER_WEB, model.STATUS_ENGINE_AVAILABLE, False),
        model.LAYER_RECOVERY: item(model.LAYER_RECOVERY, model.STATUS_READY, True),
    }


def _relative_luminance(hex_color: str) -> float:
    raw = hex_color.lstrip("#")
    rgb = [int(raw[index:index + 2], 16) / 255.0 for index in (0, 2, 4)]

    def channel(value: float) -> float:
        return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4

    red, green, blue = (channel(value) for value in rgb)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _contrast(a: str, b: str) -> float:
    first, second = sorted((_relative_luminance(a), _relative_luminance(b)), reverse=True)
    return (first + 0.05) / (second + 0.05)


def _show(window: ui.SecurityOverviewWindow, width: int, height: int) -> None:
    app = _app()
    window.resize(width, height)
    window.show()
    app.processEvents()
    window._apply_responsive_layout(force=True)
    app.processEvents()
    window._sync_all_scroll_widths()
    app.processEvents()


def test_dashboard_is_still_primary_structure_not_replaced() -> None:
    _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        assert window.hero.objectName() == "PostureHero"
        assert window.modules_panel.objectName() == "ModulesPanel"
        assert len(window.metric_cards) == 3
        assert len(window.card_widgets) == 4
        assert window.nav_buttons["Dashboard"].objectName() == "NavActive"
    finally:
        window.close()


def test_semantic_tokens_cover_dark_surfaces_typography_and_interaction() -> None:
    required_colors = {
        "bg_app", "bg_sidebar", "bg_header", "surface_1", "surface_2", "surface_3",
        "border_subtle", "border_strong", "text_primary", "text_secondary", "text_muted",
        "accent", "success", "warning", "danger", "info", "hover", "pressed", "selected",
        "disabled_surface", "disabled_text",
    }
    assert required_colors.issubset(COLORS)
    assert {"caption", "body", "bodyStrong", "subtitle", "title", "pageTitle", "metric"}.issubset(TYPOGRAPHY)
    assert {"hover", "pressed", "selected", "focus", "disabled_surface", "disabled_text"}.issubset(INTERACTION)


def test_text_contrast_meets_aa_for_normal_secondary_copy() -> None:
    assert _contrast(COLORS["text_primary"], COLORS["bg_app"]) >= 4.5
    assert _contrast(COLORS["text_secondary"], COLORS["bg_app"]) >= 4.5
    assert _contrast(COLORS["text_secondary"], COLORS["surface_1"]) >= 4.5
    assert _contrast(COLORS["text_muted"], COLORS["bg_app"]) >= 4.5


def test_every_secondary_scroll_surface_explicitly_owns_dark_background() -> None:
    _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        style = window.styleSheet()
        for selector in ("#SecondaryPageScroll", "#SecondaryPageViewport", "#SecondaryPageHost"):
            assert selector in style
        assert COLORS["bg_app"] in style
    finally:
        window.close()


def test_secondary_pages_share_page_header_and_one_empty_state_component() -> None:
    _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        for page in (
            window.scan_page,
            window.quarantine_page,
            window.history_page,
            window.protection_page,
            window.settings_page,
        ):
            assert page.findChild(PageHeader) is not None
            assert page.findChild(QLabel, "PageTitle") is not None
            assert page.findChild(QLabel, "PageSubtitle") is not None

        assert isinstance(window.quarantine_page.empty, EmptyState)
        assert isinstance(window.history_page.empty, EmptyState)
        assert window.quarantine_page.empty.maximumHeight() <= 220
        assert window.history_page.empty.maximumHeight() <= 220
    finally:
        window.close()


def test_scan_empty_composition_is_bounded_and_actions_truthful() -> None:
    _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        panel = window.scan_page.findChild(QFrame, "TaskPanel")
        assert panel is not None
        assert panel.maximumHeight() <= 340
        assert window.scan_page.quick_scan.isEnabled() is False
        assert window.scan_page.full_scan.isEnabled() is False
        assert window.scan_page.quick_scan.objectName() == "PrimaryDisabled"
        assert window.scan_page.full_scan.objectName() == "SecondaryDisabled"
    finally:
        window.close()


def test_quarantine_toolbar_preserves_required_controls_without_fake_rows() -> None:
    _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        texts = [button.text() for button in window.quarantine_page.findChildren(type(window.quarantine_page.refresh_button))]
        assert "In quarantena" in texts
        assert "Ripristinati" in texts
        assert "Filtri" in texts
        assert "Aggiorna lista" in texts
        assert window.quarantine_page.table.rowCount() == 0
    finally:
        window.close()


def test_protection_has_explicit_engine_runtime_and_control_hierarchy() -> None:
    _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        badges = window.protection_page.findChildren(StatusBadge)
        rows = window.protection_page.findChildren(QFrame, "ProtectionRow")
        runtime_meta = window.protection_page.findChildren(QLabel, "SettingMeta")
        assert len(rows) == 4
        assert len(badges) == 4
        assert len(runtime_meta) >= 4
        assert any("Runtime non verificato" in label.text() for label in runtime_meta)
    finally:
        window.close()


def test_settings_uses_reusable_rows_and_four_clear_sections() -> None:
    _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        sections = window.settings_page.findChildren(QFrame, "SettingsPanel")
        rows = window.settings_page.findChildren(SettingsRow)
        assert len(sections) == 4
        assert len(rows) >= 6
        panel_titles = {label.text() for label in window.settings_page.findChildren(QLabel, "PanelTitle")}
        assert {"Protezione", "Generale", "Cartelle monitorate", "Esclusioni / Allowlist"}.issubset(panel_titles)
    finally:
        window.close()


def test_secondary_pages_have_no_outer_horizontal_overflow_at_laptop_and_narrow_widths() -> None:
    app = _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        for width, height in ((1080, 820), (760, 760), (560, 620)):
            _show(window, width, height)
            for page in ui.PAGE_ORDER:
                window._navigate(page)
                app.processEvents()
                window._sync_all_scroll_widths()
                app.processEvents()
                current = window.stack.currentWidget()
                if hasattr(current, "horizontalScrollBar"):
                    assert current.horizontalScrollBar().maximum() == 0
    finally:
        window.close()
