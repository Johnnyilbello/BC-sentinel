from __future__ import annotations

"""Unified B6-2 application shell for BC Sentinel.

The accepted Dashboard is the visual source of truth. The dashboard presentation
component remains isolated in ``home_security_ui_impl`` while this module owns
navigation, secondary pages and responsive geometry. Security state/actions stay
delegated to the accepted model and engine interfaces.
"""

import argparse
import json
import os
import sys
from typing import Callable, Mapping

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QBoxLayout,
    QFrame,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from sentinel import home_security_model as model
from sentinel import home_security_ui_impl as _impl
from sentinel.ui_design_system import (
    BREAKPOINTS,
    COLORS,
    MOTION,
    NAV_ITEMS as DESIGN_NAV_ITEMS,
    SPACING,
)
from sentinel.ui_pages import HistoryPage, ProtectionPage, QuarantinePage, ScanPage, SettingsPage
from sentinel.ui_styles import home_stylesheet

PROFILE = model.PROFILE
WINDOW_TITLE = "BC Sentinel"
SPACING_TOKENS = dict(SPACING)
MOTION_TOKENS = dict(MOTION)
COLOR_TOKENS = {
    "canvas": COLORS["canvas"],
    "sidebar": COLORS["sidebar"],
    "surface_lowest": COLORS["surface_lowest"],
    "surface_low": COLORS["surface_low"],
    "surface_1": COLORS["surface"],
    "surface_2": COLORS["surface_high"],
    "surface_3": COLORS["surface_highest"],
    "border": COLORS["border"],
    "border_soft": COLORS["border_soft"],
    "text_primary": COLORS["text"],
    "text_secondary": COLORS["text_secondary"],
    "text_muted": COLORS["text_muted"],
    "accent": COLORS["accent"],
    "accent_bright": COLORS["accent_bright"],
    "success": COLORS["accent_bright"],
    "warning": COLORS["warning"],
    "critical": COLORS["danger"],
    "cool": COLORS["info"],
}
NAV_ITEMS = DESIGN_NAV_ITEMS
PAGE_ORDER = tuple(label for _, label in DESIGN_NAV_ITEMS)

ProtectionCard = _impl.ProtectionCard
MetricCard = _impl.MetricCard
_display_posture = _impl._display_posture
_status_role = _impl._status_role


class _PageScroll(QScrollArea):
    """Vertical-only wrapper whose host continuously follows the real viewport.

    Qt may reveal the vertical scrollbar one event-loop tick after page content is
    laid out. That shrinks the viewport by the scrollbar extent. Re-syncing on
    viewport resize and scrollbar range changes prevents the stale-width 8 px
    horizontal overflow that can otherwise appear after navigating/resizing.
    """

    def __init__(self, page: QWidget, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SecondaryPageScroll")
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.viewport().setObjectName("SecondaryPageViewport")

        host = QWidget()
        host.setObjectName("SecondaryPageHost")
        host.setMinimumWidth(0)
        host.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)

        layout = QVBoxLayout(host)
        layout.setContentsMargins(24, 24, 24, 32)
        layout.setSpacing(0)

        page.setMinimumWidth(0)
        page.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        layout.addWidget(page)
        layout.addStretch(1)

        self.setWidget(host)
        self.page = page
        self.host = host
        self.verticalScrollBar().rangeChanged.connect(self._schedule_width_sync)
        QTimer.singleShot(0, self.sync_width)

    def _schedule_width_sync(self, *_args) -> None:
        QTimer.singleShot(0, self.sync_width)

    def sync_width(self) -> None:
        width = max(0, self.viewport().width())
        if width:
            self.host.setFixedWidth(width)
        self.host.updateGeometry()
        self.page.updateGeometry()

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        QTimer.singleShot(0, self.sync_width)


class SecurityOverviewWindow(_impl.SecurityOverviewWindow):
    """Complete six-surface application shell using the Dashboard visual system."""

    def __init__(self, status_provider: Callable[[], Mapping] | None = None) -> None:
        super().__init__(status_provider=status_provider)
        self.setMinimumSize(560, 620)
        self.resize(1440, 900)
        self._current_page = "Dashboard"
        self._layout_mode = "desktop"
        self._install_complete_shell()
        self._apply_theme()
        QTimer.singleShot(0, lambda: self._apply_responsive_layout(force=True))

    def _apply_theme(self) -> None:
        app = QApplication.instance()
        if app is not None:
            font = QFont()
            font.setFamilies(["Plus Jakarta Sans", "Segoe UI Variable Text", "Segoe UI"])
            font.setPointSize(10)
            app.setFont(font)
        self.setStyleSheet(home_stylesheet())

    def _install_complete_shell(self) -> None:
        main_layout = self.main_column.layout()
        main_layout.removeWidget(self.page_scroll)
        self.page_scroll.setParent(None)
        self.page_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.page_host = self.page_scroll.widget()
        self.page_host.setMinimumWidth(0)
        self.page_host.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.content_root.setMinimumWidth(0)
        self.content_root.setMaximumWidth(16777215)
        self.hero.setMinimumWidth(0)
        self.modules_panel.setMinimumWidth(0)
        self.activity.setMinimumWidth(0)
        self.headline_label.setMinimumWidth(0)
        for card in self.card_widgets.values():
            card.setMinimumWidth(0)

        self.scan_page = ScanPage()
        self.quarantine_page = QuarantinePage()
        self.history_page = HistoryPage()
        self.protection_page = ProtectionPage(self.snapshot, self._open_recovery)
        self.settings_page = SettingsPage(self.snapshot)

        self.scan_scroll = _PageScroll(self.scan_page)
        self.quarantine_scroll = _PageScroll(self.quarantine_page)
        self.history_scroll = _PageScroll(self.history_page)
        self.protection_scroll = _PageScroll(self.protection_page)
        self.settings_scroll = _PageScroll(self.settings_page)
        self.secondary_scrolls = [
            self.scan_scroll,
            self.quarantine_scroll,
            self.history_scroll,
            self.protection_scroll,
            self.settings_scroll,
        ]

        self.stack = QStackedWidget()
        self.stack.setObjectName("PageStack")
        self.stack.setMinimumWidth(0)
        self.stack.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Expanding)
        self.stack.addWidget(self.page_scroll)
        for scroll in self.secondary_scrolls:
            self.stack.addWidget(scroll)
        main_layout.addWidget(self.stack, 1)

        for index, name in enumerate(PAGE_ORDER):
            button = self.nav_buttons[name]
            button.setEnabled(True)
            button.setCheckable(True)
            button.setChecked(index == 0)
            try:
                button.clicked.disconnect()
            except (RuntimeError, TypeError):
                pass
            button.clicked.connect(lambda checked=False, page=name: self._navigate(page))

        self.topbar_title = self.main_column.findChild(QLabel, "TopBarTitle")
        if self.topbar_title is None:
            self.topbar_title = QLabel("BC SENTINEL")
        brand_name = self.sidebar.findChild(QLabel, "BrandName")
        brand_edition = self.sidebar.findChild(QLabel, "BrandEdition")
        self.brand_copy = brand_name if brand_name is not None else QLabel()
        self._brand_labels = [widget for widget in (brand_name, brand_edition) if widget is not None]
        self._footer_buttons = self.sidebar.findChildren(QWidget, "SidebarFooterItem")
        self._footer_texts = [button.text() for button in self._footer_buttons]
        self._sync_page_host_width()

    def _navigate(self, page: str) -> None:
        if page not in PAGE_ORDER:
            return
        self._current_page = page
        index = PAGE_ORDER.index(page)
        self.stack.setCurrentIndex(index)
        for name, button in self.nav_buttons.items():
            selected = name == page
            button.setChecked(selected)
            button.setObjectName("NavActive" if selected else "NavItem")
            button.style().unpolish(button)
            button.style().polish(button)
        if self._layout_mode != "mobile":
            self.topbar_title.setText(
                "BC SENTINEL Intelligent Windows Protection"
                if page == "Dashboard"
                else f"BC SENTINEL · {page}"
            )
        QTimer.singleShot(0, self._sync_all_scroll_widths)

    def _reset_grid_stretches(self) -> None:
        for column in range(4):
            self.metrics_grid.setColumnStretch(column, 0)
            self.cards_grid.setColumnStretch(column, 0)

    def _sync_page_host_width(self) -> None:
        viewport = max(0, self.page_scroll.viewport().width())
        if viewport:
            self.page_host.setFixedWidth(viewport)
        self.page_host.updateGeometry()
        self.content_root.updateGeometry()

    def _sync_all_scroll_widths(self) -> None:
        self._sync_page_host_width()
        for scroll in getattr(self, "secondary_scrolls", []):
            scroll.sync_width()

    def _apply_responsive_layout(self, force: bool = False) -> None:
        width = max(0, self.width())
        compact = width < BREAKPOINTS["wide"]
        mobile = width < BREAKPOINTS["compact"]
        mode = "mobile" if mobile else "compact" if compact else "desktop"

        if not force and mode == getattr(self, "_layout_mode", None):
            self._sync_all_scroll_widths()
            return

        self._layout_mode = mode
        self.sidebar.setFixedWidth(76 if mobile else 220 if compact else 260)
        for label in getattr(self, "_brand_labels", []):
            label.setVisible(not mobile)
        if hasattr(self, "sidebar_scan_button"):
            self.sidebar_scan_button.setText("" if mobile else "Quick Scan · B6-3")
        for name, button in self.nav_buttons.items():
            button.setText("" if mobile else name)
        for button, text in zip(
            getattr(self, "_footer_buttons", []), getattr(self, "_footer_texts", [])
        ):
            button.setText("" if mobile else text)
        self.refresh_button.setText("" if mobile else "Aggiorna stato")
        self.topbar_title.setText(
            "BC SENTINEL"
            if mobile
            else "BC SENTINEL Intelligent Windows Protection"
            if self._current_page == "Dashboard"
            else f"BC SENTINEL · {self._current_page}"
        )

        self.hero_layout.setDirection(
            QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight
        )
        self.hero_actions.setDirection(
            QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight
        )
        self.hero_actions.setAlignment(
            Qt.AlignmentFlag.AlignLeft if compact else Qt.AlignmentFlag.AlignVCenter
        )
        self.headline_label.setMinimumWidth(0 if compact else 320)
        self.hero_summary.setMaximumWidth(16777215 if compact else 620)
        self.smart_scan_button.setMinimumWidth(0 if compact else 190)
        self.full_scan_button.setMinimumWidth(0 if compact else 190)
        self.section_hint.setVisible(not compact)

        self._reset_grid_stretches()
        self._render_metrics(columns=1 if compact else 3)
        self._render_cards(columns=1 if compact else 2)
        for card in self.card_widgets.values():
            card.setMinimumWidth(0)

        for page in (
            self.scan_page,
            self.quarantine_page,
            self.history_page,
            self.protection_page,
            self.settings_page,
        ):
            setter = getattr(page, "set_compact", None)
            if setter:
                setter(compact, mobile)

        margin = 16 if compact else 24
        if self.page_host.layout():
            self.page_host.layout().setContentsMargins(margin, margin, margin, 32)
        for scroll in self.secondary_scrolls:
            if scroll.host.layout():
                scroll.host.layout().setContentsMargins(margin, margin, margin, 32)

        QTimer.singleShot(0, self._sync_all_scroll_widths)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        QTimer.singleShot(0, self._apply_responsive_layout)
        QTimer.singleShot(0, self._sync_all_scroll_widths)

    def _open_recovery(self) -> None:
        self._handle_card_action(model.LAYER_RECOVERY)

    def _refresh_snapshot(self) -> None:
        self.refresh_button.setEnabled(False)
        try:
            self.snapshot = model.build_snapshot(self.status_provider)
            self._update_hero()
            for widget in self.card_widgets.values():
                widget.deleteLater()
            self.card_widgets.clear()
            self._render_cards(1 if self._layout_mode in {"compact", "mobile"} else 2)

            current_index = self.stack.currentIndex()
            for scroll in (self.protection_scroll, self.settings_scroll):
                self.stack.removeWidget(scroll)
                if scroll in self.secondary_scrolls:
                    self.secondary_scrolls.remove(scroll)
                scroll.deleteLater()

            self.protection_page = ProtectionPage(self.snapshot, self._open_recovery)
            self.settings_page = SettingsPage(self.snapshot)
            self.protection_scroll = _PageScroll(self.protection_page)
            self.settings_scroll = _PageScroll(self.settings_page)
            self.secondary_scrolls.extend([self.protection_scroll, self.settings_scroll])
            self.stack.insertWidget(4, self.protection_scroll)
            self.stack.insertWidget(5, self.settings_scroll)
            self.stack.setCurrentIndex(min(current_index, self.stack.count() - 1))
            self._apply_responsive_layout(force=True)
            self.statusBar().showMessage(
                "Stato aggiornato passivamente. Nessuna scansione avviata.", 4500
            )
        finally:
            self.refresh_button.setEnabled(True)


_impl.SecurityOverviewWindow = SecurityOverviewWindow


def self_check() -> dict:
    contract = model.validate_b62_safety_contract()
    snapshot = model.build_snapshot()
    return {
        "profile": PROFILE,
        "passed": bool(contract["passed"]),
        "contract": contract,
        "snapshot": snapshot.to_dict(),
        "window_created": False,
        "startup_scan_dispatch": False,
        "startup_rescue_dispatch": False,
        "smart_scan_enabled": snapshot.smart_scan_enabled,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B6-2 unified Home UI")
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
    window = SecurityOverviewWindow()
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
                "minimum_size": [window.minimumWidth(), window.minimumHeight()],
                "card_count": len(window.card_widgets),
                "smart_scan_enabled": window.smart_scan_button.isEnabled(),
                "content_width": window.content_root.width(),
                "hero_width": window.hero.width(),
                "horizontal_scroll_max": window.page_scroll.horizontalScrollBar().maximum(),
                "page_count": window.stack.count(),
            }
        )
        print(json.dumps(payload, indent=2, sort_keys=True))
        window.close()
        return 0 if payload["passed"] else 4

    window.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
