from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Callable, Final, Mapping

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QTimer, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QGraphicsOpacityEffect,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from sentinel import home_security_model as model
from sentinel import rescue_home_ui

PROFILE: Final[str] = model.PROFILE
WINDOW_TITLE: Final[str] = "BC Sentinel"

SPACING_TOKENS: Final[dict[str, int]] = {
    "xs": 4,
    "sm": 8,
    "md": 12,
    "lg": 16,
    "xl": 20,
    "2xl": 24,
    "3xl": 32,
    "4xl": 40,
}

MOTION_TOKENS: Final[dict[str, int]] = {
    "micro": 140,
    "state": 200,
    "panel": 250,
    "page": 300,
    "stagger": 45,
}

COLOR_TOKENS: Final[dict[str, str]] = {
    "canvas": "#0e1511",
    "sidebar": "#161d19",
    "surface_1": "#1a211d",
    "surface_2": "#242c27",
    "surface_3": "#2f3632",
    "border": "#3c4a42",
    "border_soft": "#29352f",
    "text_primary": "#dde4dd",
    "text_secondary": "#bbcabf",
    "text_muted": "#86948a",
    "accent": "#10b981",
    "accent_soft": "#123428",
    "success": "#4edea3",
    "warning": "#f0b766",
    "critical": "#ff8b82",
    "cool": "#adc6ff",
}

NAV_ITEMS: Final[tuple[tuple[str, str], ...]] = (
    ("▦", "Dashboard"),
    ("⌕", "Scansione"),
    ("▣", "Quarantena"),
    ("↺", "Cronologia"),
    ("⬢", "Protezione"),
    ("⚙", "Impostazioni"),
)

MODULE_GLYPHS: Final[Mapping[str, str]] = {
    model.LAYER_MALWARE: "✦",
    model.LAYER_BEHAVIOR: "◉",
    model.LAYER_WEB: "◎",
    model.LAYER_RECOVERY: "↻",
}


def _reduced_motion() -> bool:
    value = os.environ.get("BC_SENTINEL_REDUCED_MOTION", "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _status_role(status: str) -> str:
    if status in {model.STATUS_ACTIVE, model.STATUS_READY}:
        return "positive"
    if status in {model.STATUS_ATTENTION, model.STATUS_OFF}:
        return "attention"
    return "neutral"


def _posture_color(posture: str) -> str:
    if posture == model.POSTURE_PROTECTED:
        return COLOR_TOKENS["success"]
    if posture == model.POSTURE_ATTENTION:
        return COLOR_TOKENS["critical"]
    return COLOR_TOKENS["warning"]


class ShieldMark(QWidget):
    """Native vector shield; no web asset dependency."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(76, 76)
        self.setAccessibleName("BC Sentinel shield")

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#223329"))
        painter.drawEllipse(2, 2, 72, 72)

        path = QPainterPath()
        path.moveTo(38, 15)
        path.lineTo(56, 22)
        path.lineTo(54, 43)
        path.cubicTo(53, 53, 46, 60, 38, 64)
        path.cubicTo(30, 60, 23, 53, 22, 43)
        path.lineTo(20, 22)
        path.closeSubpath()
        painter.setBrush(QColor(COLOR_TOKENS["accent"]))
        painter.drawPath(path)

        check = QPainterPath()
        check.moveTo(29, 39)
        check.lineTo(35, 45)
        check.lineTo(48, 31)
        pen = QPen(QColor("#07110c"), 4)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(check)


class ModuleSwitch(QWidget):
    """Read-only Windows-style state indicator in B6-2."""

    def __init__(self, on: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.on = bool(on)
        self.setFixedSize(44, 24)
        self.setAccessibleName("Protection runtime switch")
        self.setToolTip("Read-only in B6-2. Runtime controls arrive in a later milestone.")

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        track = QColor(COLOR_TOKENS["accent"] if self.on else "#26332d")
        border = QColor("#4d6256" if not self.on else "#2a8f69")
        painter.setPen(QPen(border, 1))
        painter.setBrush(track)
        painter.drawRoundedRect(1, 2, 42, 20, 10, 10)
        x = 23 if self.on else 4
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#edf4ef" if self.on else "#8c9991"))
        painter.drawEllipse(x, 5, 14, 14)


class ProtectionCard(QFrame):
    def __init__(
        self,
        card: model.HomeProtectionCard,
        on_action: Callable[[str], None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.card = card
        self._details_animation: QPropertyAnimation | None = None
        self.setObjectName("ProtectionCard")
        self.setProperty("cardId", card.card_id)
        self.setProperty("statusRole", _status_role(card.status))
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        top = QHBoxLayout()
        top.setSpacing(12)
        icon = QLabel(MODULE_GLYPHS.get(card.card_id, "•"))
        icon.setObjectName("ModuleIcon")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setFixedSize(40, 40)
        top.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)

        title_wrap = QVBoxLayout()
        title_wrap.setSpacing(3)
        title = QLabel(card.label)
        title.setObjectName("CardTitle")
        title.setWordWrap(True)
        description = QLabel(card.description)
        description.setObjectName("CardDescription")
        description.setWordWrap(True)
        title_wrap.addWidget(title)
        title_wrap.addWidget(description)
        top.addLayout(title_wrap, 1)

        self.runtime_switch = ModuleSwitch(card.status == model.STATUS_ACTIVE and card.runtime_verified)
        top.addWidget(self.runtime_switch, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(top)

        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        status = QLabel(card.status_label)
        status.setObjectName("StatusPill")
        status.setProperty("statusRole", _status_role(card.status))
        status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status.setMinimumHeight(26)
        status.setAccessibleName(f"{card.label} status: {card.status_label}")
        status_row.addWidget(status)
        status_row.addStretch(1)
        layout.addLayout(status_row)

        summary = QLabel(card.summary)
        summary.setObjectName("CardSummary")
        summary.setWordWrap(True)
        summary.setMinimumHeight(40)
        layout.addWidget(summary)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.details_button = QPushButton("Advanced details")
        self.details_button.setObjectName("InlineButton")
        self.details_button.setCheckable(True)
        self.details_button.setAccessibleName(f"Advanced details for {card.label}")
        self.details_button.toggled.connect(self._toggle_details)
        actions.addWidget(self.details_button)
        actions.addStretch(1)

        self.action_button = QPushButton(card.action_label)
        self.action_button.setObjectName("RecoveryButton" if card.action_enabled else "HiddenAction")
        self.action_button.setEnabled(card.action_enabled)
        self.action_button.setVisible(card.action_enabled)
        self.action_button.setAccessibleName(card.action_label)
        self.action_button.clicked.connect(lambda: on_action(card.card_id))
        actions.addWidget(self.action_button)
        layout.addLayout(actions)

        self.details_panel = QFrame()
        self.details_panel.setObjectName("AdvancedPanel")
        self.details_panel.setMaximumHeight(0)
        self.details_panel.setMinimumHeight(0)
        details_layout = QVBoxLayout(self.details_panel)
        details_layout.setContentsMargins(12, 12, 12, 12)
        details_layout.setSpacing(8)
        details_title = QLabel("Technical evidence")
        details_title.setObjectName("AdvancedTitle")
        self.details_text = QPlainTextEdit()
        self.details_text.setObjectName("AdvancedText")
        self.details_text.setReadOnly(True)
        self.details_text.setMinimumHeight(168)
        self.details_text.setPlainText(json.dumps(card.advanced_details, indent=2, sort_keys=True, default=str))
        self.details_text.setAccessibleName(f"Technical evidence for {card.label}")
        details_layout.addWidget(details_title)
        details_layout.addWidget(self.details_text)
        layout.addWidget(self.details_panel)

    def _toggle_details(self, expanded: bool) -> None:
        target = 226 if expanded else 0
        self.details_button.setText("Hide details" if expanded else "Advanced details")
        if _reduced_motion():
            self.details_panel.setMaximumHeight(target)
            return
        animation = QPropertyAnimation(self.details_panel, b"maximumHeight", self)
        animation.setDuration(MOTION_TOKENS["panel"])
        animation.setStartValue(self.details_panel.maximumHeight())
        animation.setEndValue(target)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        animation.start()
        self._details_animation = animation


class MetricCard(QFrame):
    def __init__(self, label: str, value: str, symbol: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("MetricCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)
        top = QHBoxLayout()
        title = QLabel(label.upper())
        title.setObjectName("MetricLabel")
        symbol_label = QLabel(symbol)
        symbol_label.setObjectName("MetricSymbol")
        top.addWidget(title)
        top.addStretch(1)
        top.addWidget(symbol_label)
        layout.addLayout(top)
        value_label = QLabel(value)
        value_label.setObjectName("MetricValue")
        layout.addWidget(value_label)


class SecurityOverviewWindow(QMainWindow):
    def __init__(self, status_provider: Callable[[], Mapping] | None = None) -> None:
        super().__init__()
        contract = model.validate_b62_safety_contract()
        if not contract["passed"]:
            raise RuntimeError("B6-2 safety contract refused: " + ";".join(contract["failures"]))

        self.status_provider = status_provider
        self.snapshot = model.build_snapshot(status_provider)
        self.card_widgets: dict[str, ProtectionCard] = {}
        self.recovery_window: rescue_home_ui.HomeWindow | None = None
        self._entrance_animations: list[QPropertyAnimation] = []
        self._animated_widgets: list[QWidget] = []

        self.setObjectName("SecurityOverviewWindow")
        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(980, 700)
        self.resize(1380, 880)
        self._build_ui()
        self._apply_theme()
        QTimer.singleShot(0, self._start_entrance_motion)

    def _build_ui(self) -> None:
        shell = QWidget()
        shell.setObjectName("AppShell")
        shell_layout = QHBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)

        sidebar = self._build_sidebar()
        shell_layout.addWidget(sidebar)

        main = QWidget()
        main.setObjectName("MainColumn")
        main_layout = QVBoxLayout(main)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        main_layout.addWidget(self._build_topbar())

        page_scroll = QScrollArea()
        page_scroll.setObjectName("PageScroll")
        page_scroll.setWidgetResizable(True)
        page_scroll.setFrameShape(QFrame.Shape.NoFrame)
        page_scroll.viewport().setObjectName("PageViewport")
        page_scroll.viewport().setAutoFillBackground(False)

        page_host = QWidget()
        page_host.setObjectName("PageHost")
        host_layout = QHBoxLayout(page_host)
        host_layout.setContentsMargins(24, 22, 24, 30)
        host_layout.addStretch(1)

        root = QWidget()
        root.setObjectName("SecurityRoot")
        root.setMaximumWidth(1280)
        root.setAutoFillBackground(False)
        page = QVBoxLayout(root)
        page.setContentsMargins(0, 0, 0, 0)
        page.setSpacing(20)

        hero = self._build_hero()
        page.addWidget(hero)

        metrics = QGridLayout()
        metrics.setHorizontalSpacing(12)
        metrics.setVerticalSpacing(12)
        metric_cards = (
            MetricCard("Ultima scansione", "Non collegata", "◷"),
            MetricCard("Rilevamenti", "—", "!"),
            MetricCard("Quarantena", "—", "▣"),
        )
        for index, metric in enumerate(metric_cards):
            metrics.addWidget(metric, 0, index)
            metrics.setColumnStretch(index, 1)
        page.addLayout(metrics)

        section_row = QHBoxLayout()
        section_title = QLabel("Moduli di protezione")
        section_title.setObjectName("SectionTitle")
        section_hint = QLabel("Disponibilità motore ≠ protezione runtime verificata")
        section_hint.setObjectName("SectionHint")
        section_row.addWidget(section_title)
        section_row.addStretch(1)
        section_row.addWidget(section_hint)
        page.addLayout(section_row)

        self.cards_grid = QGridLayout()
        self.cards_grid.setHorizontalSpacing(12)
        self.cards_grid.setVerticalSpacing(12)
        self._render_cards()
        page.addLayout(self.cards_grid)

        activity = QFrame()
        activity.setObjectName("ActivityCard")
        activity_layout = QHBoxLayout(activity)
        activity_layout.setContentsMargins(18, 16, 18, 16)
        activity_layout.setSpacing(16)
        activity_copy = QVBoxLayout()
        activity_copy.setSpacing(4)
        activity_title = QLabel("Attività recente")
        activity_title.setObjectName("CardTitle")
        self.activity_summary = QLabel(self.snapshot.recent_activity_summary)
        self.activity_summary.setObjectName("CardSummary")
        self.activity_summary.setWordWrap(True)
        activity_copy.addWidget(activity_title)
        activity_copy.addWidget(self.activity_summary)
        activity_layout.addLayout(activity_copy, 1)
        activity_state = QLabel("Non collegata")
        activity_state.setObjectName("NeutralPill")
        activity_layout.addWidget(activity_state, 0, Qt.AlignmentFlag.AlignTop)
        page.addWidget(activity)

        host_layout.addWidget(root, 1)
        host_layout.addStretch(1)
        page_scroll.setWidget(page_host)
        main_layout.addWidget(page_scroll, 1)
        shell_layout.addWidget(main, 1)
        self.setCentralWidget(shell)

        self._animated_widgets = [self.hero, *metric_cards, *self.card_widgets.values(), activity]

    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(236)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(14, 22, 14, 18)
        layout.setSpacing(8)

        brand = QHBoxLayout()
        brand.setContentsMargins(6, 0, 6, 18)
        logo = QLabel("S")
        logo.setObjectName("BrandMark")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setFixedSize(38, 38)
        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        name = QLabel("BC Sentinel")
        name.setObjectName("BrandName")
        edition = QLabel("Intelligent Protection")
        edition.setObjectName("BrandEdition")
        brand_text.addWidget(name)
        brand_text.addWidget(edition)
        brand.addWidget(logo)
        brand.addLayout(brand_text, 1)
        layout.addLayout(brand)

        self.nav_buttons: dict[str, QPushButton] = {}
        for index, (glyph, label) in enumerate(NAV_ITEMS):
            button = QPushButton(f"{glyph}   {label}")
            button.setObjectName("NavActive" if index == 0 else "NavItem")
            button.setCheckable(index == 0)
            button.setChecked(index == 0)
            button.setEnabled(index == 0)
            button.setToolTip("Dashboard attiva" if index == 0 else "Sezione prevista nella roadmap BC Sentinel")
            button.setAccessibleName(label)
            self.nav_buttons[label] = button
            layout.addWidget(button)

        layout.addStretch(1)
        divider = QFrame()
        divider.setObjectName("SidebarDivider")
        divider.setFixedHeight(1)
        layout.addWidget(divider)

        self.sidebar_scan_button = QPushButton("⚡  Quick Scan")
        self.sidebar_scan_button.setObjectName("SidebarScan")
        self.sidebar_scan_button.setEnabled(False)
        self.sidebar_scan_button.setToolTip("Smart Scan sarà attivata in B6-3")
        layout.addWidget(self.sidebar_scan_button)
        return sidebar

    def _build_topbar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("TopBar")
        bar.setFixedHeight(56)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(22, 0, 22, 0)
        title = QLabel("BC SENTINEL Intelligent Windows Protection")
        title.setObjectName("TopBarTitle")
        layout.addWidget(title)
        layout.addStretch(1)
        self.refresh_button = QPushButton("↻  Refresh status")
        self.refresh_button.setObjectName("TopBarAction")
        self.refresh_button.setAccessibleName("Refresh passive protection status")
        self.refresh_button.clicked.connect(self._refresh_snapshot)
        layout.addWidget(self.refresh_button)
        return bar

    def _build_hero(self) -> QWidget:
        self.hero = QFrame()
        self.hero.setObjectName("PostureHero")
        self.hero.setProperty("posture", self.snapshot.posture)
        layout = QHBoxLayout(self.hero)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(22)

        layout.addWidget(ShieldMark(), 0, Qt.AlignmentFlag.AlignVCenter)

        copy = QVBoxLayout()
        copy.setSpacing(6)
        self.posture_label = QLabel(self.snapshot.posture_label)
        self.posture_label.setObjectName("PosturePill")
        self.posture_label.setProperty("posture", self.snapshot.posture)
        self.posture_label.setMaximumWidth(220)
        self.posture_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.headline_label = QLabel(self.snapshot.headline)
        self.headline_label.setObjectName("HeroTitle")
        self.headline_label.setWordWrap(True)
        self.hero_summary = QLabel(self.snapshot.summary)
        self.hero_summary.setObjectName("HeroSummary")
        self.hero_summary.setWordWrap(True)
        copy.addWidget(self.posture_label, 0, Qt.AlignmentFlag.AlignLeft)
        copy.addWidget(self.headline_label)
        copy.addWidget(self.hero_summary)
        layout.addLayout(copy, 1)

        actions = QVBoxLayout()
        actions.setSpacing(8)
        actions.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        self.smart_scan_button = QPushButton("⚡  Scansione rapida")
        self.smart_scan_button.setObjectName("PrimaryDisabled")
        self.smart_scan_button.setEnabled(False)
        self.smart_scan_button.setMinimumWidth(180)
        self.smart_scan_button.setAccessibleName("Smart Scan unavailable until B6-3")
        full_scan = QPushButton("⌕  Scansione completa")
        full_scan.setObjectName("SecondaryDisabled")
        full_scan.setEnabled(False)
        full_scan.setMinimumWidth(180)
        note = QLabel("Disponibili nel prossimo milestone")
        note.setObjectName("Microcopy")
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        actions.addWidget(self.smart_scan_button)
        actions.addWidget(full_scan)
        actions.addWidget(note)
        layout.addLayout(actions)
        return self.hero

    def _render_cards(self) -> None:
        while self.cards_grid.count():
            item = self.cards_grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self.card_widgets.clear()

        for index, card in enumerate(self.snapshot.cards):
            widget = ProtectionCard(card, self._handle_card_action)
            self.card_widgets[card.card_id] = widget
            row, column = divmod(index, 2)
            self.cards_grid.addWidget(widget, row, column)
        self.cards_grid.setColumnStretch(0, 1)
        self.cards_grid.setColumnStretch(1, 1)

    def _handle_card_action(self, card_id: str) -> None:
        if card_id != model.LAYER_RECOVERY:
            return
        card = next((item for item in self.snapshot.cards if item.card_id == card_id), None)
        if card is None or not card.action_enabled:
            return
        if self.recovery_window is None:
            self.recovery_window = rescue_home_ui.HomeWindow()
            self.recovery_window.destroyed.connect(self._clear_recovery_window)
        self.recovery_window.show()
        self.recovery_window.raise_()
        self.recovery_window.activateWindow()
        self.statusBar().showMessage("System & Recovery opened. Discovery remains manual.", 5000)

    def _clear_recovery_window(self) -> None:
        self.recovery_window = None

    def _refresh_snapshot(self) -> None:
        self.refresh_button.setEnabled(False)
        try:
            self.snapshot = model.build_snapshot(self.status_provider)
            self._update_hero()
            self._render_cards()
            self._animated_widgets = [self.hero, *self.card_widgets.values()]
            self.statusBar().showMessage("Passive status refreshed. No scan was started.", 4500)
            self._start_entrance_motion(cards_only=True)
        finally:
            self.refresh_button.setEnabled(True)

    def _update_hero(self) -> None:
        self.hero.setProperty("posture", self.snapshot.posture)
        self.posture_label.setText(self.snapshot.posture_label)
        self.posture_label.setProperty("posture", self.snapshot.posture)
        self.headline_label.setText(self.snapshot.headline)
        self.hero_summary.setText(self.snapshot.summary)
        for widget in (self.hero, self.posture_label):
            widget.style().unpolish(widget)
            widget.style().polish(widget)

    def _start_entrance_motion(self, cards_only: bool = False) -> None:
        if _reduced_motion():
            return
        widgets = list(self.card_widgets.values()) if cards_only else list(self._animated_widgets)
        self._entrance_animations.clear()
        for index, widget in enumerate(widgets):
            effect = QGraphicsOpacityEffect(widget)
            widget.setGraphicsEffect(effect)
            effect.setOpacity(0.0)
            animation = QPropertyAnimation(effect, b"opacity", self)
            animation.setDuration(MOTION_TOKENS["page"] if index == 0 else MOTION_TOKENS["state"])
            animation.setStartValue(0.0)
            animation.setEndValue(1.0)
            animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            QTimer.singleShot(index * MOTION_TOKENS["stagger"], animation.start)
            self._entrance_animations.append(animation)

    def _apply_theme(self) -> None:
        app = QApplication.instance()
        if app is not None:
            font = QFont()
            font.setFamilies(["Plus Jakarta Sans", "Segoe UI Variable Text", "Segoe UI"])
            font.setPointSize(10)
            app.setFont(font)

        c = COLOR_TOKENS
        self.setStyleSheet(
            f"""
            #SecurityOverviewWindow, #AppShell, #MainColumn, #PageScroll, #PageViewport, #PageHost, #SecurityRoot {{
                background: {c['canvas']}; border: none;
            }}
            QLabel {{ color: {c['text_primary']}; background: transparent; }}
            #Sidebar {{ background: {c['sidebar']}; border-right: 1px solid {c['border_soft']}; }}
            #BrandMark {{ background: {c['accent']}; color: #062016; border-radius: 9px; font-size: 19px; font-weight: 800; }}
            #BrandName {{ color: {c['accent']}; font-size: 18px; font-weight: 750; }}
            #BrandEdition {{ color: {c['text_muted']}; font-size: 10px; }}
            #NavActive, #NavItem {{ text-align: left; padding: 10px 12px; border-radius: 8px; border: none; font-size: 13px; font-weight: 600; }}
            #NavActive {{ background: #123428; color: {c['text_primary']}; border-left: 3px solid {c['accent']}; }}
            #NavItem {{ background: transparent; color: {c['text_muted']}; }}
            #NavItem:disabled {{ color: #65716a; }}
            #SidebarDivider {{ background: {c['border_soft']}; border: none; }}
            #SidebarScan {{ background: #123428; color: #5e8875; border: 1px solid #28513f; border-radius: 8px; padding: 9px 12px; font-weight: 700; }}
            #TopBar {{ background: {c['canvas']}; border-bottom: 1px solid {c['border_soft']}; }}
            #TopBarTitle {{ color: {c['text_secondary']}; font-size: 14px; font-weight: 650; }}
            #TopBarAction {{ background: transparent; color: {c['text_secondary']}; border: 1px solid {c['border']}; border-radius: 8px; padding: 7px 11px; font-weight: 600; }}
            #TopBarAction:hover {{ background: {c['surface_2']}; color: {c['text_primary']}; }}
            #PostureHero {{ background: {c['surface_1']}; border: 1px solid {c['border']}; border-radius: 16px; }}
            #HeroTitle {{ color: #f0f5f1; font-size: 25px; font-weight: 750; }}
            #HeroSummary {{ color: {c['text_secondary']}; font-size: 13px; }}
            #PosturePill, #StatusPill, #NeutralPill {{ border-radius: 13px; padding: 4px 9px; font-size: 10px; font-weight: 750; }}
            #PosturePill[posture="{model.POSTURE_PROTECTED}"], #StatusPill[statusRole="positive"] {{ color: {c['success']}; background: #10271c; border: 1px solid #2a6045; }}
            #PosturePill[posture="{model.POSTURE_ATTENTION}"], #StatusPill[statusRole="attention"] {{ color: {c['critical']}; background: #301817; border: 1px solid #6c302e; }}
            #PosturePill[posture="{model.POSTURE_UNVERIFIED}"] {{ color: {c['warning']}; background: #2d2414; border: 1px solid #665027; }}
            #StatusPill[statusRole="neutral"], #NeutralPill {{ color: {c['text_secondary']}; background: {c['surface_3']}; border: 1px solid {c['border']}; }}
            #PrimaryDisabled, #SecondaryDisabled {{ border-radius: 8px; padding: 9px 14px; font-weight: 700; }}
            #PrimaryDisabled {{ background: #174532; color: #6c9f89; border: 1px solid #286148; }}
            #SecondaryDisabled {{ background: transparent; color: #6f7d75; border: 1px solid #344239; }}
            #Microcopy {{ color: {c['text_muted']}; font-size: 10px; }}
            #MetricCard {{ background: {c['surface_1']}; border: 1px solid {c['border_soft']}; border-radius: 12px; }}
            #MetricLabel {{ color: {c['text_muted']}; font-size: 10px; font-weight: 750; }}
            #MetricSymbol {{ color: {c['text_muted']}; font-size: 16px; }}
            #MetricValue {{ color: #edf3ee; font-size: 21px; font-weight: 700; }}
            #SectionTitle {{ color: #eef3ef; font-size: 17px; font-weight: 700; }}
            #SectionHint {{ color: {c['text_muted']}; font-size: 10px; }}
            #ProtectionCard, #ActivityCard {{ background: {c['surface_1']}; border: 1px solid {c['border_soft']}; border-radius: 12px; }}
            #ProtectionCard:hover {{ border: 1px solid {c['border']}; background: #1d2721; }}
            #ModuleIcon {{ background: {c['surface_2']}; color: {c['accent']}; border: 1px solid {c['border_soft']}; border-radius: 20px; font-size: 18px; font-weight: 700; }}
            #CardTitle {{ color: #f0f5f1; font-size: 15px; font-weight: 700; }}
            #CardDescription {{ color: {c['text_secondary']}; font-size: 12px; }}
            #CardSummary {{ color: {c['text_muted']}; font-size: 11px; }}
            #InlineButton {{ background: transparent; color: {c['text_secondary']}; border: none; padding: 5px 0; font-size: 11px; font-weight: 650; text-align: left; }}
            #InlineButton:hover {{ color: {c['accent']}; }}
            #InlineButton:focus {{ color: {c['accent']}; }}
            #RecoveryButton {{ background: {c['accent']}; color: #062016; border: 1px solid #34c996; border-radius: 8px; padding: 8px 12px; font-weight: 750; }}
            #RecoveryButton:hover {{ background: #22c990; }}
            #AdvancedPanel {{ background: #0b120e; border: 1px solid {c['border_soft']}; border-radius: 9px; }}
            #AdvancedTitle {{ color: {c['text_secondary']}; font-size: 10px; font-weight: 750; }}
            #AdvancedText {{ background: #09100c; color: #bec9c1; border: 1px solid #27332c; border-radius: 7px; font-family: Consolas, "Cascadia Mono", monospace; font-size: 10px; selection-background-color: #22523d; }}
            QScrollBar:vertical {{ background: transparent; width: 8px; margin: 2px; }}
            QScrollBar::handle:vertical {{ background: #34443b; border-radius: 4px; min-height: 34px; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
            QStatusBar {{ color: {c['text_muted']}; background: {c['canvas']}; border-top: 1px solid {c['border_soft']}; }}
            """
        )


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
    parser = argparse.ArgumentParser(description="BC Sentinel B6-2 Home security overview")
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
        payload = self_check()
        payload["window_created"] = True
        payload["window_title"] = window.windowTitle()
        payload["minimum_size"] = [window.minimumWidth(), window.minimumHeight()]
        payload["card_count"] = len(window.card_widgets)
        payload["smart_scan_enabled"] = window.smart_scan_button.isEnabled()
        print(json.dumps(payload, indent=2, sort_keys=True))
        window.close()
        return 0 if payload["passed"] else 4

    window.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
