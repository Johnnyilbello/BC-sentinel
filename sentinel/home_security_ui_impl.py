from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Callable, Final, Mapping

from PySide6.QtCore import QEasingCurve, QPointF, QPropertyAnimation, QRectF, QSize, QTimer, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap, QPolygonF
from PySide6.QtWidgets import (
    QApplication,
    QBoxLayout,
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

# Stitch/Sentinel Elite spacing scale. The 4 px base and 8 px rhythm are canonical.
SPACING_TOKENS: Final[dict[str, int]] = {
    "xs": 4,
    "sm": 8,
    "md": 16,
    "lg": 24,
    "xl": 32,
    "xxl": 48,
}

MOTION_TOKENS: Final[dict[str, int]] = {
    "micro": 140,
    "state": 200,
    "panel": 250,
    "page": 300,
    "stagger": 45,
}

# Dashboard + Sentinel Elite tokens extracted from the original Stitch bundle.
COLOR_TOKENS: Final[dict[str, str]] = {
    "canvas": "#0f1412",
    "sidebar": "#1c211f",
    "surface_lowest": "#0a0f0d",
    "surface_low": "#181d1a",
    "surface_1": "#1c211f",
    "surface_2": "#262b29",
    "surface_3": "#313634",
    "border": "#3c4a42",
    "border_soft": "#29342f",
    "text_primary": "#dde4dd",
    "text_secondary": "#bbcabf",
    "text_muted": "#86948a",
    "accent": "#10b981",
    "accent_bright": "#4edea3",
    "accent_soft": "#123428",
    "success": "#4edea3",
    "warning": "#f0b766",
    "critical": "#ff8b82",
    "cool": "#adc6ff",
}

NAV_ITEMS: Final[tuple[tuple[str, str], ...]] = (
    ("dashboard", "Dashboard"),
    ("scan", "Scansione"),
    ("quarantine", "Quarantena"),
    ("history", "Cronologia"),
    ("protection", "Protezione"),
    ("settings", "Impostazioni"),
)

MODULE_ICONS: Final[Mapping[str, str]] = {
    model.LAYER_MALWARE: "radar",
    model.LAYER_BEHAVIOR: "behavior",
    model.LAYER_WEB: "web",
    model.LAYER_RECOVERY: "recovery",
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


def _display_posture(posture: str) -> tuple[str, str, str]:
    """Consumer copy stays concise while the model remains the technical source of truth."""
    if posture == model.POSTURE_PROTECTED:
        return (
            "Protezione verificata",
            "BC Sentinel è attivo",
            "Monitoraggio runtime verificato sui livelli di protezione principali.",
        )
    if posture == model.POSTURE_ATTENTION:
        return (
            "Attenzione richiesta",
            "BC Sentinel richiede attenzione",
            "È stato verificato uno stato di protezione che richiede un controllo.",
        )
    return (
        "Verifica necessaria",
        "Stato di protezione da verificare",
        "I motori sono disponibili, ma manca una prova runtime aggiornata. "
        "BC Sentinel non mostrerà il PC come protetto senza evidenza corrente.",
    )


def _layer_state_copy(card: model.HomeProtectionCard) -> str:
    if card.status == model.STATUS_ACTIVE and card.runtime_verified:
        return "Protezione runtime verificata."
    if card.status == model.STATUS_READY:
        return "Disponibile · apertura manuale."
    if card.status == model.STATUS_ENGINE_AVAILABLE:
        return "Motore disponibile · runtime non verificato."
    if card.status == model.STATUS_ATTENTION:
        return "Richiede attenzione."
    if card.status == model.STATUS_OFF:
        return "Disattivato con stato verificato."
    return "Stato runtime non disponibile."


def _make_icon(kind: str, color: str | None = None, size: int = 20) -> QIcon:
    """Small dependency-free line icons to avoid emoji/font fallback artifacts."""
    color = color or COLOR_TOKENS["text_secondary"]
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(color), max(1.35, size / 12.0))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)

    s = float(size)
    if kind == "dashboard":
        d = s * 0.27
        gap = s * 0.14
        x = s * 0.14
        y = s * 0.14
        for r in range(2):
            for c in range(2):
                p.drawRoundedRect(QRectF(x + c * (d + gap), y + r * (d + gap), d, d), 1.5, 1.5)
    elif kind in {"scan", "protection"}:
        path = QPainterPath()
        path.moveTo(s * 0.5, s * 0.12)
        path.lineTo(s * 0.78, s * 0.23)
        path.lineTo(s * 0.75, s * 0.55)
        path.cubicTo(s * 0.73, s * 0.72, s * 0.61, s * 0.82, s * 0.5, s * 0.88)
        path.cubicTo(s * 0.39, s * 0.82, s * 0.27, s * 0.72, s * 0.25, s * 0.55)
        path.lineTo(s * 0.22, s * 0.23)
        path.closeSubpath()
        p.drawPath(path)
        if kind == "protection":
            p.drawLine(QPointF(s * 0.38, s * 0.50), QPointF(s * 0.47, s * 0.59))
            p.drawLine(QPointF(s * 0.47, s * 0.59), QPointF(s * 0.65, s * 0.39))
    elif kind == "quarantine":
        p.drawRoundedRect(QRectF(s * 0.18, s * 0.32, s * 0.64, s * 0.48), 2, 2)
        p.drawLine(QPointF(s * 0.18, s * 0.40), QPointF(s * 0.82, s * 0.40))
        p.drawLine(QPointF(s * 0.40, s * 0.19), QPointF(s * 0.60, s * 0.19))
        p.drawLine(QPointF(s * 0.50, s * 0.19), QPointF(s * 0.50, s * 0.58))
        p.drawLine(QPointF(s * 0.42, s * 0.50), QPointF(s * 0.50, s * 0.58))
        p.drawLine(QPointF(s * 0.58, s * 0.50), QPointF(s * 0.50, s * 0.58))
    elif kind == "history":
        p.drawArc(QRectF(s * 0.18, s * 0.18, s * 0.64, s * 0.64), 35 * 16, 300 * 16)
        p.drawLine(QPointF(s * 0.20, s * 0.33), QPointF(s * 0.12, s * 0.26))
        p.drawLine(QPointF(s * 0.20, s * 0.33), QPointF(s * 0.26, s * 0.23))
        p.drawLine(QPointF(s * 0.50, s * 0.33), QPointF(s * 0.50, s * 0.52))
        p.drawLine(QPointF(s * 0.50, s * 0.52), QPointF(s * 0.64, s * 0.58))
    elif kind == "settings":
        p.drawEllipse(QRectF(s * 0.35, s * 0.35, s * 0.30, s * 0.30))
        for angle in range(0, 360, 45):
            import math
            a = math.radians(angle)
            inner = QPointF(s * (0.5 + 0.25 * math.cos(a)), s * (0.5 + 0.25 * math.sin(a)))
            outer = QPointF(s * (0.5 + 0.38 * math.cos(a)), s * (0.5 + 0.38 * math.sin(a)))
            p.drawLine(inner, outer)
    elif kind in {"refresh", "recovery"}:
        p.drawArc(QRectF(s * 0.18, s * 0.18, s * 0.64, s * 0.64), 30 * 16, 285 * 16)
        p.drawLine(QPointF(s * 0.79, s * 0.22), QPointF(s * 0.79, s * 0.40))
        p.drawLine(QPointF(s * 0.79, s * 0.22), QPointF(s * 0.61, s * 0.23))
    elif kind == "bolt":
        poly = QPolygonF(
            [
                QPointF(s * 0.57, s * 0.08),
                QPointF(s * 0.30, s * 0.52),
                QPointF(s * 0.49, s * 0.52),
                QPointF(s * 0.41, s * 0.92),
                QPointF(s * 0.72, s * 0.42),
                QPointF(s * 0.52, s * 0.42),
            ]
        )
        p.drawPolyline(poly)
    elif kind == "search":
        p.drawEllipse(QRectF(s * 0.19, s * 0.19, s * 0.48, s * 0.48))
        p.drawLine(QPointF(s * 0.61, s * 0.61), QPointF(s * 0.84, s * 0.84))
    elif kind == "radar":
        p.drawEllipse(QRectF(s * 0.18, s * 0.18, s * 0.64, s * 0.64))
        p.drawEllipse(QRectF(s * 0.33, s * 0.33, s * 0.34, s * 0.34))
        p.drawLine(QPointF(s * 0.50, s * 0.50), QPointF(s * 0.74, s * 0.31))
    elif kind == "behavior":
        p.drawPolyline(
            QPolygonF(
                [
                    QPointF(s * 0.12, s * 0.58),
                    QPointF(s * 0.28, s * 0.58),
                    QPointF(s * 0.38, s * 0.32),
                    QPointF(s * 0.50, s * 0.72),
                    QPointF(s * 0.61, s * 0.45),
                    QPointF(s * 0.88, s * 0.45),
                ]
            )
        )
    elif kind == "web":
        p.drawEllipse(QRectF(s * 0.16, s * 0.16, s * 0.68, s * 0.68))
        p.drawArc(QRectF(s * 0.34, s * 0.16, s * 0.32, s * 0.68), 90 * 16, 180 * 16)
        p.drawArc(QRectF(s * 0.34, s * 0.16, s * 0.32, s * 0.68), 270 * 16, 180 * 16)
        p.drawLine(QPointF(s * 0.18, s * 0.50), QPointF(s * 0.82, s * 0.50))
    elif kind == "info":
        p.drawEllipse(QRectF(s * 0.16, s * 0.16, s * 0.68, s * 0.68))
        p.drawLine(QPointF(s * 0.50, s * 0.43), QPointF(s * 0.50, s * 0.67))
        p.drawPoint(QPointF(s * 0.50, s * 0.31))
    else:
        p.drawEllipse(QRectF(s * 0.36, s * 0.36, s * 0.28, s * 0.28))
    p.end()
    return QIcon(pix)


class SentinelLogo(QWidget):
    """Compact vector interpretation of the original Stitch Sentinel shield."""

    def __init__(self, size: int = 44, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._size = size
        self.setFixedSize(size, size)
        self.setAccessibleName("BC Sentinel logo")

    def paintEvent(self, event) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = float(self._size)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#202a25"))
        p.drawRoundedRect(QRectF(1, 1, s - 2, s - 2), 9, 9)

        pen = QPen(QColor(COLOR_TOKENS["accent"]), max(1.8, s / 18))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)

        outer = QPainterPath()
        outer.moveTo(s * 0.50, s * 0.16)
        outer.lineTo(s * 0.76, s * 0.24)
        outer.lineTo(s * 0.74, s * 0.55)
        outer.cubicTo(s * 0.72, s * 0.72, s * 0.61, s * 0.82, s * 0.50, s * 0.88)
        outer.cubicTo(s * 0.39, s * 0.82, s * 0.28, s * 0.72, s * 0.26, s * 0.55)
        outer.lineTo(s * 0.24, s * 0.24)
        outer.closeSubpath()
        p.drawPath(outer)

        inner = QPainterPath()
        inner.moveTo(s * 0.62, s * 0.36)
        inner.cubicTo(s * 0.56, s * 0.31, s * 0.43, s * 0.31, s * 0.39, s * 0.39)
        inner.cubicTo(s * 0.35, s * 0.47, s * 0.42, s * 0.52, s * 0.50, s * 0.52)
        inner.cubicTo(s * 0.60, s * 0.52, s * 0.66, s * 0.57, s * 0.61, s * 0.65)
        inner.cubicTo(s * 0.56, s * 0.73, s * 0.43, s * 0.72, s * 0.37, s * 0.67)
        p.drawPath(inner)


class ModuleSwitch(QWidget):
    """Read-only Windows-style state indicator in B6-2."""

    def __init__(self, on: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.on = bool(on)
        self.setFixedSize(44, 24)
        self.setAccessibleName("Protection runtime switch")
        self.setToolTip("Sola lettura in B6-2. I controlli runtime arriveranno in un milestone successivo.")

    def paintEvent(self, event) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        track = QColor(COLOR_TOKENS["accent"] if self.on else "#27342e")
        border = QColor("#2a8f69" if self.on else "#506158")
        p.setPen(QPen(border, 1))
        p.setBrush(track)
        p.drawRoundedRect(1, 2, 42, 20, 10, 10)
        x = 23 if self.on else 4
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#eef5f0" if self.on else "#91a097"))
        p.drawEllipse(x, 5, 14, 14)


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
        self.setMinimumWidth(280)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 14)
        layout.setSpacing(10)

        top = QHBoxLayout()
        top.setSpacing(14)

        icon_wrap = QLabel()
        icon_wrap.setObjectName("ModuleIcon")
        icon_wrap.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_wrap.setFixedSize(42, 42)
        icon_wrap.setPixmap(_make_icon(MODULE_ICONS.get(card.card_id, "info"), COLOR_TOKENS["accent"], 21).pixmap(21, 21))
        top.addWidget(icon_wrap, 0, Qt.AlignmentFlag.AlignTop)

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

        state = QLabel(_layer_state_copy(card))
        state.setObjectName("CardState")
        state.setProperty("statusRole", _status_role(card.status))
        state.setWordWrap(True)
        layout.addWidget(state)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.details_button = QPushButton("Dettagli avanzati")
        self.details_button.setObjectName("InlineButton")
        self.details_button.setCheckable(True)
        self.details_button.setIcon(_make_icon("info", COLOR_TOKENS["text_muted"], 15))
        self.details_button.setIconSize(QSize(15, 15))
        self.details_button.setAccessibleName(f"Dettagli avanzati per {card.label}")
        self.details_button.toggled.connect(self._toggle_details)
        actions.addWidget(self.details_button)
        actions.addStretch(1)

        self.action_button = QPushButton("Apri" if card.action_enabled else card.action_label)
        self.action_button.setObjectName("RecoveryButton" if card.action_enabled else "HiddenAction")
        self.action_button.setEnabled(card.action_enabled)
        self.action_button.setVisible(card.action_enabled)
        if card.action_enabled:
            self.action_button.setIcon(_make_icon("recovery", "#062016", 16))
            self.action_button.setIconSize(QSize(16, 16))
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
        details_title = QLabel("Evidenza tecnica")
        details_title.setObjectName("AdvancedTitle")
        self.details_text = QPlainTextEdit()
        self.details_text.setObjectName("AdvancedText")
        self.details_text.setReadOnly(True)
        self.details_text.setMinimumHeight(164)
        self.details_text.setPlainText(json.dumps(card.advanced_details, indent=2, sort_keys=True, default=str))
        self.details_text.setAccessibleName(f"Evidenza tecnica per {card.label}")
        details_layout.addWidget(details_title)
        details_layout.addWidget(self.details_text)
        layout.addWidget(self.details_panel)

    def _toggle_details(self, expanded: bool) -> None:
        target = 222 if expanded else 0
        self.details_button.setText("Nascondi dettagli" if expanded else "Dettagli avanzati")
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
    def __init__(self, label: str, value: str, icon_kind: str, accent: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("MetricCard")
        self.setProperty("accentMetric", accent)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(102)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 15, 18, 15)
        layout.setSpacing(8)
        top = QHBoxLayout()
        title = QLabel(label.upper())
        title.setObjectName("MetricLabel")
        icon = QLabel()
        icon.setPixmap(_make_icon(icon_kind, COLOR_TOKENS["accent"] if accent else COLOR_TOKENS["text_muted"], 18).pixmap(18, 18))
        top.addWidget(title)
        top.addStretch(1)
        top.addWidget(icon)
        layout.addLayout(top)
        value_label = QLabel(value)
        value_label.setObjectName("MetricValueAccent" if accent else "MetricValue")
        value_label.setWordWrap(False)
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
        self._last_layout_mode: tuple[bool, bool] | None = None

        self.setObjectName("SecurityOverviewWindow")
        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(1080, 720)
        self.resize(1440, 900)
        self._build_ui()
        self._apply_theme()
        QTimer.singleShot(0, self._post_layout_setup)
        QTimer.singleShot(0, self._start_entrance_motion)

    def _build_ui(self) -> None:
        shell = QWidget()
        shell.setObjectName("AppShell")
        shell_layout = QHBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)

        self.sidebar = self._build_sidebar()
        shell_layout.addWidget(self.sidebar)

        self.main_column = QWidget()
        self.main_column.setObjectName("MainColumn")
        main_layout = QVBoxLayout(self.main_column)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        main_layout.addWidget(self._build_topbar())

        self.page_scroll = QScrollArea()
        self.page_scroll.setObjectName("PageScroll")
        self.page_scroll.setWidgetResizable(True)
        self.page_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.page_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.page_scroll.viewport().setObjectName("PageViewport")
        self.page_scroll.viewport().setAutoFillBackground(False)

        page_host = QWidget()
        page_host.setObjectName("PageHost")
        host_layout = QVBoxLayout(page_host)
        host_layout.setContentsMargins(24, 24, 24, 32)
        host_layout.setSpacing(0)

        self.content_root = QWidget()
        self.content_root.setObjectName("SecurityRoot")
        self.content_root.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.content_root.setAutoFillBackground(False)
        page = QVBoxLayout(self.content_root)
        page.setContentsMargins(0, 0, 0, 0)
        page.setSpacing(24)

        self.hero = self._build_hero()
        page.addWidget(self.hero)

        self.metrics_grid = QGridLayout()
        self.metrics_grid.setHorizontalSpacing(16)
        self.metrics_grid.setVerticalSpacing(16)
        self.metric_cards = [
            MetricCard("Ultima scansione", "Non disponibile", "history"),
            MetricCard("Rilevamenti attivi", "—", "protection", accent=True),
            MetricCard("File in quarantena", "—", "quarantine"),
        ]
        self._render_metrics(columns=3)
        page.addLayout(self.metrics_grid)

        self.modules_panel = QFrame()
        self.modules_panel.setObjectName("ModulesPanel")
        modules_layout = QVBoxLayout(self.modules_panel)
        modules_layout.setContentsMargins(24, 20, 24, 24)
        modules_layout.setSpacing(18)

        module_header = QHBoxLayout()
        module_header.setSpacing(10)
        module_icon = QLabel()
        module_icon.setPixmap(_make_icon("protection", COLOR_TOKENS["accent"], 21).pixmap(21, 21))
        section_title = QLabel("Moduli Protezione")
        section_title.setObjectName("SectionTitle")
        self.section_hint = QLabel("Disponibilità motore ≠ protezione runtime verificata")
        self.section_hint.setObjectName("SectionHint")
        self.section_hint.setWordWrap(True)
        module_header.addWidget(module_icon)
        module_header.addWidget(section_title)
        module_header.addStretch(1)
        module_header.addWidget(self.section_hint)
        modules_layout.addLayout(module_header)

        divider = QFrame()
        divider.setObjectName("SectionDivider")
        divider.setFixedHeight(1)
        modules_layout.addWidget(divider)

        self.cards_grid = QGridLayout()
        self.cards_grid.setHorizontalSpacing(16)
        self.cards_grid.setVerticalSpacing(16)
        self._render_cards(columns=2)
        modules_layout.addLayout(self.cards_grid)
        page.addWidget(self.modules_panel)

        self.activity = QFrame()
        self.activity.setObjectName("ActivityCard")
        activity_layout = QHBoxLayout(self.activity)
        activity_layout.setContentsMargins(18, 14, 18, 14)
        activity_layout.setSpacing(16)
        activity_copy = QVBoxLayout()
        activity_copy.setSpacing(3)
        activity_title = QLabel("Attività recente")
        activity_title.setObjectName("CardTitle")
        self.activity_summary = QLabel("La cronologia verrà collegata alla Home in un milestone successivo.")
        self.activity_summary.setObjectName("CardSummary")
        self.activity_summary.setWordWrap(True)
        activity_copy.addWidget(activity_title)
        activity_copy.addWidget(self.activity_summary)
        activity_layout.addLayout(activity_copy, 1)
        activity_state = QLabel("Non collegata")
        activity_state.setObjectName("NeutralPill")
        activity_layout.addWidget(activity_state, 0, Qt.AlignmentFlag.AlignVCenter)
        page.addWidget(self.activity)

        host_layout.addWidget(self.content_root)
        host_layout.addStretch(1)
        self.page_scroll.setWidget(page_host)
        main_layout.addWidget(self.page_scroll, 1)
        shell_layout.addWidget(self.main_column, 1)
        self.setCentralWidget(shell)

        self._animated_widgets = [self.hero, *self.metric_cards, self.modules_panel, self.activity]

    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(260)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 24, 16, 18)
        layout.setSpacing(8)

        brand = QHBoxLayout()
        brand.setContentsMargins(2, 0, 2, 24)
        brand.setSpacing(12)
        brand.addWidget(SentinelLogo(44))
        brand_text = QVBoxLayout()
        brand_text.setSpacing(1)
        name = QLabel("BC Sentinel")
        name.setObjectName("BrandName")
        edition = QLabel("Enterprise Shield")
        edition.setObjectName("BrandEdition")
        brand_text.addWidget(name)
        brand_text.addWidget(edition)
        brand.addLayout(brand_text, 1)
        layout.addLayout(brand)

        self.nav_buttons: dict[str, QPushButton] = {}
        for index, (icon_kind, label) in enumerate(NAV_ITEMS):
            button = QPushButton(label)
            button.setObjectName("NavActive" if index == 0 else "NavItem")
            button.setIcon(_make_icon(icon_kind, COLOR_TOKENS["accent"] if index == 0 else COLOR_TOKENS["text_secondary"], 20))
            button.setIconSize(QSize(20, 20))
            button.setCheckable(index == 0)
            button.setChecked(index == 0)
            button.setEnabled(index == 0)
            button.setToolTip("Dashboard attiva" if index == 0 else "Sezione prevista nella roadmap BC Sentinel")
            button.setAccessibleName(label)
            self.nav_buttons[label] = button
            layout.addWidget(button)

        layout.addStretch(1)

        self.sidebar_scan_button = QPushButton("Quick Scan · B6-3")
        self.sidebar_scan_button.setObjectName("SidebarScan")
        self.sidebar_scan_button.setIcon(_make_icon("bolt", COLOR_TOKENS["accent"], 18))
        self.sidebar_scan_button.setIconSize(QSize(18, 18))
        self.sidebar_scan_button.setEnabled(False)
        self.sidebar_scan_button.setToolTip("Quick Scan sarà attivata in B6-3")
        layout.addWidget(self.sidebar_scan_button)

        divider = QFrame()
        divider.setObjectName("SidebarDivider")
        divider.setFixedHeight(1)
        layout.addWidget(divider)

        for icon_kind, label in (("info", "Supporto"), ("protection", "Account")):
            button = QPushButton(label)
            button.setObjectName("SidebarFooterItem")
            button.setIcon(_make_icon(icon_kind, COLOR_TOKENS["text_muted"], 18))
            button.setIconSize(QSize(18, 18))
            button.setEnabled(False)
            layout.addWidget(button)

        return sidebar

    def _build_topbar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("TopBar")
        bar.setFixedHeight(56)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(24, 0, 18, 0)
        title = QLabel("BC SENTINEL Intelligent Windows Protection")
        title.setObjectName("TopBarTitle")
        layout.addWidget(title)
        layout.addStretch(1)
        self.refresh_button = QPushButton("Aggiorna stato")
        self.refresh_button.setObjectName("TopBarAction")
        self.refresh_button.setIcon(_make_icon("refresh", COLOR_TOKENS["text_secondary"], 16))
        self.refresh_button.setIconSize(QSize(16, 16))
        self.refresh_button.setAccessibleName("Aggiorna stato di protezione passivo")
        self.refresh_button.clicked.connect(self._refresh_snapshot)
        layout.addWidget(self.refresh_button)
        return bar

    def _build_hero(self) -> QWidget:
        hero = QFrame()
        hero.setObjectName("PostureHero")
        hero.setProperty("posture", self.snapshot.posture)
        hero.setMinimumHeight(170)

        self.hero_layout = QBoxLayout(QBoxLayout.Direction.LeftToRight, hero)
        self.hero_layout.setContentsMargins(30, 24, 30, 24)
        self.hero_layout.setSpacing(24)

        self.hero_layout.addWidget(SentinelLogo(82), 0, Qt.AlignmentFlag.AlignVCenter)

        copy = QVBoxLayout()
        copy.setSpacing(7)
        badge_text, headline, summary = _display_posture(self.snapshot.posture)
        self.posture_label = QLabel(badge_text)
        self.posture_label.setObjectName("PosturePill")
        self.posture_label.setProperty("posture", self.snapshot.posture)
        self.posture_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.posture_label.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)

        self.headline_label = QLabel(headline)
        self.headline_label.setObjectName("HeroTitle")
        self.headline_label.setWordWrap(True)
        self.headline_label.setMinimumWidth(320)

        self.hero_summary = QLabel(summary)
        self.hero_summary.setObjectName("HeroSummary")
        self.hero_summary.setWordWrap(True)
        self.hero_summary.setMaximumWidth(620)

        copy.addWidget(self.posture_label, 0, Qt.AlignmentFlag.AlignLeft)
        copy.addWidget(self.headline_label)
        copy.addWidget(self.hero_summary)
        self.hero_layout.addLayout(copy, 1)

        self.hero_actions = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.hero_actions.setSpacing(14)
        self.hero_actions.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        self.smart_scan_button = QPushButton("Scansione rapida")
        self.smart_scan_button.setObjectName("PrimaryDisabled")
        self.smart_scan_button.setIcon(_make_icon("bolt", "#6c9f89", 18))
        self.smart_scan_button.setIconSize(QSize(18, 18))
        self.smart_scan_button.setEnabled(False)
        self.smart_scan_button.setMinimumWidth(190)
        self.smart_scan_button.setAccessibleName("Smart Scan non disponibile fino a B6-3")

        self.full_scan_button = QPushButton("Scansione completa")
        self.full_scan_button.setObjectName("SecondaryDisabled")
        self.full_scan_button.setIcon(_make_icon("search", "#738178", 18))
        self.full_scan_button.setIconSize(QSize(18, 18))
        self.full_scan_button.setEnabled(False)
        self.full_scan_button.setMinimumWidth(190)

        self.hero_actions.addWidget(self.smart_scan_button)
        self.hero_actions.addWidget(self.full_scan_button)
        self.hero_layout.addLayout(self.hero_actions)
        return hero

    def _render_metrics(self, columns: int) -> None:
        while self.metrics_grid.count():
            item = self.metrics_grid.takeAt(0)
            if item.widget() is not None:
                item.widget().setParent(None)
        for index, card in enumerate(self.metric_cards):
            row, col = divmod(index, columns)
            self.metrics_grid.addWidget(card, row, col)
        for col in range(max(1, columns)):
            self.metrics_grid.setColumnStretch(col, 1)

    def _render_cards(self, columns: int = 2) -> None:
        existing = list(self.card_widgets.values())
        if not existing:
            for card in self.snapshot.cards:
                self.card_widgets[card.card_id] = ProtectionCard(card, self._handle_card_action)
            existing = list(self.card_widgets.values())

        while self.cards_grid.count():
            item = self.cards_grid.takeAt(0)
            if item.widget() is not None:
                item.widget().setParent(None)

        for index, widget in enumerate(existing):
            row, column = divmod(index, columns)
            self.cards_grid.addWidget(widget, row, column)
        for col in range(max(1, columns)):
            self.cards_grid.setColumnStretch(col, 1)

    def _rebuild_cards_for_snapshot(self) -> None:
        while self.cards_grid.count():
            item = self.cards_grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self.card_widgets.clear()
        columns = 2 if self._content_width() >= 900 else 1
        self._render_cards(columns=columns)

    def _content_width(self) -> int:
        return max(0, self.page_scroll.viewport().width() - 48)

    def _post_layout_setup(self) -> None:
        self._apply_responsive_layout(force=True)

    def _apply_responsive_layout(self, force: bool = False) -> None:
        width = self._content_width()
        compact = width < 900
        narrow_metrics = width < 760
        mode = (compact, narrow_metrics)
        if not force and mode == self._last_layout_mode:
            return
        self._last_layout_mode = mode

        self.hero_layout.setDirection(
            QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight
        )
        self.hero_actions.setDirection(
            QBoxLayout.Direction.TopToBottom if width < 1060 else QBoxLayout.Direction.LeftToRight
        )
        self.section_hint.setVisible(width >= 820)
        self._render_metrics(columns=1 if narrow_metrics else 3)
        self._render_cards(columns=1 if compact else 2)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        QTimer.singleShot(0, self._apply_responsive_layout)

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
        self.statusBar().showMessage("System & Recovery aperto. La discovery resta manuale.", 5000)

    def _clear_recovery_window(self) -> None:
        self.recovery_window = None

    def _refresh_snapshot(self) -> None:
        self.refresh_button.setEnabled(False)
        try:
            self.snapshot = model.build_snapshot(self.status_provider)
            self._update_hero()
            self._rebuild_cards_for_snapshot()
            self._animated_widgets = [self.hero, self.modules_panel]
            self.statusBar().showMessage("Stato aggiornato passivamente. Nessuna scansione avviata.", 4500)
            self._start_entrance_motion(cards_only=True)
        finally:
            self.refresh_button.setEnabled(True)

    def _update_hero(self) -> None:
        self.hero.setProperty("posture", self.snapshot.posture)
        badge, headline, summary = _display_posture(self.snapshot.posture)
        self.posture_label.setText(badge)
        self.posture_label.setProperty("posture", self.snapshot.posture)
        self.headline_label.setText(headline)
        self.hero_summary.setText(summary)
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
                background: {c['canvas']};
                border: none;
            }}
            QLabel {{
                color: {c['text_primary']};
                background: transparent;
            }}

            #Sidebar {{
                background: {c['sidebar']};
                border-right: 1px solid {c['border']};
            }}
            #BrandName {{
                color: {c['accent']};
                font-size: 20px;
                font-weight: 700;
            }}
            #BrandEdition {{
                color: {c['text_secondary']};
                font-size: 11px;
                font-weight: 500;
            }}
            #NavActive, #NavItem, #SidebarFooterItem {{
                text-align: left;
                padding: 10px 12px;
                border-radius: 8px;
                border: none;
                font-size: 14px;
                font-weight: 600;
            }}
            #NavActive {{
                background: #14382c;
                color: {c['text_primary']};
                border-left: 3px solid {c['accent']};
            }}
            #NavItem, #SidebarFooterItem {{
                background: transparent;
                color: {c['text_secondary']};
            }}
            #NavItem:disabled, #SidebarFooterItem:disabled {{
                color: #78877f;
            }}
            #SidebarDivider {{
                background: {c['border_soft']};
                border: none;
                margin-top: 6px;
                margin-bottom: 6px;
            }}
            #SidebarScan {{
                background: #153a2d;
                color: #7ea592;
                border: 1px solid #2b654c;
                border-radius: 8px;
                padding: 10px 12px;
                font-size: 13px;
                font-weight: 700;
            }}

            #TopBar {{
                background: {c['canvas']};
                border-bottom: 1px solid {c['border']};
            }}
            #TopBarTitle {{
                color: {c['text_primary']};
                font-size: 15px;
                font-weight: 650;
            }}
            #TopBarAction {{
                background: transparent;
                color: {c['text_secondary']};
                border: 1px solid {c['border']};
                border-radius: 8px;
                padding: 7px 11px;
                font-size: 12px;
                font-weight: 600;
            }}
            #TopBarAction:hover {{
                background: {c['surface_2']};
                color: {c['text_primary']};
            }}

            #PostureHero {{
                background: {c['surface_1']};
                border: 1px solid {c['border']};
                border-radius: 24px;
            }}
            #HeroTitle {{
                color: #f2f6f3;
                font-size: 28px;
                font-weight: 700;
            }}
            #HeroSummary {{
                color: {c['text_secondary']};
                font-size: 14px;
            }}
            #PosturePill, #StatusPill, #NeutralPill {{
                border-radius: 12px;
                padding: 4px 9px;
                font-size: 11px;
                font-weight: 700;
            }}
            #PosturePill[posture="{model.POSTURE_PROTECTED}"], #StatusPill[statusRole="positive"] {{
                color: {c['success']};
                background: #10271c;
                border: 1px solid #2a6045;
            }}
            #PosturePill[posture="{model.POSTURE_ATTENTION}"], #StatusPill[statusRole="attention"] {{
                color: {c['critical']};
                background: #301817;
                border: 1px solid #6c302e;
            }}
            #PosturePill[posture="{model.POSTURE_UNVERIFIED}"] {{
                color: {c['warning']};
                background: #2d2414;
                border: 1px solid #665027;
            }}
            #StatusPill[statusRole="neutral"], #NeutralPill {{
                color: {c['text_secondary']};
                background: {c['surface_3']};
                border: 1px solid {c['border']};
            }}
            #PrimaryDisabled, #SecondaryDisabled {{
                border-radius: 8px;
                padding: 10px 16px;
                font-size: 14px;
                font-weight: 700;
            }}
            #PrimaryDisabled {{
                background: #174532;
                color: #79a892;
                border: 1px solid #286148;
            }}
            #SecondaryDisabled {{
                background: transparent;
                color: #7d8c84;
                border: 1px solid #405047;
            }}

            #MetricCard {{
                background: {c['surface_1']};
                border: 1px solid {c['border']};
                border-radius: 16px;
            }}
            #MetricCard[accentMetric="true"] {{
                border-left: 4px solid {c['accent']};
            }}
            #MetricLabel {{
                color: {c['text_secondary']};
                font-size: 12px;
                font-weight: 650;
            }}
            #MetricValue {{
                color: #f0f5f1;
                font-size: 24px;
                font-weight: 700;
            }}
            #MetricValueAccent {{
                color: {c['accent']};
                font-size: 24px;
                font-weight: 700;
            }}

            #ModulesPanel {{
                background: {c['surface_1']};
                border: 1px solid {c['border']};
                border-radius: 24px;
            }}
            #SectionTitle {{
                color: #f0f5f1;
                font-size: 18px;
                font-weight: 700;
            }}
            #SectionHint {{
                color: {c['text_muted']};
                font-size: 11px;
            }}
            #SectionDivider {{
                background: {c['border']};
                border: none;
            }}
            #ProtectionCard {{
                background: {c['canvas']};
                border: 1px solid #344139;
                border-radius: 16px;
            }}
            #ProtectionCard:hover {{
                border: 1px solid {c['border']};
                background: #111813;
            }}
            #ModuleIcon {{
                background: {c['surface_2']};
                border: 1px solid {c['border_soft']};
                border-radius: 21px;
            }}
            #CardTitle {{
                color: #f1f5f2;
                font-size: 16px;
                font-weight: 700;
            }}
            #CardDescription {{
                color: {c['text_secondary']};
                font-size: 13px;
            }}
            #CardSummary {{
                color: {c['text_muted']};
                font-size: 12px;
            }}
            #CardState {{
                color: {c['text_muted']};
                font-size: 12px;
                padding-left: 56px;
            }}
            #CardState[statusRole="positive"] {{
                color: {c['accent_bright']};
            }}
            #CardState[statusRole="attention"] {{
                color: {c['critical']};
            }}
            #InlineButton {{
                background: transparent;
                color: {c['text_secondary']};
                border: none;
                padding: 5px 0;
                font-size: 11px;
                font-weight: 650;
                text-align: left;
            }}
            #InlineButton:hover, #InlineButton:focus {{
                color: {c['accent']};
            }}
            #RecoveryButton {{
                background: {c['accent']};
                color: #062016;
                border: 1px solid #34c996;
                border-radius: 8px;
                padding: 7px 12px;
                font-size: 12px;
                font-weight: 750;
            }}
            #RecoveryButton:hover {{
                background: #22c990;
            }}

            #ActivityCard {{
                background: {c['surface_1']};
                border: 1px solid {c['border_soft']};
                border-radius: 16px;
            }}
            #AdvancedPanel {{
                background: {c['surface_lowest']};
                border: 1px solid {c['border_soft']};
                border-radius: 10px;
            }}
            #AdvancedTitle {{
                color: {c['text_secondary']};
                font-size: 11px;
                font-weight: 700;
            }}
            #AdvancedText {{
                background: #09100c;
                color: #bec9c1;
                border: 1px solid #27332c;
                border-radius: 8px;
                font-family: Consolas, "Cascadia Mono", monospace;
                font-size: 10px;
                selection-background-color: #22523d;
            }}
            QScrollBar:vertical {{
                background: transparent;
                width: 8px;
                margin: 2px;
            }}
            QScrollBar::handle:vertical {{
                background: #34443b;
                border-radius: 4px;
                min-height: 34px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QStatusBar {{
                color: {c['text_muted']};
                background: {c['canvas']};
                border-top: 1px solid {c['border_soft']};
            }}
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
        window.resize(1600, 980)
        window.show()
        app.processEvents()
        payload = self_check()
        payload["window_created"] = True
        payload["window_title"] = window.windowTitle()
        payload["minimum_size"] = [window.minimumWidth(), window.minimumHeight()]
        payload["card_count"] = len(window.card_widgets)
        payload["smart_scan_enabled"] = window.smart_scan_button.isEnabled()
        payload["content_width"] = window.content_root.width()
        payload["hero_width"] = window.hero.width()
        payload["horizontal_scroll_max"] = window.page_scroll.horizontalScrollBar().maximum()
        print(json.dumps(payload, indent=2, sort_keys=True))
        window.close()
        return 0 if payload["passed"] else 4

    window.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
