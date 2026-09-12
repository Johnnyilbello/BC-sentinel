from __future__ import annotations

"""BC Sentinel desktop design system extracted from the product-owner Stitch bundle.

Visual source of truth:
- Sentinel Elite for the application shell and consumer-security surfaces.
- Brutalist Luxe Command only for dense expert/history/evidence tables.

This module intentionally contains presentation primitives only. It never starts scans,
changes protection state, mutates quarantine, or dispatches Rescue actions.
"""

import math
from typing import Final

from PySide6.QtCore import QPointF, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap, QPolygonF
from PySide6.QtWidgets import QLabel, QSizePolicy, QWidget

COLORS: Final[dict[str, str]] = {
    "canvas": "#0f1412",
    "sidebar": "#1c211f",
    "surface_lowest": "#0a0f0d",
    "surface_low": "#181d1a",
    "surface": "#1c211f",
    "surface_high": "#262b29",
    "surface_highest": "#313634",
    "border": "#3c4a42",
    "border_soft": "#29342f",
    "text": "#dde4dd",
    "text_secondary": "#bbcabf",
    "text_muted": "#86948a",
    "accent": "#10b981",
    "accent_bright": "#4edea3",
    "accent_container": "#005236",
    "accent_soft": "#123428",
    "warning": "#f0b766",
    "danger": "#ff8b82",
    "danger_soft": "#301817",
    "info": "#adc6ff",
    "focus": "#6ffbbe",
}

SPACING: Final[dict[str, int]] = {"xs": 4, "sm": 8, "md": 16, "lg": 24, "xl": 32, "xxl": 48}
RADIUS: Final[dict[str, int]] = {"control": 8, "card": 16, "panel": 24, "pill": 999}
MOTION: Final[dict[str, int]] = {"micro": 140, "state": 200, "panel": 250, "page": 300, "stagger": 45}
BREAKPOINTS: Final[dict[str, int]] = {"wide": 1180, "desktop": 960, "compact": 820, "mobile": 680}
NAV_ITEMS: Final[tuple[tuple[str, str], ...]] = (
    ("dashboard", "Dashboard"),
    ("scan", "Scansione"),
    ("quarantine", "Quarantena"),
    ("history", "Cronologia"),
    ("protection", "Protezione"),
    ("settings", "Impostazioni"),
)


def make_icon(kind: str, color: str | None = None, size: int = 20) -> QIcon:
    """Dependency-free Material-like line icons; avoids emoji/font fallback artifacts."""
    color = color or COLORS["text_secondary"]
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
        d, gap, x, y = s * 0.27, s * 0.14, s * 0.14, s * 0.14
        for r in range(2):
            for c in range(2):
                p.drawRoundedRect(QRectF(x + c * (d + gap), y + r * (d + gap), d, d), 1.5, 1.5)
    elif kind in {"scan", "protection", "shield"}:
        path = QPainterPath()
        path.moveTo(s * 0.50, s * 0.10); path.lineTo(s * 0.79, s * 0.22); path.lineTo(s * 0.76, s * 0.55)
        path.cubicTo(s * 0.73, s * 0.72, s * 0.61, s * 0.83, s * 0.50, s * 0.89)
        path.cubicTo(s * 0.39, s * 0.83, s * 0.27, s * 0.72, s * 0.24, s * 0.55)
        path.lineTo(s * 0.21, s * 0.22); path.closeSubpath(); p.drawPath(path)
        if kind in {"protection", "shield"}:
            p.drawLine(QPointF(s * 0.37, s * 0.50), QPointF(s * 0.47, s * 0.60))
            p.drawLine(QPointF(s * 0.47, s * 0.60), QPointF(s * 0.66, s * 0.38))
    elif kind == "quarantine":
        p.drawRoundedRect(QRectF(s * 0.18, s * 0.31, s * 0.64, s * 0.50), 2, 2)
        p.drawLine(QPointF(s * 0.18, s * 0.40), QPointF(s * 0.82, s * 0.40))
        p.drawLine(QPointF(s * 0.37, s * 0.20), QPointF(s * 0.63, s * 0.20)); p.drawLine(QPointF(s * 0.50, s * 0.20), QPointF(s * 0.50, s * 0.62))
    elif kind == "history":
        p.drawArc(QRectF(s * 0.17, s * 0.17, s * 0.66, s * 0.66), 35 * 16, 300 * 16)
        p.drawLine(QPointF(s * 0.21, s * 0.33), QPointF(s * 0.12, s * 0.25)); p.drawLine(QPointF(s * 0.50, s * 0.31), QPointF(s * 0.50, s * 0.52)); p.drawLine(QPointF(s * 0.50, s * 0.52), QPointF(s * 0.65, s * 0.59))
    elif kind == "settings":
        p.drawEllipse(QRectF(s * 0.35, s * 0.35, s * 0.30, s * 0.30))
        for angle in range(0, 360, 45):
            a = math.radians(angle)
            p.drawLine(QPointF(s * (0.5 + 0.25 * math.cos(a)), s * (0.5 + 0.25 * math.sin(a))), QPointF(s * (0.5 + 0.38 * math.cos(a)), s * (0.5 + 0.38 * math.sin(a))))
    elif kind in {"refresh", "recovery"}:
        p.drawArc(QRectF(s * 0.18, s * 0.18, s * 0.64, s * 0.64), 30 * 16, 285 * 16); p.drawLine(QPointF(s * 0.79, s * 0.22), QPointF(s * 0.79, s * 0.40)); p.drawLine(QPointF(s * 0.79, s * 0.22), QPointF(s * 0.61, s * 0.23))
    elif kind == "bolt":
        p.drawPolyline(QPolygonF([QPointF(s*.57,s*.08), QPointF(s*.30,s*.52), QPointF(s*.49,s*.52), QPointF(s*.41,s*.92), QPointF(s*.72,s*.42), QPointF(s*.52,s*.42)]))
    elif kind == "search":
        p.drawEllipse(QRectF(s * 0.19, s * 0.19, s * 0.48, s * 0.48)); p.drawLine(QPointF(s * 0.61, s * 0.61), QPointF(s * 0.84, s * 0.84))
    elif kind == "radar":
        p.drawEllipse(QRectF(s*.18,s*.18,s*.64,s*.64)); p.drawEllipse(QRectF(s*.33,s*.33,s*.34,s*.34)); p.drawLine(QPointF(s*.50,s*.50),QPointF(s*.74,s*.31))
    elif kind == "behavior":
        p.drawPolyline(QPolygonF([QPointF(s*.12,s*.58),QPointF(s*.28,s*.58),QPointF(s*.38,s*.32),QPointF(s*.50,s*.72),QPointF(s*.61,s*.45),QPointF(s*.88,s*.45)]))
    elif kind == "web":
        p.drawEllipse(QRectF(s*.16,s*.16,s*.68,s*.68)); p.drawArc(QRectF(s*.34,s*.16,s*.32,s*.68),90*16,180*16); p.drawArc(QRectF(s*.34,s*.16,s*.32,s*.68),270*16,180*16); p.drawLine(QPointF(s*.18,s*.50),QPointF(s*.82,s*.50))
    elif kind == "info":
        p.drawEllipse(QRectF(s*.16,s*.16,s*.68,s*.68)); p.drawLine(QPointF(s*.50,s*.43),QPointF(s*.50,s*.68)); p.drawPoint(QPointF(s*.50,s*.31))
    elif kind == "folder":
        p.drawRoundedRect(QRectF(s*.14,s*.28,s*.72,s*.52),2,2); p.drawLine(QPointF(s*.18,s*.28),QPointF(s*.39,s*.28)); p.drawLine(QPointF(s*.39,s*.28),QPointF(s*.47,s*.20)); p.drawLine(QPointF(s*.47,s*.20),QPointF(s*.67,s*.20))
    elif kind == "plus":
        p.drawLine(QPointF(s*.50,s*.20),QPointF(s*.50,s*.80)); p.drawLine(QPointF(s*.20,s*.50),QPointF(s*.80,s*.50))
    elif kind == "filter":
        p.drawLine(QPointF(s*.15,s*.28),QPointF(s*.85,s*.28)); p.drawLine(QPointF(s*.28,s*.50),QPointF(s*.72,s*.50)); p.drawLine(QPointF(s*.40,s*.72),QPointF(s*.60,s*.72))
    elif kind == "stop":
        p.drawEllipse(QRectF(s*.14,s*.14,s*.72,s*.72)); p.drawRect(QRectF(s*.36,s*.36,s*.28,s*.28))
    elif kind == "menu":
        for y in (0.28, 0.50, 0.72): p.drawLine(QPointF(s*.18,s*y),QPointF(s*.82,s*y))
    elif kind == "warning":
        poly = QPolygonF([QPointF(s*.5,s*.12),QPointF(s*.88,s*.82),QPointF(s*.12,s*.82),QPointF(s*.5,s*.12)]); p.drawPolyline(poly); p.drawLine(QPointF(s*.5,s*.35),QPointF(s*.5,s*.58)); p.drawPoint(QPointF(s*.5,s*.70))
    else:
        p.drawEllipse(QRectF(s*.36,s*.36,s*.28,s*.28))
    p.end()
    return QIcon(pix)


class SentinelLogo(QWidget):
    """Vector recreation of the nested emerald Sentinel shield/S mark from Stitch."""
    def __init__(self, size: int = 44, parent: QWidget | None = None) -> None:
        super().__init__(parent); self._size=int(size); self.setFixedSize(self._size,self._size); self.setAccessibleName("BC Sentinel"); self.setSizePolicy(QSizePolicy.Policy.Fixed,QSizePolicy.Policy.Fixed)
    def paintEvent(self, event) -> None:  # noqa: N802
        p=QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing); s=float(self._size); p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor("#18201c")); p.drawRoundedRect(QRectF(0,0,s,s),max(6.0,s*.17),max(6.0,s*.17))
        pen=QPen(QColor(COLORS["accent"]),max(2.2,s*.075)); pen.setCapStyle(Qt.PenCapStyle.RoundCap); pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin); p.setPen(pen); p.setBrush(Qt.BrushStyle.NoBrush)
        left=QPainterPath(); left.moveTo(s*.46,s*.16); left.lineTo(s*.29,s*.16); left.cubicTo(s*.20,s*.16,s*.15,s*.21,s*.15,s*.30); left.lineTo(s*.15,s*.58); left.cubicTo(s*.15,s*.72,s*.27,s*.81,s*.46,s*.91)
        right=QPainterPath(); right.moveTo(s*.54,s*.16); right.lineTo(s*.71,s*.16); right.cubicTo(s*.80,s*.16,s*.85,s*.21,s*.85,s*.30); right.lineTo(s*.85,s*.58); right.cubicTo(s*.85,s*.72,s*.73,s*.81,s*.54,s*.91); p.drawPath(left); p.drawPath(right)
        inner_l=QPainterPath(); inner_l.moveTo(s*.45,s*.30); inner_l.lineTo(s*.37,s*.30); inner_l.cubicTo(s*.29,s*.30,s*.26,s*.35,s*.26,s*.43); inner_l.lineTo(s*.26,s*.57); inner_l.cubicTo(s*.26,s*.69,s*.35,s*.77,s*.46,s*.82)
        inner_r=QPainterPath(); inner_r.moveTo(s*.55,s*.30); inner_r.lineTo(s*.63,s*.30); inner_r.cubicTo(s*.71,s*.30,s*.74,s*.35,s*.74,s*.43); inner_r.lineTo(s*.47,s*.43); inner_r.cubicTo(s*.39,s*.43,s*.36,s*.47,s*.36,s*.53); inner_r.cubicTo(s*.36,s*.58,s*.40,s*.61,s*.47,s*.61); inner_r.lineTo(s*.67,s*.61); inner_r.cubicTo(s*.66,s*.69,s*.61,s*.75,s*.54,s*.79); p.drawPath(inner_l); p.drawPath(inner_r)


class ReadOnlyToggle(QWidget):
    def __init__(self, on: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent); self.on=bool(on); self.setFixedSize(44,24); self.setAccessibleName("Stato protezione")
    def paintEvent(self, event) -> None:  # noqa: N802
        p=QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing); p.setPen(QPen(QColor("#2a8f69" if self.on else "#506158"),1)); p.setBrush(QColor(COLORS["accent"] if self.on else "#27342e")); p.drawRoundedRect(1,2,42,20,10,10); p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor("#eef5f0" if self.on else "#91a097")); p.drawEllipse(23 if self.on else 4,5,14,14)


def apply_icon(button_or_label, kind: str, color: str | None = None, size: int = 20) -> None:
    icon=make_icon(kind,color,size)
    if isinstance(button_or_label,QLabel): button_or_label.setPixmap(icon.pixmap(size,size))
    else: button_or_label.setIcon(icon); button_or_label.setIconSize(QSize(size,size))


def stylesheet() -> str:
    c=COLORS
    return f"""
    QWidget {{ font-family: 'Plus Jakarta Sans', 'Segoe UI Variable Text', 'Segoe UI'; }}
    QLabel {{ color: {c['text']}; background: transparent; }}
    QToolTip {{ background: {c['surface_high']}; color: {c['text']}; border: 1px solid {c['border']}; padding: 5px 7px; }}
    QScrollArea {{ border: none; background: transparent; }}
    QScrollBar:vertical {{ background: transparent; width: 8px; margin: 2px; }}
    QScrollBar::handle:vertical {{ background: #34443b; border-radius: 4px; min-height: 34px; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
    QScrollBar:horizontal {{ height: 0px; background: transparent; }}
    QPushButton:focus {{ outline: none; border: 1px solid {c['focus']}; }}
    """
