from __future__ import annotations

"""Small presentation-only motion primitives for BC Sentinel.

The components in this module translate selected interaction ideas from web UI
references into native PySide6 without adding web/runtime dependencies. They do
not start scans, change security state, mutate findings, or expose remediation
authority.
"""

import math
import os

from PySide6.QtCore import Property, QEasingCurve, QPointF, QPropertyAnimation, QRectF, QTimer, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QLabel, QSizePolicy, QWidget

from sentinel.ui_design_system import COLORS, MOTION


REDUCED_MOTION_ENV = "BC_SENTINEL_REDUCED_MOTION"


def reduced_motion_enabled() -> bool:
    value = str(os.environ.get(REDUCED_MOTION_ENV, "")).strip().casefold()
    return value in {"1", "true", "yes", "on"}


class AnimatedNumberLabel(QLabel):
    """Number-flow inspired native label with a short, optional value tween."""

    def __init__(
        self,
        value: float = 0,
        *,
        suffix: str = "%",
        duration_ms: int | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._display_value = float(value)
        self._suffix = str(suffix)
        self._duration_ms = int(duration_ms or MOTION["state"])
        self._animation = QPropertyAnimation(self, b"displayValue", self)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        self._render_value()

    def _get_display_value(self) -> float:
        return float(self._display_value)

    def _set_display_value(self, value: float) -> None:
        self._display_value = float(value)
        self._render_value()

    displayValue = Property(float, _get_display_value, _set_display_value)

    def _render_value(self) -> None:
        self.setText(f"{int(round(self._display_value))}{self._suffix}")

    def set_target(self, value: float, *, immediate: bool = False) -> None:
        target = float(value)
        if reduced_motion_enabled() or immediate:
            self._animation.stop()
            self._set_display_value(target)
            return
        self._animation.stop()
        self._animation.setDuration(max(80, self._duration_ms))
        self._animation.setStartValue(float(self._display_value))
        self._animation.setEndValue(target)
        self._animation.start()


class StatusOrb(QWidget):
    """Subtle native status orb for scan activity and terminal scan states."""

    STATES = {
        "idle",
        "working",
        "clean",
        "findings",
        "attention",
        "cancelled",
        "unavailable",
    }

    def __init__(self, size: int = 58, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._size = max(32, int(size))
        self._state = "idle"
        self._phase = 0.0
        self.setFixedSize(self._size, self._size)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setObjectName("ScanStatusOrb")
        self.setAccessibleName("Stato Smart Scan: pronto")

        self._timer = QTimer(self)
        self._timer.setInterval(48)
        self._timer.timeout.connect(self._tick)
        self._sync_timer()

    @property
    def state(self) -> str:
        return self._state

    def set_state(self, state: str) -> None:
        normalized = str(state or "idle").strip().casefold()
        if normalized not in self.STATES:
            normalized = "attention"
        self._state = normalized
        self.setAccessibleName(f"Stato Smart Scan: {self._accessible_state(normalized)}")
        self._sync_timer()
        self.update()

    def _sync_timer(self) -> None:
        should_animate = self._state == "working" and not reduced_motion_enabled()
        if should_animate and not self._timer.isActive():
            self._timer.start()
        elif not should_animate and self._timer.isActive():
            self._timer.stop()

    def _tick(self) -> None:
        self._phase = (self._phase + 0.055) % 1.0
        self.update()

    @staticmethod
    def _accessible_state(state: str) -> str:
        return {
            "idle": "pronto",
            "working": "scansione in corso",
            "clean": "completata senza rilevamenti",
            "findings": "rilevamenti da verificare",
            "attention": "attenzione richiesta",
            "cancelled": "annullata",
            "unavailable": "non disponibile",
        }.get(state, "attenzione richiesta")

    def _state_color(self) -> QColor:
        return QColor(
            {
                "idle": COLORS["info"],
                "working": COLORS["accent_bright"],
                "clean": COLORS["success"],
                "findings": COLORS["warning"],
                "attention": COLORS["danger"],
                "cancelled": COLORS["text_muted"],
                "unavailable": COLORS["disabled_text"],
            }.get(self._state, COLORS["warning"])
        )

    def paintEvent(self, event) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = float(self._size)
        center = QPointF(s / 2.0, s / 2.0)
        color = self._state_color()

        painter.setPen(Qt.PenStyle.NoPen)
        base = QColor(COLORS["surface_nested"])
        painter.setBrush(base)
        painter.drawEllipse(QRectF(s * 0.08, s * 0.08, s * 0.84, s * 0.84))

        pulse = 0.0
        if self._state == "working" and not reduced_motion_enabled():
            pulse = 0.5 + 0.5 * math.sin(self._phase * math.tau)

        outer = QColor(color)
        outer.setAlphaF(0.20 + pulse * 0.16)
        pen = QPen(outer, 2.0 + pulse * 0.8)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        inset = s * (0.14 - pulse * 0.015)
        painter.drawEllipse(QRectF(inset, inset, s - 2 * inset, s - 2 * inset))

        ring = QColor(color)
        ring.setAlphaF(0.72)
        painter.setPen(QPen(ring, 2.2))
        painter.drawArc(QRectF(s * 0.23, s * 0.23, s * 0.54, s * 0.54), 35 * 16, 250 * 16)

        painter.setPen(Qt.PenStyle.NoPen)
        dot = QColor(color)
        dot.setAlphaF(0.95)
        painter.setBrush(dot)
        radius = s * (0.105 + pulse * 0.012)
        painter.drawEllipse(center, radius, radius)
        painter.end()
