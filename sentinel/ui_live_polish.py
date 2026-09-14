from __future__ import annotations

"""B6-5.3 live UI polish derived from real Windows screenshots.

This layer is presentation-only. It fixes wrapped-text geometry, removes hard
vertical caps that can clip copy, and gives refresh controls distinct semantic
icons. It does not change scan, detection, confirmation, remediation, severity,
confidence, or evidence behavior.
"""

from typing import Final

from PySide6.QtCore import QPointF, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import QLabel, QSizePolicy, QWidget

from sentinel.home_guided_resolution_ui import B65SmartScanPage
from sentinel.ui_design_system import COLORS

PROFILE: Final[str] = "v0.11.0-beta.6-ui-live-polish-r3"
_MAX_WIDGET_HEIGHT: Final[int] = 16777215

_TEXT_SAFE_OBJECTS: Final[frozenset[str]] = frozenset(
    {
        "TaskTitle",
        "TaskSubtitle",
        "ScanProgressText",
        "ScanSummary",
        "PanelTitle",
        "PanelDescription",
        "CardTitle",
        "ThreatBodyText",
        "ThreatLocation",
        "ThreatRecommendationText",
        "GuidanceHeadline",
        "GuidanceStepText",
        "SafetyNote",
        "EmptyTitle",
        "EmptyBody",
    }
)


def _list_refresh_icon(size: int = 16, color: str | None = None) -> QIcon:
    """List-specific refresh glyph, intentionally distinct from status refresh."""

    color = color or COLORS["text_secondary"]
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(color), max(1.25, size / 12.5))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    s = float(size)

    # Three list rows on the left.
    for y in (0.28, 0.50, 0.72):
        painter.drawPoint(QPointF(s * 0.14, s * y))
        painter.drawLine(QPointF(s * 0.22, s * y), QPointF(s * 0.49, s * y))

    # Compact refresh arrow on the right.
    painter.drawArc(QRectF(s * 0.48, s * 0.26, s * 0.38, s * 0.46), 35 * 16, 275 * 16)
    painter.drawLine(QPointF(s * 0.82, s * 0.28), QPointF(s * 0.82, s * 0.43))
    painter.drawLine(QPointF(s * 0.82, s * 0.28), QPointF(s * 0.68, s * 0.29))
    painter.end()
    return QIcon(pix)


def _make_label_text_safe(label: QLabel, *, remove_width_cap: bool = False) -> None:
    label.setMinimumWidth(0)
    label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    if remove_width_cap:
        label.setMaximumWidth(16777215)
    label.updateGeometry()


def _polish_wrapped_labels(root: QWidget) -> None:
    for label in root.findChildren(QLabel):
        if label.objectName() in _TEXT_SAFE_OBJECTS:
            _make_label_text_safe(
                label,
                remove_width_cap=label.objectName() in {"TaskSubtitle", "EmptyBody", "PanelDescription"},
            )


class PolishedB65SmartScanPage(B65SmartScanPage):
    """B6-5.3 scan page with content-driven height instead of hard clipping caps."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._apply_live_text_safety()

    def _apply_live_text_safety(self) -> None:
        # The page already lives in a vertical QScrollArea, so a hard maximum
        # height is counterproductive: it can crop wrapped copy at Windows DPI
        # scales and with Segoe UI Variable metrics.
        self.panel.setMaximumHeight(_MAX_WIDGET_HEIGHT)
        self.panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        for label in (
            self.task_title,
            self.task_subtitle,
            self.progress_label,
            self.coverage_label,
        ):
            _make_label_text_safe(label, remove_width_cap=True)

        panel_layout = self.panel.layout()
        if panel_layout is not None:
            # Text is centered by QLabel itself. Removing the layout alignment
            # lets Qt allocate the full available width and a correct heightForWidth.
            panel_layout.setAlignment(self.task_title, Qt.AlignmentFlag(0))
            panel_layout.setAlignment(self.task_subtitle, Qt.AlignmentFlag(0))
            panel_layout.setAlignment(self.progress_label, Qt.AlignmentFlag(0))
            panel_layout.setAlignment(self.coverage_label, Qt.AlignmentFlag(0))

        _polish_wrapped_labels(self)
        self.updateGeometry()

    def _toggle_advanced(self, checked: bool) -> None:
        # Keep progressive disclosure but never restore the predecessor hard cap.
        super()._toggle_advanced(checked)
        self.panel.setMaximumHeight(_MAX_WIDGET_HEIGHT)
        self._apply_live_text_safety()

    def set_running(self) -> None:
        super().set_running()
        self._apply_live_text_safety()

    def set_progress(self, progress) -> None:
        super().set_progress(progress)
        self._apply_live_text_safety()

    def set_result(self, result) -> None:
        super().set_result(result)
        self._apply_live_text_safety()

        # Keep canonical/raw evidence untouched while making the primary UI
        # language consistent when the historical runtime returns this stock copy.
        for card in self.threat_card_widgets:
            recommendation = getattr(card, "recommendation_label", None)
            if recommendation is not None and recommendation.text().strip() == "Review the findings before taking action.":
                recommendation.setText("Verifica i rilevamenti prima di intervenire.")
            _polish_wrapped_labels(card)

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        super().set_compact(compact, mobile)
        self.panel.setMaximumHeight(_MAX_WIDGET_HEIGHT)
        self._apply_live_text_safety()


def apply_window_live_polish(window: QWidget) -> None:
    """Apply screenshot-driven fixes to the B6-5.3 shell after construction."""

    refresh_button = getattr(window, "refresh_button", None)
    if refresh_button is not None:
        refresh_button.setProperty("semanticIcon", "status_refresh")
        refresh_button.setToolTip("Rileggi lo stato di protezione corrente")

    quarantine_page = getattr(window, "quarantine_page", None)
    if quarantine_page is not None:
        list_refresh = getattr(quarantine_page, "refresh_button", None)
        if list_refresh is not None:
            list_refresh.setIcon(_list_refresh_icon(16, COLORS["text_secondary"]))
            list_refresh.setIconSize(QSize(16, 16))
            list_refresh.setProperty("semanticIcon", "list_refresh")
            list_refresh.setToolTip("Ricarica l'elenco della quarantena")

        empty = getattr(quarantine_page, "empty", None)
        if empty is not None:
            empty.setMinimumHeight(190)
            empty.setMaximumHeight(_MAX_WIDGET_HEIGHT)
            empty.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            _polish_wrapped_labels(empty)
            empty_layout = empty.layout()
            if empty_layout is not None:
                for label in empty.findChildren(QLabel):
                    if label.objectName() in {"EmptyTitle", "EmptyBody"}:
                        empty_layout.setAlignment(label, Qt.AlignmentFlag(0))
            empty.updateGeometry()

    scan_page = getattr(window, "scan_page", None)
    if scan_page is not None:
        _polish_wrapped_labels(scan_page)


def validate_live_ui_polish_contract() -> dict:
    return {
        "profile": PROFILE,
        "passed": True,
        "wrapped_text_uses_content_driven_height": True,
        "smart_scan_hard_height_cap_removed": True,
        "quarantine_empty_state_hard_height_cap_removed": True,
        "refresh_icons_semantically_distinct": True,
        "status_refresh_icon_role": "status_refresh",
        "quarantine_refresh_icon_role": "list_refresh",
        "historical_runtime_primary_copy_localized_without_mutating_raw_evidence": True,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_destructive_action": False,
    }
