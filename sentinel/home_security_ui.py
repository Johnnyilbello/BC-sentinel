from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Callable, Final, Mapping

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QTimer, Qt
from PySide6.QtGui import QFont
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
    "canvas": "#090d12",
    "surface_1": "#0f151c",
    "surface_2": "#121a22",
    "surface_3": "#17212b",
    "border": "#26333e",
    "border_soft": "#1c2730",
    "text_primary": "#f3f6f8",
    "text_secondary": "#b6c0c9",
    "text_muted": "#7f8d99",
    "accent": "#9dc8dc",
    "success": "#76b99a",
    "warning": "#d0ad6f",
    "critical": "#d78080",
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

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        header = QHBoxLayout()
        header.setSpacing(12)
        title_wrap = QVBoxLayout()
        title_wrap.setSpacing(4)
        title = QLabel(card.label)
        title.setObjectName("CardTitle")
        title.setWordWrap(True)
        description = QLabel(card.description)
        description.setObjectName("CardDescription")
        description.setWordWrap(True)
        title_wrap.addWidget(title)
        title_wrap.addWidget(description)
        header.addLayout(title_wrap, 1)

        status = QLabel(card.status_label)
        status.setObjectName("StatusPill")
        status.setProperty("statusRole", _status_role(card.status))
        status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status.setMinimumHeight(28)
        status.setAccessibleName(f"{card.label} status: {card.status_label}")
        header.addWidget(status, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)

        summary = QLabel(card.summary)
        summary.setObjectName("CardSummary")
        summary.setWordWrap(True)
        summary.setMinimumHeight(42)
        layout.addWidget(summary)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.details_button = QPushButton("Advanced details")
        self.details_button.setObjectName("GhostButton")
        self.details_button.setCheckable(True)
        self.details_button.setAccessibleName(f"Advanced details for {card.label}")
        self.details_button.toggled.connect(self._toggle_details)
        actions.addWidget(self.details_button)
        actions.addStretch(1)

        self.action_button = QPushButton(card.action_label)
        self.action_button.setObjectName("CardAction" if card.action_enabled else "DisabledAction")
        self.action_button.setEnabled(card.action_enabled)
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
        self.details_text.setMinimumHeight(175)
        self.details_text.setPlainText(json.dumps(card.advanced_details, indent=2, sort_keys=True, default=str))
        self.details_text.setAccessibleName(f"Technical evidence for {card.label}")
        details_layout.addWidget(details_title)
        details_layout.addWidget(self.details_text)
        layout.addWidget(self.details_panel)

    def _toggle_details(self, expanded: bool) -> None:
        target = 235 if expanded else 0
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


class SecurityOverviewWindow(QMainWindow):
    def __init__(
        self,
        status_provider: Callable[[], Mapping] | None = None,
    ) -> None:
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
        self.resize(1220, 840)
        self._build_ui()
        self._apply_theme()
        QTimer.singleShot(0, self._start_entrance_motion)

    def _build_ui(self) -> None:
        page_scroll = QScrollArea()
        page_scroll.setObjectName("PageScroll")
        page_scroll.setWidgetResizable(True)
        page_scroll.setFrameShape(QFrame.Shape.NoFrame)
        page_scroll.viewport().setObjectName("PageViewport")
        page_scroll.viewport().setAutoFillBackground(False)

        root = QWidget()
        root.setObjectName("SecurityRoot")
        root.setAutoFillBackground(False)
        page = QVBoxLayout(root)
        page.setContentsMargins(32, 28, 32, 32)
        page.setSpacing(24)

        top = QHBoxLayout()
        top.setSpacing(16)
        brand = QVBoxLayout()
        brand.setSpacing(5)
        eyebrow = QLabel("BC SENTINEL / HOME")
        eyebrow.setObjectName("Eyebrow")
        title = QLabel("Security overview")
        title.setObjectName("PageTitle")
        subtitle = QLabel("A clear view of what BC Sentinel can verify right now. Technical evidence is always available when you need it.")
        subtitle.setObjectName("PageSubtitle")
        subtitle.setWordWrap(True)
        brand.addWidget(eyebrow)
        brand.addWidget(title)
        brand.addWidget(subtitle)
        top.addLayout(brand, 1)

        self.refresh_button = QPushButton("Refresh status")
        self.refresh_button.setObjectName("GhostButton")
        self.refresh_button.setAccessibleName("Refresh passive protection status")
        self.refresh_button.clicked.connect(self._refresh_snapshot)
        top.addWidget(self.refresh_button, 0, Qt.AlignmentFlag.AlignTop)
        page.addLayout(top)

        self.hero = QFrame()
        self.hero.setObjectName("PostureHero")
        self.hero.setProperty("posture", self.snapshot.posture)
        hero_layout = QHBoxLayout(self.hero)
        hero_layout.setContentsMargins(24, 22, 24, 22)
        hero_layout.setSpacing(24)

        hero_copy = QVBoxLayout()
        hero_copy.setSpacing(8)
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
        hero_copy.addWidget(self.posture_label, 0, Qt.AlignmentFlag.AlignLeft)
        hero_copy.addWidget(self.headline_label)
        hero_copy.addWidget(self.hero_summary)
        hero_layout.addLayout(hero_copy, 1)

        action_wrap = QVBoxLayout()
        action_wrap.setSpacing(8)
        action_wrap.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        self.smart_scan_button = QPushButton("Smart Scan")
        self.smart_scan_button.setObjectName("PrimaryDisabled")
        self.smart_scan_button.setEnabled(False)
        self.smart_scan_button.setMinimumWidth(168)
        self.smart_scan_button.setAccessibleName("Smart Scan unavailable until B6-3")
        scan_note = QLabel("Available in the next milestone")
        scan_note.setObjectName("Microcopy")
        scan_note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        action_wrap.addWidget(self.smart_scan_button)
        action_wrap.addWidget(scan_note)
        hero_layout.addLayout(action_wrap)
        page.addWidget(self.hero)

        section_row = QHBoxLayout()
        section_title = QLabel("Protection layers")
        section_title.setObjectName("SectionTitle")
        section_row.addWidget(section_title)
        section_row.addStretch(1)
        section_hint = QLabel("Engine availability and live status are shown separately")
        section_hint.setObjectName("SectionHint")
        section_row.addWidget(section_hint)
        page.addLayout(section_row)

        self.cards_grid = QGridLayout()
        self.cards_grid.setHorizontalSpacing(16)
        self.cards_grid.setVerticalSpacing(16)
        self._render_cards()
        page.addLayout(self.cards_grid)

        activity = QFrame()
        activity.setObjectName("ActivityCard")
        activity_layout = QHBoxLayout(activity)
        activity_layout.setContentsMargins(20, 18, 20, 18)
        activity_layout.setSpacing(16)
        activity_copy = QVBoxLayout()
        activity_copy.setSpacing(5)
        activity_title = QLabel("Recent activity")
        activity_title.setObjectName("CardTitle")
        self.activity_summary = QLabel(self.snapshot.recent_activity_summary)
        self.activity_summary.setObjectName("CardSummary")
        self.activity_summary.setWordWrap(True)
        activity_copy.addWidget(activity_title)
        activity_copy.addWidget(self.activity_summary)
        activity_layout.addLayout(activity_copy, 1)
        activity_state = QLabel("Not connected yet")
        activity_state.setObjectName("NeutralPill")
        activity_layout.addWidget(activity_state, 0, Qt.AlignmentFlag.AlignTop)
        page.addWidget(activity)

        footer = QHBoxLayout()
        footer_note = QLabel("BC Sentinel Home · B6-2 overview foundation")
        footer_note.setObjectName("FooterText")
        footer.addWidget(footer_note)
        footer.addStretch(1)
        truth_note = QLabel("No hidden scan or remediation is started from this screen")
        truth_note.setObjectName("FooterText")
        footer.addWidget(truth_note)
        page.addLayout(footer)

        page_scroll.setWidget(root)
        self.setCentralWidget(page_scroll)
        self._animated_widgets = [self.hero, *self.card_widgets.values(), activity]

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
            font.setFamilies(["Segoe UI Variable", "Segoe UI", "Arial"])
            font.setPointSize(10)
            app.setFont(font)

        c = COLOR_TOKENS
        self.setStyleSheet(
            f"""
            #SecurityOverviewWindow, #PageScroll, #PageViewport, #SecurityRoot {{
                background: {c['canvas']};
                border: none;
            }}
            QLabel {{ color: {c['text_primary']}; background: transparent; }}
            #Eyebrow {{ color: {c['accent']}; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
            #PageTitle {{ color: {c['text_primary']}; font-size: 31px; font-weight: 650; }}
            #PageSubtitle {{ color: {c['text_secondary']}; font-size: 13px; }}
            #PostureHero {{
                background: {c['surface_1']};
                border: 1px solid {c['border']};
                border-radius: 16px;
            }}
            #HeroTitle {{ color: {c['text_primary']}; font-size: 22px; font-weight: 650; }}
            #HeroSummary {{ color: {c['text_secondary']}; font-size: 13px; }}
            #PosturePill, #StatusPill, #NeutralPill {{
                border-radius: 14px;
                padding: 4px 10px;
                font-size: 11px;
                font-weight: 700;
            }}
            #PosturePill[posture="{model.POSTURE_PROTECTED}"], #StatusPill[statusRole="positive"] {{
                color: {c['success']}; background: #10221b; border: 1px solid #244737;
            }}
            #PosturePill[posture="{model.POSTURE_ATTENTION}"], #StatusPill[statusRole="attention"] {{
                color: {c['warning']}; background: #241d12; border: 1px solid #4b3b20;
            }}
            #PosturePill[posture="{model.POSTURE_UNVERIFIED}"], #StatusPill[statusRole="neutral"], #NeutralPill {{
                color: {c['text_secondary']}; background: {c['surface_3']}; border: 1px solid {c['border']};
            }}
            #SectionTitle {{ color: {c['text_primary']}; font-size: 16px; font-weight: 650; }}
            #SectionHint {{ color: {c['text_muted']}; font-size: 11px; }}
            #ProtectionCard, #ActivityCard {{
                background: {c['surface_1']};
                border: 1px solid {c['border_soft']};
                border-radius: 14px;
            }}
            #ProtectionCard:hover {{ border: 1px solid {c['border']}; background: {c['surface_2']}; }}
            #CardTitle {{ color: {c['text_primary']}; font-size: 15px; font-weight: 650; }}
            #CardDescription, #CardSummary {{ color: {c['text_secondary']}; font-size: 12px; }}
            #CardSummary {{ color: {c['text_muted']}; }}
            #GhostButton {{
                background: transparent;
                color: {c['text_secondary']};
                border: 1px solid {c['border']};
                border-radius: 9px;
                padding: 8px 12px;
                font-weight: 600;
            }}
            #GhostButton:hover {{ background: {c['surface_3']}; color: {c['text_primary']}; }}
            #GhostButton:focus {{ border: 1px solid {c['accent']}; }}
            #CardAction {{
                background: #dbe9ef;
                color: #101820;
                border: none;
                border-radius: 9px;
                padding: 8px 12px;
                font-weight: 700;
            }}
            #CardAction:hover {{ background: #edf5f8; }}
            #DisabledAction, #PrimaryDisabled {{
                background: #121922;
                color: #657481;
                border: 1px solid #202c36;
                border-radius: 9px;
                padding: 8px 12px;
                font-weight: 650;
            }}
            #PrimaryDisabled {{ padding: 10px 18px; }}
            #Microcopy, #FooterText {{ color: {c['text_muted']}; font-size: 11px; }}
            #AdvancedPanel {{
                background: #0b1117;
                border: 1px solid {c['border_soft']};
                border-radius: 10px;
            }}
            #AdvancedTitle {{ color: {c['text_secondary']}; font-size: 11px; font-weight: 700; }}
            #AdvancedText {{
                background: #080d12;
                color: #bec9d1;
                border: 1px solid #1c2831;
                border-radius: 8px;
                font-family: Consolas, "Cascadia Mono", monospace;
                font-size: 10px;
                selection-background-color: #274253;
            }}
            QScrollBar:vertical {{ background: transparent; width: 8px; margin: 2px; }}
            QScrollBar::handle:vertical {{ background: #26333e; border-radius: 4px; min-height: 34px; }}
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
