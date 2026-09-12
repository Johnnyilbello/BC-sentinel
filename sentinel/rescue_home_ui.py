from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Callable, Final

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from sentinel import rescue_home_ui_model as model

PROFILE: Final[str] = model.PROFILE
WINDOW_TITLE: Final[str] = "BC Sentinel - Home"


class TargetCardWidget(QFrame):
    def __init__(self, card: model.HomeTargetCard, on_select: Callable[[str], None], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.card = card
        self.setObjectName("TargetCard")
        self.setProperty("targetId", card.target_id)
        self.setProperty("targetStatus", card.status)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(10)

        top = QHBoxLayout()
        copy = QVBoxLayout()
        copy.setSpacing(4)
        title = QLabel(card.friendly_label)
        title.setObjectName("TargetTitle")
        title.setWordWrap(True)
        location = QLabel(card.location_label)
        location.setObjectName("TargetLocation")
        location.setWordWrap(True)
        copy.addWidget(title)
        copy.addWidget(location)
        top.addLayout(copy, 1)

        status = QLabel(card.status.replace("_", " ").title())
        status.setObjectName("TargetStatus")
        status.setProperty("status", card.status)
        status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status.setMinimumHeight(28)
        top.addWidget(status, 0, Qt.AlignmentFlag.AlignTop)
        outer.addLayout(top)

        explanation = QLabel(card.explanation)
        explanation.setObjectName("TargetExplanation")
        explanation.setWordWrap(True)
        outer.addWidget(explanation)

        actions = QHBoxLayout()
        self.details_button = QPushButton("Advanced details")
        self.details_button.setObjectName("DetailsButton")
        self.details_button.setCheckable(True)
        self.details_button.setAccessibleName(f"Advanced details for {card.friendly_label} {card.location_label}")
        actions.addWidget(self.details_button)
        actions.addStretch(1)

        self.select_button = QPushButton("Select")
        self.select_button.setObjectName("PrimaryButton" if card.selectable else "InactiveAction")
        self.select_button.setEnabled(card.selectable)
        self.select_button.setAccessibleName(f"Select {card.friendly_label} {card.location_label}")
        self.select_button.clicked.connect(lambda: on_select(card.target_id))
        actions.addWidget(self.select_button)
        outer.addLayout(actions)

        self.details_panel = QFrame()
        self.details_panel.setObjectName("AdvancedPanel")
        panel_layout = QVBoxLayout(self.details_panel)
        panel_layout.setContentsMargins(12, 12, 12, 12)
        panel_title = QLabel("Technical evidence")
        panel_title.setObjectName("AdvancedTitle")
        self.details_text = QPlainTextEdit()
        self.details_text.setObjectName("AdvancedText")
        self.details_text.setReadOnly(True)
        self.details_text.setPlainText(json.dumps(card.advanced_details, indent=2, sort_keys=True, default=str))
        self.details_text.setMinimumHeight(190)
        self.details_text.setAccessibleName(f"Technical evidence for {card.friendly_label} {card.location_label}")
        panel_layout.addWidget(panel_title)
        panel_layout.addWidget(self.details_text)
        self.details_panel.setVisible(False)
        self.details_button.toggled.connect(self.details_panel.setVisible)
        outer.addWidget(self.details_panel)

    def set_selected(self, selected: bool) -> None:
        self.setProperty("selected", selected)
        self.select_button.setText("Selected" if selected else "Select")
        self.select_button.setEnabled(self.card.selectable and not selected)
        self.style().unpolish(self)
        self.style().polish(self)


class HomeWindow(QMainWindow):
    def __init__(self, discovery_provider: Callable[[], dict] | None = None) -> None:
        super().__init__()
        contract = model.validate_engine_contract()
        if not contract["passed"]:
            raise RuntimeError("B6-1 parent safety contract refused: " + ";".join(contract["failures"]))

        self.discovery_provider = discovery_provider
        self.ui_state = model.initial_state()
        self.discovery_view: model.HomeDiscoveryView | None = None
        self.target_widgets: dict[str, TargetCardWidget] = {}

        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(920, 660)
        self.resize(1120, 780)
        self.setObjectName("HomeWindow")
        self._build_ui()
        self._apply_theme()

    def _build_ui(self) -> None:
        root = QWidget()
        outer = QVBoxLayout(root)
        outer.setContentsMargins(28, 24, 28, 24)
        outer.setSpacing(18)

        header = QVBoxLayout()
        eyebrow = QLabel("BC SENTINEL / HOME")
        eyebrow.setObjectName("Eyebrow")
        title = QLabel("Choose the Windows system to analyze")
        title.setObjectName("Title")
        subtitle = QLabel("BC Sentinel identifies supported Windows installations without changing them. Technical evidence is always available under Advanced details.")
        subtitle.setObjectName("Subtitle")
        subtitle.setWordWrap(True)
        header.addWidget(eyebrow)
        header.addWidget(title)
        header.addWidget(subtitle)
        outer.addLayout(header)

        safety = QFrame()
        safety.setObjectName("SafetyBanner")
        safety_layout = QHBoxLayout(safety)
        safety_layout.setContentsMargins(16, 12, 16, 12)
        safety_title = QLabel("Read-only step")
        safety_title.setObjectName("SafetyTitle")
        safety_text = QLabel("No repair, unlock, write mount, format or reimage action is available here.")
        safety_text.setObjectName("SafetyText")
        safety_text.setWordWrap(True)
        safety_layout.addWidget(safety_title)
        safety_layout.addWidget(safety_text, 1)
        outer.addWidget(safety)

        controls = QHBoxLayout()
        self.discovery_button = QPushButton("Find Windows installations")
        self.discovery_button.setObjectName("PrimaryButton")
        self.discovery_button.setAccessibleName("Find Windows installations")
        self.discovery_button.clicked.connect(self._run_discovery)
        controls.addWidget(self.discovery_button)
        controls.addStretch(1)
        self.state_label = QLabel("Ready to search")
        self.state_label.setObjectName("StateLabel")
        controls.addWidget(self.state_label)
        outer.addLayout(controls)

        self.summary_label = QLabel("BC Sentinel has not searched for offline Windows targets yet.")
        self.summary_label.setObjectName("SummaryLabel")
        self.summary_label.setWordWrap(True)
        outer.addWidget(self.summary_label)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setObjectName("TargetScroll")
        self.target_root = QWidget()
        self.target_layout = QVBoxLayout(self.target_root)
        self.target_layout.setContentsMargins(0, 0, 8, 0)
        self.target_layout.setSpacing(12)
        self.target_layout.addStretch(1)
        self.scroll.setWidget(self.target_root)
        outer.addWidget(self.scroll, 1)

        footer = QHBoxLayout()
        self.selection_label = QLabel("No Windows target selected.")
        self.selection_label.setObjectName("FooterText")
        self.selection_label.setWordWrap(True)
        footer.addWidget(self.selection_label, 1)
        self.next_button = QPushButton("Continue")
        self.next_button.setObjectName("InactiveAction")
        self.next_button.setEnabled(False)
        self.next_button.setAccessibleName("Continue with selected Windows target")
        footer.addWidget(self.next_button)
        outer.addLayout(footer)

        self.setCentralWidget(root)

    def _clear_targets(self) -> None:
        while self.target_layout.count() > 1:
            item = self.target_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self.target_widgets.clear()

    def _run_discovery(self) -> None:
        self.ui_state.state = "DISCOVERING"
        self.ui_state.last_reason = "explicit_user_discovery"
        self.state_label.setText("Searching…")
        self.discovery_button.setEnabled(False)
        self.summary_label.setText("Reading target metadata. BC Sentinel is not changing any target state.")
        self._clear_targets()
        QApplication.processEvents()

        try:
            self.discovery_view = model.run_operator_discovery(self.discovery_provider)
            self.ui_state.state = model.discovery_state_for(self.discovery_view)
            self._render_discovery_view(self.discovery_view)
        except Exception as exc:
            self.discovery_view = None
            self.ui_state.state = "DISCOVERY_ERROR"
            self.ui_state.last_reason = f"{type(exc).__name__}:{exc}"
            self.state_label.setText("Search failed")
            self.summary_label.setText("BC Sentinel could not safely complete target discovery. No target action was started.")
        finally:
            self.discovery_button.setEnabled(True)

    def _render_discovery_view(self, view: model.HomeDiscoveryView) -> None:
        self.state_label.setText(self.ui_state.state.replace("_", " ").title())
        if not view.targets:
            self.summary_label.setText("No supported Windows targets were found. You can search again after connecting the required disk or recovery media.")
            return

        selectable = sum(1 for target in view.targets if target.selectable)
        if view.recommended_target_id:
            self.summary_label.setText("BC Sentinel found one clearly validated Windows target and marked it as Recommended. Review it before selecting.")
        elif selectable > 1:
            self.summary_label.setText("BC Sentinel found more than one valid Windows installation. Choose the one you want to analyze; none was selected automatically.")
        elif any(target.status == model.STATUS_AMBIGUOUS for target in view.targets):
            self.summary_label.setText("BC Sentinel found ambiguous target evidence. Selection is blocked until the ambiguity is resolved.")
        elif selectable == 0:
            self.summary_label.setText("Windows-related targets were found, but none can be selected safely in their current state.")
        else:
            self.summary_label.setText("Review the available Windows target and select it when ready.")

        for target in view.targets:
            widget = TargetCardWidget(target, self._select_target)
            self.target_widgets[target.target_id] = widget
            self.target_layout.insertWidget(self.target_layout.count() - 1, widget)

    def _select_target(self, target_id: str) -> None:
        if self.discovery_view is None:
            return
        try:
            model.select_target(self.ui_state, self.discovery_view, target_id)
        except model.TargetSelectionError as exc:
            self.selection_label.setText(f"Selection refused: {exc}")
            return

        for card_id, widget in self.target_widgets.items():
            widget.set_selected(card_id == target_id)
        selected = next(target for target in self.discovery_view.targets if target.target_id == target_id)
        self.selection_label.setText(
            f"Selected: {selected.friendly_label} — {selected.location_label}. No analysis has started yet."
        )
        self.next_button.setEnabled(False)
        self.next_button.setText("Next step not enabled in B6-1")
        self.next_button.setObjectName("InactiveAction")
        self.statusBar().showMessage("Target selected. Rescue commands remain undispatched.", 6000)

    def _apply_theme(self) -> None:
        app = QApplication.instance()
        if app is not None:
            app.setFont(QFont("Segoe UI", 10))
        self.setStyleSheet(
            """
            #HomeWindow { background: #0b0e12; }
            QLabel { color: #e9edf2; }
            #Eyebrow { color: #7f8a98; font-size: 11px; font-weight: 700; letter-spacing: 1px; }
            #Title { color: #f7f9fb; font-size: 30px; font-weight: 650; }
            #Subtitle, #SafetyText, #TargetLocation, #TargetExplanation, #FooterText, #SummaryLabel { color: #99a4b2; font-size: 13px; }
            #SafetyBanner, #TargetCard, #AdvancedPanel { background: #10151b; border: 1px solid #24303a; border-radius: 12px; }
            #SafetyTitle, #TargetTitle, #AdvancedTitle { color: #eef3f6; font-weight: 700; }
            #TargetTitle { font-size: 16px; }
            #TargetStatus { background: #172029; color: #b5c8d5; border: 1px solid #2b3a46; border-radius: 14px; padding: 3px 10px; font-weight: 700; }
            #StateLabel { color: #b9c7d2; font-weight: 600; }
            #PrimaryButton { background: #dce8ef; color: #111820; border: none; border-radius: 9px; padding: 9px 14px; font-weight: 700; }
            #PrimaryButton:hover { background: #edf4f7; }
            #DetailsButton { background: transparent; color: #bac6cf; border: 1px solid #33404b; border-radius: 8px; padding: 8px 12px; }
            #DetailsButton:hover { background: #151c22; }
            #InactiveAction { background: #151b21; color: #65717d; border: 1px solid #232d36; border-radius: 8px; padding: 8px 12px; }
            #AdvancedText { background: #0c1116; color: #c9d3da; border: 1px solid #202b34; border-radius: 8px; font-family: Consolas, monospace; font-size: 11px; }
            QScrollArea { background: transparent; }
            QScrollBar:vertical { background: transparent; width: 8px; margin: 2px; }
            QScrollBar::handle:vertical { background: #29343e; border-radius: 4px; min-height: 30px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
            QStatusBar { color: #9eabb6; background: #0b0e12; }
            """
        )


def self_check() -> dict:
    contract = model.validate_engine_contract()
    state = model.initial_state().to_dict()
    return {
        "profile": PROFILE,
        "passed": bool(contract["passed"]),
        "contract": contract,
        "initial_state": state,
        "window_created": False,
        "startup_dispatch": False,
        "automatic_discovery": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta6 B6-1 unified Home target discovery UX")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--offscreen-smoke", action="store_true")
    args = parser.parse_args(argv)

    if args.self_check and not args.offscreen_smoke:
        payload = self_check()
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if payload["passed"] else 4

    if args.offscreen_smoke:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    app = QApplication.instance() or QApplication(sys.argv[:1])
    window = HomeWindow()
    if args.offscreen_smoke:
        payload = self_check()
        payload["window_created"] = True
        payload["window_title"] = window.windowTitle()
        payload["minimum_size"] = [window.minimumWidth(), window.minimumHeight()]
        print(json.dumps(payload, indent=2, sort_keys=True))
        window.close()
        return 0 if payload["passed"] else 4

    window.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
