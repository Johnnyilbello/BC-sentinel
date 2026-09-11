from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Final

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from sentinel import rescue_technician_ui_model as model

PROFILE: Final[str] = model.PROFILE


class StatusPill(QLabel):
    def __init__(self, text: str, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("StatusPill")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumHeight(28)


class InfoCard(QFrame):
    def __init__(self, title: str, value: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("InfoCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(6)
        title_label = QLabel(title)
        title_label.setObjectName("CardEyebrow")
        value_label = QLabel(value)
        value_label.setObjectName("CardValue")
        value_label.setWordWrap(True)
        layout.addWidget(title_label)
        layout.addWidget(value_label)


class TechnicianWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        contract = model.validate_engine_contract()
        if not contract["passed"]:
            raise RuntimeError("B6-0 engine contract refused: " + ";".join(contract["failures"]))

        self.ui_state = model.initial_state()
        self.setWindowTitle("BC Sentinel — Rescue Technician")
        self.setMinimumSize(980, 680)
        self.resize(1180, 780)
        self.setObjectName("TechnicianWindow")
        self._build_ui(contract)
        self._apply_theme()

    def _build_ui(self, contract: dict) -> None:
        root = QWidget()
        outer = QVBoxLayout(root)
        outer.setContentsMargins(28, 24, 28, 24)
        outer.setSpacing(22)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        eyebrow = QLabel("BC SENTINEL / RESCUE TECHNICIAN")
        eyebrow.setObjectName("Eyebrow")
        title = QLabel("Field recovery console")
        title.setObjectName("Title")
        subtitle = QLabel("Safe technician workflow over the frozen Beta5 rescue engine.")
        subtitle.setObjectName("Subtitle")
        title_box.addWidget(eyebrow)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box, 1)
        self.status_pill = StatusPill(self.ui_state.state)
        header.addWidget(self.status_pill, 0, Qt.AlignmentFlag.AlignTop)
        outer.addLayout(header)

        safety = QFrame()
        safety.setObjectName("SafetyBanner")
        safety_layout = QHBoxLayout(safety)
        safety_layout.setContentsMargins(18, 14, 18, 14)
        safety_title = QLabel("Safety boundary active")
        safety_title.setObjectName("SafetyTitle")
        safety_text = QLabel("No repair-execute, unlock, format or reimage authority is exposed by this UI.")
        safety_text.setObjectName("SafetyText")
        safety_text.setWordWrap(True)
        safety_layout.addWidget(safety_title)
        safety_layout.addWidget(safety_text, 1)
        outer.addWidget(safety)

        cards = QHBoxLayout()
        cards.setSpacing(14)
        cards.addWidget(InfoCard("TARGET", "No offline target selected"), 1)
        cards.addWidget(InfoCard("SESSION", "No active session"), 1)
        cards.addWidget(InfoCard("ENGINE", str(contract["engine_profile"])), 1)
        outer.addLayout(cards)

        section_title = QLabel("Technician workflow")
        section_title.setObjectName("SectionTitle")
        outer.addWidget(section_title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setObjectName("WorkflowScroll")
        workflow_root = QWidget()
        workflow = QVBoxLayout(workflow_root)
        workflow.setContentsMargins(0, 0, 8, 0)
        workflow.setSpacing(10)

        rows = (
            ("1", "Discover target", "Find offline Windows candidates without unlocking or mounting them for write.", "discover"),
            ("2", "Inspect health", "Assess damaged, restricted or degraded state before considering any next action.", "assess"),
            ("3", "Collect evidence", "Run the accepted scan and bounded stress checks with evidence stored outside the target.", "scan"),
            ("4", "Review decision", "Read RR-6 certification and advisory decision without overriding refusal semantics.", "decide"),
            ("5", "Technician report", "Build and independently verify the evidence package for handoff or archival.", "report"),
        )
        for number, title, description, command in rows:
            card = QFrame()
            card.setObjectName("WorkflowCard")
            row = QHBoxLayout(card)
            row.setContentsMargins(18, 16, 18, 16)
            row.setSpacing(16)
            index = QLabel(number)
            index.setObjectName("StepIndex")
            index.setAlignment(Qt.AlignmentFlag.AlignCenter)
            index.setFixedSize(34, 34)
            copy = QVBoxLayout()
            copy.setSpacing(4)
            heading = QLabel(title)
            heading.setObjectName("WorkflowTitle")
            body = QLabel(description)
            body.setObjectName("WorkflowBody")
            body.setWordWrap(True)
            copy.addWidget(heading)
            copy.addWidget(body)
            row.addWidget(index)
            row.addLayout(copy, 1)
            button = QPushButton("Not started")
            button.setObjectName("InactiveAction")
            button.setEnabled(False)
            button.setProperty("engineCommand", command)
            button.setMinimumWidth(112)
            row.addWidget(button)
            workflow.addWidget(card)

        workflow.addStretch(1)
        scroll.setWidget(workflow_root)
        outer.addWidget(scroll, 1)

        footer = QHBoxLayout()
        footer_text = QLabel("B6-0 foundation: startup performs no rescue command and changes no target state.")
        footer_text.setObjectName("FooterText")
        footer.addWidget(footer_text, 1)
        contract_button = QPushButton("Safety contract")
        contract_button.setObjectName("SecondaryButton")
        contract_button.clicked.connect(lambda: self._show_contract(contract))
        footer.addWidget(contract_button)
        outer.addLayout(footer)

        self.setCentralWidget(root)

    def _show_contract(self, contract: dict) -> None:
        self.statusBar().showMessage(
            "Contract PASS — engine commands locked to Beta5; forbidden destructive commands absent.",
            8000,
        )

    def _apply_theme(self) -> None:
        app = QApplication.instance()
        if app is not None:
            app.setFont(QFont("Segoe UI", 10))
        self.setStyleSheet(
            """
            #TechnicianWindow { background: #0b0e12; }
            QLabel { color: #e9edf2; }
            #Eyebrow, #CardEyebrow { color: #7f8a98; font-size: 11px; font-weight: 700; letter-spacing: 1px; }
            #Title { color: #f7f9fb; font-size: 32px; font-weight: 650; }
            #Subtitle, #WorkflowBody, #FooterText, #SafetyText { color: #99a4b2; font-size: 13px; }
            #StatusPill { background: #172029; color: #a8c5d7; border: 1px solid #2b3a46; border-radius: 14px; padding: 3px 12px; font-weight: 700; }
            #SafetyBanner { background: #11171d; border: 1px solid #27323c; border-radius: 12px; }
            #SafetyTitle { color: #d6e3ea; font-weight: 700; }
            #InfoCard, #WorkflowCard { background: #10151b; border: 1px solid #1f2933; border-radius: 14px; }
            #CardValue { color: #e6ebf0; font-size: 14px; font-weight: 600; }
            #SectionTitle { color: #f0f3f6; font-size: 18px; font-weight: 650; }
            #StepIndex { background: #18212a; color: #b9cad6; border: 1px solid #2a3844; border-radius: 17px; font-weight: 700; }
            #WorkflowTitle { color: #eef2f5; font-size: 14px; font-weight: 650; }
            #InactiveAction { background: #151b21; color: #65717d; border: 1px solid #232d36; border-radius: 8px; padding: 8px 12px; }
            #SecondaryButton { background: transparent; color: #bac6cf; border: 1px solid #33404b; border-radius: 8px; padding: 8px 12px; }
            #SecondaryButton:hover { background: #151c22; }
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
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta6 technician UX foundation")
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
    window = TechnicianWindow()
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
