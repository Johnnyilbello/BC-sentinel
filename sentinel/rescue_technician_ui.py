from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from typing import Final

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QFont, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QBoxLayout,
    QFrame,
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

from sentinel import rescue_technician_ui_model as model

PROFILE: Final[str] = model.PROFILE
WINDOW_TITLE: Final[str] = "BC Sentinel - Rescue Technician"


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
        self.value_label = QLabel(value)
        self.value_label.setObjectName("CardValue")
        self.value_label.setWordWrap(True)
        self.value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.setMinimumWidth(0)
        layout.addWidget(title_label)
        layout.addWidget(self.value_label)


class ReadOnlyFixtureWorker(QThread):
    """Runs only an injected diagnostic fixture off the Qt event loop.

    It never resolves or invokes a rescue engine command. Production controls do
    not create this worker; it gives the UI a safe, testable worker boundary for
    future read-only progress sources.
    """

    completed = Signal(str)
    failed = Signal(str)

    def __init__(self, work: Callable[[], str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._work = work

    def run(self) -> None:
        try:
            self.completed.emit(str(self._work()))
        except Exception as exc:  # UI diagnostic boundary
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class TechnicianWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        contract = model.validate_engine_contract()
        if not contract["passed"]:
            raise RuntimeError("B6-0 engine contract refused: " + ";".join(contract["failures"]))

        self.ui_state = model.initial_state()
        self.activity_log = model.BoundedActivityLog()
        self.fixture_worker: ReadOnlyFixtureWorker | None = None
        self._layout_mode = "wide"
        self.setWindowTitle(WINDOW_TITLE)
        # Preserve the accepted B6-0 minimum while adapting within this range
        # for 125%/150% text scaling and narrow field displays.
        self.setMinimumSize(900, 640)
        self.resize(1180, 780)
        self.setObjectName("TechnicianWindow")
        self._build_ui(contract)
        self._apply_theme()

    def _build_ui(self, contract: dict) -> None:
        root = QWidget()
        outer = QVBoxLayout(root)
        outer.setContentsMargins(28, 24, 28, 24)
        outer.setSpacing(22)

        self.header = QBoxLayout(QBoxLayout.Direction.LeftToRight)
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
        self.header.addLayout(title_box, 1)
        self.status_pill = StatusPill(self.ui_state.state)
        self.status_pill.setAccessibleName("Stato del flusso tecnico")
        self.status_pill.setToolTip("Stato corrente del flusso tecnico")
        self.header.addWidget(self.status_pill, 0, Qt.AlignmentFlag.AlignTop)
        outer.addLayout(self.header)

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

        self.cards = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.cards.setSpacing(14)
        self.info_cards = [
            InfoCard("TARGET", "No offline target selected"),
            InfoCard("SESSION", "No active session"),
            InfoCard("ENGINE", str(contract["engine_profile"])),
        ]
        for card in self.info_cards:
            self.cards.addWidget(card, 1)
        outer.addLayout(self.cards)

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
        self.workflow_buttons: list[QPushButton] = []
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
            button.setAccessibleName(f"{title}: not available")
            button.setToolTip("This command remains unavailable until its safety milestone is accepted.")
            button.setMinimumWidth(112)
            row.addWidget(button)
            self.workflow_buttons.append(button)
            workflow.addWidget(card)

        workflow.addStretch(1)
        scroll.setWidget(workflow_root)
        outer.addWidget(scroll, 1)

        self.activity_view = QPlainTextEdit()
        self.activity_view.setObjectName("ActivityLog")
        self.activity_view.setReadOnly(True)
        self.activity_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.activity_view.setMinimumHeight(84)
        self.activity_view.setMaximumHeight(148)
        self.activity_view.setAccessibleName("Registro diagnostico limitato")
        self.activity_view.setToolTip("Mostra fino a 160 eventi diagnostici recenti.")
        self._append_activity("UI", "Interfaccia pronta. Nessun comando tecnico è stato eseguito.")
        outer.addWidget(self.activity_view)

        footer = QHBoxLayout()
        footer_text = QLabel("B6-0 foundation: startup performs no rescue command and changes no target state.")
        footer_text.setObjectName("FooterText")
        footer.addWidget(footer_text, 1)
        contract_button = QPushButton("Safety contract")
        contract_button.setObjectName("SecondaryButton")
        contract_button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        contract_button.setAccessibleName("Show safety contract")
        contract_button.setToolTip("Show the active safety boundary")
        contract_button.clicked.connect(lambda: self._show_contract(contract))
        self.contract_button = contract_button
        footer.addWidget(contract_button)
        outer.addLayout(footer)

        self.setCentralWidget(root)
        self._contract_shortcut = QShortcut(QKeySequence("Alt+C"), self)
        self._contract_shortcut.activated.connect(lambda: self._show_contract(contract))
        self._contract_enter_shortcut = QShortcut(QKeySequence(Qt.Key.Key_Return), self.contract_button)
        self._contract_enter_shortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
        self._contract_enter_shortcut.activated.connect(lambda: self._show_contract(contract))
        self.setTabOrder(self.contract_button, self.activity_view)
        self._apply_responsive_layout(force=True)

    def _append_activity(self, stage: str, message: str) -> None:
        self.activity_log.append(stage, message)
        if hasattr(self, "activity_view"):
            self.activity_view.setPlainText("\n".join(self.activity_log.entries()))
            cursor = self.activity_view.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            self.activity_view.setTextCursor(cursor)

    def start_read_only_fixture_worker(self, work: Callable[[], str]) -> bool:
        """Start a test/instrumentation worker without any engine dispatch."""
        if self.fixture_worker is not None and self.fixture_worker.isRunning():
            self._append_activity("WORKER", "Diagnostic fixture already running.")
            return False
        self.ui_state = model.transition(self.ui_state, "RUNNING", reason="read_only_fixture")
        self.status_pill.setText(self.ui_state.state)
        self._append_activity("WORKER", "Read-only diagnostic fixture started.")
        worker = ReadOnlyFixtureWorker(work, self)
        worker.completed.connect(self._on_fixture_complete)
        worker.failed.connect(self._on_fixture_failed)
        worker.finished.connect(self._clear_fixture_worker)
        self.fixture_worker = worker
        worker.start()
        return True

    def _on_fixture_complete(self, result: str) -> None:
        self.ui_state = model.transition(self.ui_state, "REVIEW", reason="read_only_fixture_complete")
        self.status_pill.setText(self.ui_state.state)
        self._append_activity("WORKER", result)

    def _on_fixture_failed(self, reason: str) -> None:
        self.ui_state = model.transition(self.ui_state, "ERROR", reason="read_only_fixture_failed")
        self.status_pill.setText(self.ui_state.state)
        self._append_activity("WORKER", reason)

    def _clear_fixture_worker(self) -> None:
        worker = self.fixture_worker
        self.fixture_worker = None
        if worker is not None:
            worker.deleteLater()

    def _apply_responsive_layout(self, force: bool = False) -> None:
        width = self.centralWidget().width() if self.centralWidget() is not None else self.width()
        mode = "compact" if width < 1100 else "wide"
        if not force and mode == self._layout_mode:
            return
        self._layout_mode = mode
        direction = QBoxLayout.Direction.TopToBottom if mode == "compact" else QBoxLayout.Direction.LeftToRight
        self.header.setDirection(direction)
        self.cards.setDirection(direction)
        self.status_pill.setAlignment(Qt.AlignmentFlag.AlignLeft if mode == "compact" else Qt.AlignmentFlag.AlignCenter)
        for card in self.info_cards:
            card.setMinimumHeight(72 if mode == "compact" else 0)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._apply_responsive_layout()

    def _show_contract(self, contract: dict) -> None:
        self._append_activity("SAFETY", "Safety contract inspected by operator.")
        self.statusBar().showMessage(
            "Contract PASS - engine commands locked to Beta5; forbidden destructive commands absent.",
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
    accessibility = model.validate_b66_accessibility_contract()
    state = model.initial_state().to_dict()
    return {
        "profile": PROFILE,
        "passed": bool(contract["passed"]),
        "contract": contract,
        "accessibility": accessibility,
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
        window.show()
        app.processEvents()
        window.resize(1500, 950)
        app.processEvents()
        wide_mode = window._layout_mode
        window.resize(1000, 760)
        app.processEvents()
        payload = self_check()
        payload["window_created"] = True
        payload["window_title"] = window.windowTitle()
        payload["minimum_size"] = [window.minimumWidth(), window.minimumHeight()]
        payload["wide_layout_mode"] = wide_mode
        payload["compact_layout_mode"] = window._layout_mode
        payload["activity_log_entries"] = len(window.activity_log.entries())
        print(json.dumps(payload, indent=2, sort_keys=True))
        window.close()
        return 0 if payload["passed"] else 4

    window.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
