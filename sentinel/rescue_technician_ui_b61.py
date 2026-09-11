from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Final

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sentinel import rescue_target_discovery as b50
from sentinel import rescue_technician_target_selection as selection
from sentinel import rescue_technician_ui as b60ui

PROFILE: Final[str] = selection.PROFILE
WINDOW_TITLE: Final[str] = "BC Sentinel - Rescue Technician / Target Selection"


class TargetDiscoveryPanel(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("TargetDiscoveryPanel")
        self.snapshot: selection.DiscoveryUiSnapshot | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        header = QHBoxLayout()
        copy = QVBoxLayout()
        title = QLabel("Offline target selection")
        title.setObjectName("SectionTitle")
        subtitle = QLabel(
            "Discover candidate Windows volumes, review their safety state, then explicitly select one READY target."
        )
        subtitle.setObjectName("WorkflowBody")
        subtitle.setWordWrap(True)
        copy.addWidget(title)
        copy.addWidget(subtitle)
        header.addLayout(copy, 1)
        self.discover_button = QPushButton("Discover targets")
        self.discover_button.setObjectName("PrimaryButton")
        self.discover_button.setProperty("engineCommand", "discover")
        header.addWidget(self.discover_button, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)

        self.table = QTableWidget(0, 5)
        self.table.setObjectName("TargetTable")
        self.table.setHorizontalHeaderLabels(("State", "Target", "Source", "Reason", "Fingerprint"))
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setMinimumHeight(220)
        layout.addWidget(self.table)

        footer = QHBoxLayout()
        self.guidance_label = QLabel("No discovery has been run in this session.")
        self.guidance_label.setObjectName("WorkflowBody")
        self.guidance_label.setWordWrap(True)
        footer.addWidget(self.guidance_label, 1)
        self.use_button = QPushButton("Use selected target")
        self.use_button.setObjectName("PrimaryButton")
        self.use_button.setEnabled(False)
        footer.addWidget(self.use_button)
        layout.addLayout(footer)

        self.table.itemSelectionChanged.connect(self._selection_changed)

    def load_snapshot(self, snapshot: selection.DiscoveryUiSnapshot) -> None:
        self.snapshot = snapshot
        self.table.setRowCount(len(snapshot.targets))
        for row, target in enumerate(snapshot.targets):
            values = (
                target.state,
                target.normalized_root,
                target.discovery_source,
                target.reason,
                target.target_fingerprint or "-",
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setData(Qt.ItemDataRole.UserRole, row)
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole + 1, bool(target.selectable))
                self.table.setItem(row, column, item)
        self.table.resizeColumnsToContents()
        self.use_button.setEnabled(False)
        ready = snapshot.counts.get(b50.STATE_READY, 0)
        total = len(snapshot.targets)
        self.guidance_label.setText(
            f"Discovery complete: {total} candidate(s), {ready} READY. Only READY targets can be selected."
        )

    def selected_index(self) -> int | None:
        rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if len(rows) != 1:
            return None
        return int(rows[0].row())

    def selected_target(self) -> selection.TargetChoice | None:
        index = self.selected_index()
        if index is None or self.snapshot is None or index >= len(self.snapshot.targets):
            return None
        return self.snapshot.targets[index]

    def _selection_changed(self) -> None:
        target = self.selected_target()
        if target is None:
            self.use_button.setEnabled(False)
            return
        self.use_button.setEnabled(bool(target.selectable))
        self.guidance_label.setText(f"{target.state}: {target.guidance} Reason: {target.reason}")


class TechnicianTargetSelectionWindow(b60ui.TechnicianWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(WINDOW_TITLE)
        self.target_panel = TargetDiscoveryPanel()
        root_layout = self.centralWidget().layout()
        root_layout.insertWidget(3, self.target_panel)
        self.target_panel.discover_button.clicked.connect(self._discover_targets)
        self.target_panel.use_button.clicked.connect(self._use_selected_target)
        self._apply_b61_theme()

    def _apply_b61_theme(self) -> None:
        self.setStyleSheet(
            self.styleSheet()
            + """
            #TargetDiscoveryPanel { background: #0e141a; border: 1px solid #25313b; border-radius: 14px; }
            #PrimaryButton { background: #d9e8f1; color: #0d151b; border: 1px solid #eef7fb; border-radius: 8px; padding: 9px 14px; font-weight: 700; }
            #PrimaryButton:disabled { background: #182027; color: #687581; border-color: #27313a; }
            #TargetTable { background: #0c1116; alternate-background-color: #10171d; color: #dbe4ea; border: 1px solid #26323c; border-radius: 9px; gridline-color: #1f2932; selection-background-color: #243642; selection-color: #f4f8fa; }
            #TargetTable QHeaderView::section { background: #151d24; color: #aebbc5; border: 0; border-bottom: 1px solid #2a3640; padding: 7px; font-weight: 700; }
            """
        )

    def load_discovery_result(self, result: dict) -> selection.DiscoveryUiSnapshot:
        snapshot = selection.snapshot_from_result(result)
        self.target_panel.load_snapshot(snapshot)
        self.ui_state.session_id = snapshot.session_id
        self.ui_state.correlation_id = snapshot.correlation_id
        self.ui_state.last_command = "discover"
        self.ui_state.last_engine_state = "DISCOVERY_COMPLETE"
        self.ui_state.last_reason = "operator_requested_discovery"
        self.ui_state.state = "REVIEW"
        self.ui_state.busy = False
        self.ui_state.validate()
        self.status_pill.setText(self.ui_state.state)
        return snapshot

    def _discover_targets(self) -> None:
        self.ui_state.state = "RUNNING"
        self.ui_state.busy = True
        self.ui_state.last_command = "discover"
        self.ui_state.last_reason = "operator_requested_discovery"
        self.ui_state.validate()
        self.status_pill.setText("RUNNING")
        self.target_panel.discover_button.setEnabled(False)
        try:
            snapshot = selection.run_discovery(include_windows_volumes=True)
            self.target_panel.load_snapshot(snapshot)
            self.ui_state.session_id = snapshot.session_id
            self.ui_state.correlation_id = snapshot.correlation_id
            self.ui_state.state = "REVIEW"
            self.ui_state.busy = False
            self.ui_state.last_engine_state = "DISCOVERY_COMPLETE"
            self.status_pill.setText("REVIEW")
        except Exception as exc:
            self.ui_state.state = "ERROR"
            self.ui_state.busy = False
            self.ui_state.last_engine_state = "DISCOVERY_ERROR"
            self.ui_state.last_reason = f"{type(exc).__name__}:{exc}"
            self.status_pill.setText("ERROR")
            self.target_panel.guidance_label.setText("Discovery failed safely: " + self.ui_state.last_reason)
        finally:
            self.target_panel.discover_button.setEnabled(True)
            self.ui_state.validate()

    def _use_selected_target(self) -> None:
        snapshot = self.target_panel.snapshot
        index = self.target_panel.selected_index()
        if snapshot is None or index is None:
            return
        try:
            self.ui_state = selection.select_target(snapshot, index, ui_state=self.ui_state)
        except ValueError as exc:
            self.ui_state.state = "REFUSED"
            self.ui_state.busy = False
            self.ui_state.last_reason = str(exc)
            self.ui_state.validate()
            self.status_pill.setText("REFUSED")
            self.target_panel.guidance_label.setText("Target selection refused: " + str(exc))
            return
        self.status_pill.setText("READY")
        target = snapshot.targets[index]
        self.target_panel.guidance_label.setText(
            "Selected READY target: " + target.normalized_root + " | fingerprint=" + target.target_fingerprint
        )


def self_check() -> dict:
    contract = selection.safety_contract()
    return {
        "profile": PROFILE,
        "passed": all(
            (
                contract["read_only_discovery"] is True,
                contract["explicit_operator_selection_required"] is True,
                contract["ready_only_selection"] is True,
                contract["unlock_offered"] is False,
                contract["mount_write_offered"] is False,
                contract["automatic_target_selection"] is False,
                contract["automatic_repair"] is False,
                contract["automatic_destructive_action"] is False,
            )
        ),
        "window_title": WINDOW_TITLE,
        "safety": contract,
        "startup_discovery": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta6 B6-1 target discovery and selection UX")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--offscreen-smoke", action="store_true")
    parser.add_argument("--fixture-root", action="append", default=[])
    args = parser.parse_args(argv)

    if args.self_check and not args.offscreen_smoke:
        payload = self_check()
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if payload["passed"] else 4

    if args.offscreen_smoke:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    app = QApplication.instance() or QApplication(sys.argv[:1])
    window = TechnicianTargetSelectionWindow()
    if args.fixture_root:
        snapshot = selection.run_discovery(
            [Path(item) for item in args.fixture_root],
            include_windows_volumes=False,
            limits=b50.DiscoveryLimits(probe_children=False),
            bitlocker_probe=lambda _: {"provider": "b61_fixture", "available": False, "locked": False},
        )
        window.target_panel.load_snapshot(snapshot)
    if args.offscreen_smoke:
        payload = self_check()
        payload.update(
            {
                "window_created": True,
                "window_title_actual": window.windowTitle(),
                "discover_enabled": window.target_panel.discover_button.isEnabled(),
                "use_target_enabled": window.target_panel.use_button.isEnabled(),
                "startup_state": window.ui_state.state,
            }
        )
        print(json.dumps(payload, indent=2, sort_keys=True))
        window.close()
        return 0 if payload["passed"] else 4

    window.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
