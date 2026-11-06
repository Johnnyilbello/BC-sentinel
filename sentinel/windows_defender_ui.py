"""Asynchronous user-operated Defender controls, with explicit removal consent."""
from __future__ import annotations

import json

from PySide6.QtCore import QProcess, QProcessEnvironment, Signal
from PySide6.QtWidgets import QDialog, QLabel, QMessageBox, QPushButton, QVBoxLayout, QTextEdit

from sentinel import windows_defender
from sentinel.ui_design_system import COLORS
from sentinel.ui_styles import home_stylesheet


class WindowsDefenderDialog(QDialog):
    dispatch_failed = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Scansione e rimozione · Microsoft Defender")
        self.resize(640, 600)
        self.ready = False
        self.active_count = 0
        self.action = "status"
        self.last_result = None
        self.last_error = ""
        self.process = QProcess(self)
        self.process.finished.connect(self._finished)
        self.process.errorOccurred.connect(self._failed)
        layout = QVBoxLayout(self)
        copy = QLabel(
            "Questi comandi utilizzano il motore Microsoft Defender installato in Windows. "
            "Le scansioni applicano le impostazioni di risposta di Defender e possono mettere in quarantena "
            "o rimuovere ciò che rilevano. Alcune operazioni richiedono permessi amministrativi."
        )
        copy.setWordWrap(True)
        layout.addWidget(copy)
        self.status = QLabel("Premi Aggiorna stato per verificare la disponibilità del motore.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.report = QTextEdit()
        self.report.setReadOnly(True)
        self.report.setAccessibleName("Stato e minacce attive rilevate da Microsoft Defender")
        layout.addWidget(self.report)
        self.refresh_button = QPushButton("Aggiorna stato")
        self.quick_button = QPushButton("Scansione rapida con Defender")
        self.full_button = QPushButton("Scansione completa con Defender")
        self.remove_button = QPushButton("Rimuovi tutte le minacce attive rilevate da Defender")
        self.refresh_button.setObjectName("DetailsButton")
        self.quick_button.setObjectName("PrimaryButton")
        self.full_button.setObjectName("DetailsButton")
        self.remove_button.setObjectName("DefenderRemoveButton")
        for button in self.buttons:
            button.setMinimumHeight(40)
            layout.addWidget(button)
        self.refresh_button.clicked.connect(lambda: self.run("status"))
        self.quick_button.clicked.connect(lambda: self.run("quick"))
        self.full_button.clicked.connect(lambda: self.run("full"))
        self.remove_button.clicked.connect(self.remove)
        self.setStyleSheet(home_stylesheet() + f"""
            QDialog {{ background: {COLORS['bg_app']}; color: {COLORS['text_primary']}; }}
            QTextEdit {{ background: {COLORS['surface_lowest']}; color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border_subtle']}; padding: 12px; }}
            #DefenderRemoveButton {{ color: {COLORS['danger']}; background: {COLORS['danger_soft']};
                border: 1px solid {COLORS['danger']}; border-radius: 8px; padding: 9px; }}
            #PrimaryButton:disabled, #DetailsButton:disabled, #DefenderRemoveButton:disabled {{
                color: {COLORS['disabled_text']}; background: {COLORS['disabled_surface']};
                border: 1px solid {COLORS['border_subtle']}; }}
        """)
        self._sync()

    @property
    def buttons(self):
        return (self.refresh_button, self.quick_button, self.full_button, self.remove_button)

    def busy(self) -> bool:
        return self.process.state() != QProcess.ProcessState.NotRunning

    def _sync(self) -> None:
        self.refresh_button.setEnabled(not self.busy())
        self.quick_button.setEnabled(not self.busy() and self.ready)
        self.full_button.setEnabled(not self.busy() and self.ready)
        self.remove_button.setEnabled(not self.busy() and self.ready and self.active_count > 0)

    def remove(self) -> None:
        if not self.remove_button.isEnabled():
            return
        result = QMessageBox.warning(
            self, "Rimuovi minacce rilevate",
            "Microsoft Defender tenterà di rimuovere TUTTE le minacce attive che ha rilevato sul PC. "
            "La disponibilità del ripristino dipende dalla risposta applicata da Defender. Procedere?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if result == QMessageBox.StandardButton.Yes:
            self.run("remove", removal_confirmed=True)

    def run(self, action: str, *, removal_confirmed: bool = False, scan_path: str | None = None) -> None:
        if self.busy() or (action != "status" and not self.ready):
            return
        self.action = action
        try:
            program, arguments = windows_defender.command(action, removal_confirmed=removal_confirmed)
        except (OSError, ValueError) as error:
            self._dispatch_error(str(error))
            return
        self.action = action
        self.last_error = ""
        environment = QProcessEnvironment.systemEnvironment()
        if action == "custom":
            from pathlib import Path
            try:
                valid_path = scan_path and Path(scan_path).is_absolute() and Path(scan_path).exists()
            except OSError:
                valid_path = False
            if not valid_path:
                self._dispatch_error("Seleziona un file o una cartella esistente.")
                return
            environment.insert("BC_SENTINEL_SCAN_PATH", scan_path)
        else:
            environment.remove("BC_SENTINEL_SCAN_PATH")
        self.process.setProcessEnvironment(environment)
        self.process.setProgram(program)
        self.process.setArguments(arguments)
        self.status.setText("Operazione Defender in corso. La scansione completa può richiedere tempo.")
        self.process.start()
        self._sync()

    def _dispatch_error(self, message: str) -> None:
        self.ready = False
        self.active_count = 0
        self.last_result = None
        self.last_error = message
        self.status.setText(message)
        self.report.setPlainText(message)
        self._sync()
        self.dispatch_failed.emit(message)

    def _failed(self, error) -> None:
        self.ready = False
        self.last_result = None
        self.active_count = 0
        self.status.setText("Impossibile avviare Defender. " + self.process.errorString())
        self.last_error = self.status.text()
        self.report.setPlainText(self.last_error)
        self._sync()

    def _finished(self, code: int, exit_status) -> None:
        output = bytes(self.process.readAllStandardOutput()).decode("utf-8-sig", errors="replace").strip()
        error = bytes(self.process.readAllStandardError()).decode("utf-8-sig", errors="replace").strip()
        self.ready = False
        self.active_count = 0
        self.last_result = None
        try:
            if code != 0 or exit_status != QProcess.ExitStatus.NormalExit:
                raise ValueError(error[:2000] or "Il comando Defender non è stato completato.")
            data = json.loads(output)
            if not isinstance(data, dict) or not isinstance(data.get("active_threats"), list):
                raise ValueError("Risposta Defender non valida.")
            self.ready = data.get("service_enabled") is True and data.get("antivirus_enabled") is True and data.get("mode") == "Normal"
            self.last_result = data
            threats = data["active_threats"]
            self.active_count = len(threats)
            lines = [
                "Motore Microsoft Defender",
                "Modalità: " + str(data.get("mode", "")),
                "Versione firme: " + str(data.get("signature_version", "")),
                "Aggiornamento firme: " + str(data.get("signature_updated", "")),
                "Minacce attive riportate: " + str(len(threats)),
            ]
            lines.extend(str(item.get("name", "")) for item in threats if isinstance(item, dict))
            self.report.setPlainText("\n".join(lines))
            self.status.setText(
                "Comando completato. Lo stato riportato proviene da Microsoft Defender."
                if self.ready else "Defender non è disponibile in modalità antivirus attiva su questo PC."
            )
        except (ValueError, TypeError) as failure:
            self.status.setText("Operazione non completata. " + str(failure))
            self.last_error = self.status.text()
            self.report.setPlainText(self.last_error)
        self._sync()

    def closeEvent(self, event) -> None:
        if self.busy():
            self.status.setText("Attendi il termine del comando Defender prima di chiudere.")
            event.ignore()
            return
        super().closeEvent(event)
