"""Dedicated desktop control for a read-only scan of an offline Windows tree."""
from __future__ import annotations

from pathlib import Path
from threading import Event

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QDialog, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QTextEdit, QVBoxLayout,
)

from sentinel.rescue_offline_scanner import OfflineScanLimits, scan_offline_windows


class ScanWorker(QObject):
    progress = Signal(dict)
    result = Signal(dict)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, root: Path, output: Path, cancel: Event, intel: Path | None = None, yara: Path | None = None) -> None:
        super().__init__()
        self.root = root
        self.output = output
        self.cancel = cancel
        self.intel = intel
        self.yara = yara

    @Slot()
    def run(self) -> None:
        try:
            report = scan_offline_windows(
                self.root, self.output, limits=OfflineScanLimits(),
                cancel_check=self.cancel.is_set, progress_callback=self.progress.emit,
                intel_catalog=self.intel, yara_rules=self.yara, require_separate_volume=True,
            )
            self.result.emit(report)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        finally:
            self.finished.emit()


class OfflineScanDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Scansione offline · sola lettura")
        self.setMinimumSize(640, 460)
        self._cancel = Event()
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None

        layout = QVBoxLayout(self)
        description = QLabel(
            "Seleziona un'installazione Windows offline. I report vengono salvati "
            "fuori dal volume esaminato. Questa funzione non offre protezione attiva."
        )
        description.setWordWrap(True)
        layout.addWidget(description)
        self.root_edit = QLineEdit()
        self.root_edit.setPlaceholderText("Volume/cartella Windows offline")
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Cartella dei report fuori dal volume")
        for entry, label, chooser in (
            (self.root_edit, "Volume offline", self.choose_root),
            (self.output_edit, "Cartella report", self.choose_output),
        ):
            row = QHBoxLayout()
            button = QPushButton("Sfoglia…")
            button.clicked.connect(chooser)
            row.addWidget(QLabel(label))
            row.addWidget(entry, 1)
            row.addWidget(button)
            layout.addLayout(row)
        self.intel_edit = QLineEdit()
        self.intel_edit.setPlaceholderText("Catalogo SHA-256 approvato (facoltativo)")
        self.yara_edit = QLineEdit()
        self.yara_edit.setPlaceholderText("Regole YARA locali (facoltative)")
        for entry, title in ((self.intel_edit, "Catalogo IOC"), (self.yara_edit, "Regole YARA")):
            row = QHBoxLayout()
            row.addWidget(entry)
            button = QPushButton(title)
            button.clicked.connect(lambda checked=False, entry=entry, title=title:
                                   entry.setText(QFileDialog.getOpenFileName(self, title)[0]))
            row.addWidget(button)
            layout.addLayout(row)
        notice = QLabel("Senza catalogo e regole: solo analisi strutturale ed euristica. "
                        "Limiti predefiniti: 10.000 file, 64 MiB/file, 1 GiB totale, 10 minuti, 1 GiB RAM. "
                        "Sono esaminate solo le posizioni Windows supportate.")
        notice.setWordWrap(True)
        layout.addWidget(notice)
        self.status = QLabel("In attesa di una scansione.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.findings = QTextEdit()
        self.findings.setReadOnly(True)
        layout.addWidget(self.findings, 1)
        row = QHBoxLayout()
        self.start_button = QPushButton("Avvia scansione offline")
        self.cancel_button = QPushButton("Annulla")
        self.cancel_button.setEnabled(False)
        self.start_button.clicked.connect(self.start_scan)
        self.cancel_button.clicked.connect(self.cancel_scan)
        row.addWidget(self.start_button)
        row.addWidget(self.cancel_button)
        layout.addLayout(row)

    def choose_root(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Installazione Windows offline")
        if chosen:
            self.root_edit.setText(chosen)

    def choose_output(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Cartella per i report")
        if chosen:
            self.output_edit.setText(chosen)

    def start_scan(self) -> None:
        if self._thread is not None:
            return
        root = Path(self.root_edit.text().strip())
        output = Path(self.output_edit.text().strip())
        if not self.root_edit.text().strip() or not self.output_edit.text().strip():
            QMessageBox.warning(self, "Percorsi mancanti", "Seleziona il volume offline e la cartella report.")
            return
        self._cancel = Event()
        self._thread = QThread(self)
        self._worker = ScanWorker(root, output, self._cancel,
                                  Path(self.intel_edit.text()) if self.intel_edit.text() else None,
                                  Path(self.yara_edit.text()) if self.yara_edit.text() else None)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.result.connect(self._on_result)
        self._worker.failed.connect(self._on_failed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._on_finished)
        self.start_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.status.setText("Scansione in corso…")
        self.findings.clear()
        self._thread.start()

    def cancel_scan(self) -> None:
        self._cancel.set()
        self.cancel_button.setEnabled(False)
        self.status.setText("Annullamento richiesto. Attendo la fine del file corrente…")

    @Slot(dict)
    def _on_progress(self, progress: dict) -> None:
        self.status.setText(
            f"Esaminati: {progress['enumerated']} · letti: {progress['hashed']} · "
            f"saltati: {progress['skipped']} · errori: {progress['errors']}"
        )

    @Slot(dict)
    def _on_result(self, report: dict) -> None:
        rows = report["findings"]
        counts = {key: sum(row["verdict"] == key for row in rows)
                  for key in ("deterministic_ioc", "yara_match", "review", "unreadable", "not_scanned")}
        complete = report["state"] == "completed"
        self.status.setText(
            ("Scansione completata" if complete else "Scansione incompleta")
            + f" · rilevati: {counts['deterministic_ioc'] + counts['yara_match']}"
            + f" · revisione: {counts['review']}"
            + f" · errori: {counts['unreadable']}"
            + f" · non esaminati: {counts['not_scanned']}"
        )
        lines = [f"Stato: {report['state']}", "Nessuna conclusione di file pulito.",
                 f"Report: {report['output_dir']}"]
        lines.extend(f"{row['verdict']}: {row['relative_path']}" for row in rows)
        if report["summary"]["incomplete_reasons"]:
            lines.append("Motivi di incompletezza: " + ", ".join(report["summary"]["incomplete_reasons"]))
        self.findings.setPlainText("\n".join(lines))

    @Slot(str)
    def _on_failed(self, message: str) -> None:
        self.status.setText("Scansione non riuscita")
        self.findings.setPlainText(message)

    @Slot()
    def _on_finished(self) -> None:
        if self._thread is not None:
            self._thread.deleteLater()
        self._thread = None
        self._worker = None
        self.start_button.setEnabled(True)
        self.cancel_button.setEnabled(False)

    def reject(self) -> None:
        if self._thread is not None:
            self.cancel_scan()
            return
        super().reject()
