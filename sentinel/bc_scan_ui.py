"""Manual scanning and change-triggered analysis for selected folders."""
from pathlib import Path
from threading import Event

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QTextEdit, QVBoxLayout, QWidget

from sentinel.bc_folder_monitor import monitor_folder
from sentinel.bc_scan import scan_folder


class ScanThread(QThread):
    update = Signal(int, str)
    result_ready = Signal(object)
    failure = Signal(str)

    def __init__(self, folder, catalog, yara_path=None):
        super().__init__()
        self.folder, self.catalog, self.yara_path = folder, catalog, yara_path
        self.stop_event = Event()

    def run(self):
        try:
            self.result_ready.emit(scan_folder(self.folder, catalog_path=self.catalog, yara_path=self.yara_path,
                cancelled=self.stop_event.is_set, progress=self.update.emit))
        except Exception as exc:
            self.failure.emit(str(exc))


class MonitorThread(QThread):
    ready = Signal(str)
    batch = Signal(object, int)
    failure = Signal(str)

    def __init__(self, folder, catalog, yara_path):
        super().__init__()
        self.folder, self.catalog, self.yara_path = folder, catalog, yara_path
        self.stop_event = Event()

    def run(self):
        try:
            monitor_folder(self.folder, catalog=self.catalog, yara_path=self.yara_path, stop=self.stop_event,
                           started=self.ready.emit, report=self.batch.emit)
        except Exception as exc:
            self.failure.emit(str(exc))


class BCScanPage(QWidget):
    scan_started = Signal(str)
    scan_completed = Signal(object)
    scan_failed = Signal(str)
    monitor_stopped = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.monitor = None
        self.monitor_error = None
        self.catalog = None
        self.yara_path = None
        self.last_result = None
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        title = QLabel("Scansione con motore BC")
        title.setObjectName("PageTitle")
        layout.addWidget(title)
        explanation = QLabel("Analisi locale con hash e regole YARA. Il catalogo incluso riconosce il test innocuo EICAR. Puoi caricare un catalogo verificato e regole locali.")
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        row = QHBoxLayout()
        self.start_button = QPushButton("Scegli cartella e avvia")
        self.start_button.setObjectName("PrimaryButton")
        self.start_button.clicked.connect(self.choose_folder)
        self.catalog_button = QPushButton("Carica catalogo hash…")
        self.catalog_button.clicked.connect(self.choose_catalog)
        self.cancel_button = QPushButton("Annulla scansione")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel)
        for button in (self.start_button, self.catalog_button, self.cancel_button):
            button.setMinimumHeight(44)
            row.addWidget(button)
        layout.addLayout(row)
        self.yara_button = QPushButton('Carica regole YARA…')
        self.yara_button.setMinimumHeight(44)
        self.yara_button.clicked.connect(self.choose_yara)
        layout.addWidget(self.yara_button)
        self.yara_label = QLabel('Regole YARA: nessuna selezionata')
        self.yara_label.setWordWrap(True)
        layout.addWidget(self.yara_label)
        self.catalog_label = QLabel("Catalogo: test EICAR integrato")
        self.catalog_label.setWordWrap(True)
        layout.addWidget(self.catalog_label)
        self.status = QLabel("Seleziona una cartella per iniziare.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        layout.addWidget(self.progress)
        self.report = QTextEdit()
        self.report.setReadOnly(True)
        self.report.setMinimumHeight(240)
        self.report.setPlainText("I risultati e gli eventuali file non analizzati compariranno qui.")
        layout.addWidget(self.report)

        heading = QLabel("Monitoraggio cartella")
        heading.setObjectName("SectionTitle")
        layout.addWidget(heading)
        scope = QLabel("Analizza i file nuovi o modificati nella cartella scelta finché l’app è aperta. La scansione avviene dopo la modifica e non blocca l’apertura dei file.")
        scope.setWordWrap(True)
        layout.addWidget(scope)
        self.monitor_button = QPushButton("Scegli cartella da monitorare…")
        self.monitor_button.setMinimumHeight(44)
        self.monitor_button.clicked.connect(self.toggle_monitor)
        layout.addWidget(self.monitor_button)
        self.monitor_status = QLabel("Monitoraggio inattivo.")
        self.monitor_status.setTextFormat(Qt.TextFormat.PlainText)
        self.monitor_status.setWordWrap(True)
        layout.addWidget(self.monitor_status)
        self.monitor_report = QPlainTextEdit()
        self.monitor_report.setReadOnly(True)
        self.monitor_report.setMaximumBlockCount(200)
        self.monitor_report.setPlaceholderText("Le corrispondenze e gli errori compariranno qui.")
        self.monitor_report.setFixedHeight(112)
        layout.addWidget(self.monitor_report)

    def toggle_monitor(self):
        if self.monitor is not None:
            self.stop_monitor()
            return
        folder = QFileDialog.getExistingDirectory(self, "Seleziona la cartella da monitorare")
        if folder:
            self.start_monitor(folder)

    def start_monitor(self, folder):
        if self.monitor is not None:
            return
        self.monitor_error = None
        self.monitor_counts = [0, 0, 0]
        self.monitor_folder = str(folder)
        self.monitor_report.clear()
        self.monitor_status.setText("Avvio monitoraggio…")
        self.monitor_button.setText("Ferma monitoraggio")
        self.monitor = MonitorThread(folder, self.catalog, self.yara_path)
        self.monitor.ready.connect(self._monitor_ready)
        self.monitor.batch.connect(self._monitor_batch)
        self.monitor.failure.connect(self._monitor_failed)
        self.monitor.finished.connect(self._monitor_finished)
        self._sync_inputs()
        self.monitor.start()

    def stop_monitor(self):
        if self.monitor is not None:
            self.monitor.stop_event.set()
            self.monitor_status.setText("Arresto del monitoraggio…")
            self.monitor_button.setEnabled(False)

    def _monitor_ready(self, folder):
        self.monitor_folder = folder
        if not self.monitor.stop_event.is_set():
            self.monitor_status.setText("Monitoraggio attivo · " + folder)

    def _monitor_batch(self, result, missed):
        self.monitor_counts[0] += result["files"]
        self.monitor_counts[1] += len(result["findings"])
        self.monitor_counts[2] += result["skipped"] + missed
        files, findings, skipped = self.monitor_counts
        for item in result["findings"][-100:]:
            self.monitor_report.appendPlainText(f"{item['name']} — {item['path']}")
        for error in result["errors"][-20:]:
            self.monitor_report.appendPlainText(error)
        if missed:
            self.monitor_report.appendPlainText(f"{missed} eventi con copertura parziale. Avvia una scansione manuale.")
        if not self.monitor.stop_event.is_set():
            self.monitor_status.setText(f"{self.monitor_folder} · {files} file · {findings} corrispondenze · {skipped} saltati")

    def _monitor_failed(self, message):
        self.monitor_error = message

    def _monitor_finished(self):
        self.monitor.deleteLater()
        self.monitor = None
        self.monitor_button.setEnabled(True)
        self.monitor_button.setText("Scegli cartella da monitorare…")
        files, findings, skipped = self.monitor_counts
        self.monitor_status.setText(
            "Monitoraggio interrotto: " + self.monitor_error if self.monitor_error else
            f"Monitoraggio fermo · {files} file · {findings} corrispondenze · {skipped} saltati")
        self._sync_inputs()
        self.monitor_stopped.emit()

    def _sync_inputs(self):
        editable = self.worker is None and self.monitor is None
        self.catalog_button.setEnabled(editable)
        self.yara_button.setEnabled(editable)

    def choose_catalog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Catalogo hash approvato", "", "JSON (*.json)")
        if path:
            from sentinel.rescue_offline_scanner import load_approved_intel_catalog
            try:
                entries = load_approved_intel_catalog(Path(path))
            except ValueError as exc:
                QMessageBox.warning(self, "Catalogo non valido", str(exc))
                return
            self.catalog = path
            self.catalog_label.setText(f"Catalogo: {Path(path).name} · {len(entries)} hash, oltre a EICAR")

    def choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Seleziona la cartella da analizzare")
        if folder:
            self.start_scan(folder)

    def choose_yara(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Seleziona regole YARA', '', 'YARA (*.yar *.yara)')
        if path:
            from sentinel.rescue_offline_scanner import _compile_yara
            try:
                rules, status = _compile_yara(Path(path))
                if rules is None:
                    raise ValueError('Motore YARA non disponibile: ' + status)
            except ValueError as exc:
                QMessageBox.warning(self, 'Regole non valide', str(exc))
                return
            self.yara_path = path
            self.yara_label.setText('Regole YARA: ' + Path(path).name)

    def start_scan(self, folder):
        if self.worker is not None:
            return
        self.last_result = None
        self.report.clear()
        self.status.setText("Scansione BC in corso…")
        self.progress.setRange(0, 0)
        self.start_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.worker = ScanThread(folder, self.catalog, self.yara_path)
        self._sync_inputs()
        self.worker.update.connect(lambda count, path: self.status.setText(f"File analizzati: {count} · {path}"))
        self.worker.result_ready.connect(self.finished_scan)
        self.worker.failure.connect(self.failed_scan)
        self.worker.finished.connect(self.thread_finished)
        self.scan_started.emit(str(folder))
        self.worker.start()

    def cancel(self):
        if self.worker is not None:
            self.worker.stop_event.set()
            self.status.setText("Annullamento in corso…")
            self.cancel_button.setEnabled(False)

    def finished_scan(self, result):
        self.last_result = result
        state = "Annullata" if result["cancelled"] else "Completata"
        self.status.setText(f"{state} · {result['files']} file analizzati · {result['skipped']} saltati · {len(result['findings'])} corrispondenze")
        lines = [f"{x['name']} — {x['path']}\nSHA-256: {x['sha256']}" for x in result["findings"]]
        if not lines:
            lines.append("Nessuna corrispondenza con il catalogo utilizzato. Questo non garantisce che i file siano sicuri.")
        if result["errors"]:
            lines.append("Errori di lettura (primi 100):\n" + "\n".join(result["errors"]))
        if result["skipped"]:
            lines.append("Copertura parziale: file, contenuti ZIP o controlli non analizzati. Vedi i dettagli disponibili sopra.")
        self.report.setPlainText("\n\n".join(lines))
        self.scan_completed.emit(result)

    def failed_scan(self, message):
        self.status.setText("Scansione non riuscita: " + message)
        self.scan_failed.emit(message)

    def thread_finished(self):
        self.worker.deleteLater()
        self.worker = None
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        self.start_button.setEnabled(True)
        self._sync_inputs()
        self.cancel_button.setEnabled(False)
