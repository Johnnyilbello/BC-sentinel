"""On-demand BC scanner page; no changes to files or system protection."""
from pathlib import Path
from threading import Event

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QMessageBox, QProgressBar, QPushButton, QTextEdit, QVBoxLayout, QWidget

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


class BCScanPage(QWidget):
    scan_started = Signal(str)
    scan_completed = Signal(object)
    scan_failed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.catalog = None
        self.yara_path = None
        self.last_result = None
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        title = QLabel("Scansione con motore BC")
        title.setObjectName("PageTitle")
        layout.addWidget(title)
        explanation = QLabel("Analisi locale su richiesta tramite SHA-256. Il catalogo incluso riconosce solo il test innocuo EICAR; puoi caricare un catalogo di hash approvato. Non è una protezione in tempo reale e non sostituisce un antivirus completo.")
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
        self.catalog_button.setEnabled(False)
        self.yara_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.worker = ScanThread(folder, self.catalog, self.yara_path)
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
        self.catalog_button.setEnabled(True)
        self.yara_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
