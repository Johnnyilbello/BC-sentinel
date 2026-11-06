"""Operational desktop. Every visible command has a real action and an observable result."""
from __future__ import annotations

import ctypes
from datetime import datetime
import json
import os
from pathlib import Path
import sys
import traceback

from PySide6.QtCore import QSaveFile, QIODevice, Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QFrame, QHBoxLayout, QLabel,
    QMainWindow, QMessageBox, QPushButton, QStackedWidget, QTextEdit, QVBoxLayout, QWidget,
)

from sentinel.home_security_ui import _PageScroll
from sentinel.storage_analyzer_ui import StorageAnalyzerPage
from sentinel.ui_design_system import COLORS, make_icon
from sentinel.ui_pages import PageHeader
from sentinel.ui_styles import home_stylesheet
from sentinel.windows_defender_ui import WindowsDefenderDialog


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = QSaveFile(str(path))
    if not stream.open(QIODevice.OpenModeFlag.WriteOnly):
        raise OSError(stream.errorString())
    payload = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
    if stream.write(payload) != len(payload) or not stream.commit():
        raise OSError(stream.errorString())


def install_exception_reporting(window) -> None:
    def report(error_type, error, trace):
        detail = "".join(traceback.format_exception(error_type, error, trace))
        try:
            window.data_root.mkdir(parents=True, exist_ok=True)
            with (window.data_root / "errors.log").open("a", encoding="utf-8") as stream:
                stream.write(datetime.now().isoformat() + "\n" + detail + "\n")
        except OSError:
            pass
        QMessageBox.critical(window, "Operazione non completata",
            str(error) + "\nL’errore è stato registrato, quando la cartella dati è accessibile. "
            "Puoi esportare la diagnostica da Impostazioni e aiuto.")
    sys.excepthook = report


class OperationalWindow(QMainWindow):
    def __init__(self, *, data_root: Path | None = None, auto_status: bool = True) -> None:
        super().__init__()
        self.setWindowTitle("BC Sentinel")
        self.resize(1180, 820)
        self.setMinimumSize(720, 600)
        screen = QApplication.primaryScreen()
        if screen is not None:
            geometry = screen.availableGeometry()
            self.resize(min(1180, geometry.width() - 40), min(820, geometry.height() - 60))
        self.data_root = data_root or Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "BCSentinel" / "desktop"
        self.events = []
        self.command_buttons = {}
        self.nav_buttons = {}
        self.pages = {}
        self.pending_scan = None
        self.offline_dialog = None
        self._load_events()
        QApplication.instance().setFont(QFont("Segoe UI", 10))

        shell = QWidget()
        shell.setObjectName("AppShell")
        root = QHBoxLayout(shell)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(210)
        navigation = QVBoxLayout(sidebar)
        navigation.setContentsMargins(16, 24, 16, 20)
        navigation.setSpacing(8)
        brand = QLabel("BC Sentinel")
        brand.setObjectName("PageTitle")
        navigation.addWidget(brand)
        navigation.addSpacing(20)
        self.stack = QStackedWidget()
        self.stack.setObjectName("PageStack")
        root.addWidget(sidebar)
        root.addWidget(self.stack, 1)
        self.setCentralWidget(shell)
        for name, icon in (
            ("Dashboard", "dashboard"), ("Scansione", "scan"), ("Scansione offline", "folder"),
            ("Quarantena", "quarantine"), ("Cronologia", "history"),
            ("Protezione", "shield"), ("Storage Analyzer", "folder"), ("Impostazioni e aiuto", "settings"),
        ):
            button = QPushButton(name)
            button.setObjectName("NavItem")
            button.setIcon(make_icon(icon))
            button.setMinimumHeight(44)
            button.setCheckable(True)
            button.setAccessibleName(name)
            button.clicked.connect(lambda checked=False, route=name: self.navigate(route))
            navigation.addWidget(button)
            self.nav_buttons[name] = button
        navigation.addStretch()
        self.sidebar = sidebar

        page = self._page("Dashboard", "Stato del PC e azioni principali")
        self.overview = self._label("Verifica dello stato antivirus in corso…", page)
        self._button("dashboard_refresh", "Aggiorna stato", self.refresh_status, page)
        self._button("dashboard_quick", "Avvia scansione rapida", lambda: self.request_scan("quick"), page, primary=True)
        self._button("dashboard_full", "Avvia scansione completa", lambda: self.request_scan("full"), page)
        self._button("dashboard_storage", "Analizza spazio e RAM", lambda: self.navigate("Storage Analyzer"), page)

        page = self._page("Scansione", "Controlli operativi del motore Microsoft Defender")
        self.engine = WindowsDefenderDialog()
        self.engine.setParent(page)
        self.engine.setWindowFlags(Qt.WindowType.Widget)
        page.layout().addWidget(self.engine)
        self._button("custom_scan", "Scansiona una cartella…", self.custom_scan, page)
        self.engine.process.finished.connect(self._engine_finished)
        self.engine.process.errorOccurred.connect(self._engine_error)
        self.engine.dispatch_failed.connect(self._engine_error)
        self.engine.setMinimumHeight(500)

        page = self._page("Scansione offline", "Esamina un’installazione Windows offline con SHA-256 e YARA")
        self._label("Scegli il volume Windows da esaminare e una cartella dei report su un altro volume. "
                    "La scansione legge i file e segnala rilevamenti, errori e limiti della copertura.", page)
        self._button("offline_open", "Apri scansione offline", self.open_offline, page, primary=True)

        page = self._page("Quarantena", "Minacce rilevate da Defender e accesso alla gestione di Windows")
        self.threats = QTextEdit()
        self.threats.setReadOnly(True)
        self.threats.setMinimumHeight(240)
        page.layout().addWidget(self.threats)
        self._label("Per consultare gli elementi isolati o ripristinarli, apri Sicurezza di Windows e scegli "
                    "Protezione da virus e minacce → Cronologia della protezione.", page)
        self._button("quarantine_refresh", "Aggiorna rilevamenti", self.refresh_status, page)
        self._button("quarantine_windows", "Apri Sicurezza di Windows", self.open_windows_security, page)
        self._button("quarantine_remove", "Rimuovi le minacce attive rilevate", self.request_removal, page)

        page = self._page("Cronologia", "Operazioni effettivamente eseguite da questo desktop")
        self.history = QTextEdit()
        self.history.setReadOnly(True)
        self.history.setMinimumHeight(300)
        page.layout().addWidget(self.history)
        self._button("history_refresh", "Aggiorna cronologia", self.render_history, page)
        self._button("history_export", "Esporta cronologia…", self.export_history, page)

        page = self._page("Protezione", "Stato e gestione del motore antivirus di Windows")
        self.protection = self._label("Aggiorna lo stato per leggere i valori correnti del motore.", page)
        self._button("protection_refresh", "Aggiorna stato protezione", self.refresh_status, page)
        self._button("signatures", "Aggiorna firme antivirus", lambda: self.request_scan("update"), page)
        self._button("security_settings", "Apri Sicurezza di Windows", self.open_windows_security, page)
        self._button("administrator", "Apri BC Sentinel come amministratore", self.elevate, page)

        self.storage_page = StorageAnalyzerPage()
        self._add_page("Storage Analyzer", self.storage_page)

        page = self._page("Impostazioni e aiuto", "Preferenze locali, diagnostica e istruzioni")
        self.auto_refresh = QCheckBox("Aggiorna lo stato antivirus ogni 60 secondi")
        self.auto_refresh.setChecked(self._load_auto_refresh())
        self.auto_refresh.toggled.connect(self.save_settings)
        page.layout().addWidget(self.auto_refresh)
        self._label("Scansione usa Microsoft Defender. Storage Analyzer mostra spazio e RAM e offre rimozioni con conferma. "
                    "Le operazioni protette possono richiedere l’avvio come amministratore. "
                    "La disponibilità di Defender dipende dalla configurazione Windows.", page)
        self._button("diagnostics", "Esporta diagnostica…", self.export_diagnostics, page)
        self._button("data_folder", "Apri cartella dati", self.open_data_folder, page)
        self._button("help", "Come usare BC Sentinel", self.show_help, page)
        self._button("about", "Informazioni sul programma", self.show_about, page)
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(60000)
        self.refresh_timer.timeout.connect(self.refresh_if_idle)
        if self.auto_refresh.isChecked():
            self.refresh_timer.start()
        self.render_history()
        self.navigate("Dashboard")
        self.setStyleSheet(home_stylesheet() + f"""
            QMainWindow, QWidget {{ background: {COLORS['bg_app']}; color: {COLORS['text_primary']}; }}
            #Sidebar {{ background: {COLORS['bg_sidebar']}; }}
            QPushButton {{ padding: 10px; border: 1px solid {COLORS['border_strong']};
                border-radius: 8px; background: {COLORS['surface_1']}; text-align: left; }}
            QPushButton:hover {{ background: {COLORS['hover']}; }}
            QPushButton:checked {{ background: {COLORS['selected']}; border-color: {COLORS['accent']}; }}
            QPushButton:disabled {{ color: {COLORS['disabled_text']}; }}
            #PrimaryButton {{ background: {COLORS['accent_container']}; color: {COLORS['text_primary']}; }}
            QTextEdit {{ background: {COLORS['surface_lowest']}; border: 1px solid {COLORS['border_subtle']}; padding: 12px; }}
        """)
        if auto_status:
            QTimer.singleShot(0, self.refresh_if_idle)

    def _label(self, text, page):
        label = QLabel(text)
        label.setWordWrap(True)
        label.setTextFormat(Qt.TextFormat.PlainText)
        page.layout().addWidget(label)
        return label

    def _button(self, key, text, action, page, primary=False):
        button = QPushButton(text)
        button.setObjectName("PrimaryButton" if primary else "DetailsButton")
        button.setAccessibleName(text)
        button.setMinimumHeight(44)
        button.clicked.connect(lambda checked=False: action())
        page.layout().addWidget(button)
        self.command_buttons[key] = button
        return button

    def _page(self, name, description):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(PageHeader(name, description))
        self._add_page(name, page)
        return page

    def _add_page(self, name, page):
        scroll = _PageScroll(page)
        self.pages[name] = scroll
        self.stack.addWidget(scroll)

    def navigate(self, name):
        self.stack.setCurrentWidget(self.pages[name])
        for route, button in self.nav_buttons.items():
            button.setChecked(route == name)
        if name == "Storage Analyzer":
            self.storage_page.refresh_availability()
        if name == "Cronologia":
            self.render_history()
        self.pages[name].sync_width()

    def refresh_if_idle(self):
        if not self.engine.busy():
            self.engine.run("status")

    def refresh_status(self):
        if self.engine.busy():
            self.navigate("Scansione")
            QMessageBox.information(self, "Operazione in corso", "Il motore sta eseguendo un comando. "
                "Il risultato apparirà nella pagina Scansione al termine.")
            return
        self.engine.run("status")

    def request_scan(self, action, path=None):
        self.navigate("Scansione")
        if self.engine.busy():
            QMessageBox.information(self, "Operazione in corso", "Attendi il termine del comando in esecuzione.")
            return
        if action != "update" and QMessageBox.question(
            self, "Avvia scansione", "Defender applicherà le impostazioni di risposta del PC, che possono includere "
            "quarantena o rimozione delle minacce rilevate. Avviare la scansione?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        if self.engine.ready:
            self.engine.run(action, scan_path=path)
        else:
            self.pending_scan = (action, path)
            self.engine.run("status")

    def custom_scan(self):
        folder = QFileDialog.getExistingDirectory(self, "Cartella da scansionare")
        if folder:
            self.request_scan("custom", folder)

    def request_removal(self):
        self.navigate("Scansione")
        if self.engine.remove_button.isEnabled():
            self.engine.remove()
        else:
            self.engine.run("status")
            QMessageBox.information(self, "Rimozione delle minacce",
                "Lo stato viene aggiornato. La rimozione si abilita nella pagina Scansione quando Defender "
                "è attivo e riporta minacce attive.")

    def _engine_finished(self, code, exit_status):
        data = self.engine.last_result
        if data is not None:
            self.overview.setText(self.engine.report.toPlainText())
            self.protection.setText(self.engine.report.toPlainText() + "\nProtezione in tempo reale: " +
                                    ("attiva" if data.get("realtime_enabled") else "non attiva"))
            records = data.get("threat_history", [])
            self.threats.setPlainText("\n".join(
                str(item.get("name", "")) + (" · attiva" if item.get("active") else " · rilevata in passato")
                for item in records if isinstance(item, dict)
            ) or "Defender non riporta minacce nella cronologia disponibile.")
        else:
            self.overview.setText(self.engine.status.text())
            self.protection.setText(self.engine.status.text() + "\nProva l’avvio come amministratore o apri Sicurezza di Windows.")
            self.threats.setPlainText("Rilevamenti non aggiornati. " + self.engine.status.text())
        self._record(self.engine.action, "completata" if data is not None else self.engine.status.text())
        pending, self.pending_scan = self.pending_scan, None
        if pending is not None:
            if self.engine.ready:
                self.engine.run(pending[0], scan_path=pending[1])
            else:
                self.engine.status.setText("Scansione non avviata. " + self.engine.status.text() +
                    " Controlla Protezione o avvia BC Sentinel come amministratore.")

    def _engine_error(self, error):
        self.pending_scan = None
        self.overview.setText(self.engine.status.text())
        self.protection.setText(self.engine.status.text())
        self.threats.setPlainText("Rilevamenti non aggiornati. " + self.engine.status.text())
        self._record(self.engine.action, self.engine.status.text())

    def _load_events(self):
        try:
            value = json.loads((self.data_root / "history.json").read_text(encoding="utf-8"))
            if isinstance(value, list):
                self.events = [item for item in value[-200:] if isinstance(item, dict)]
        except (OSError, ValueError):
            pass

    def _record(self, action, result):
        self.events.append({"ora": datetime.now().isoformat(timespec="seconds"), "azione": action, "esito": result})
        self.events = self.events[-200:]
        try:
            write_json(self.data_root / "history.json", self.events)
        except OSError as error:
            self.statusBar().showMessage("Cronologia non salvata: " + str(error))
        self.render_history()

    def render_history(self):
        self.history.setPlainText("\n".join(
            f"{item.get('ora', '')}  ·  {item.get('azione', '')}  ·  {item.get('esito', '')}"
            for item in reversed(self.events)
        ) or "Nessuna operazione ancora registrata da questo desktop.")

    def _export(self, title, filename, payload):
        destination, _ = QFileDialog.getSaveFileName(self, title, filename, "JSON (*.json)")
        if not destination:
            return
        try:
            write_json(Path(destination), payload)
            QMessageBox.information(self, title, "File salvato.")
        except OSError as error:
            QMessageBox.warning(self, title, "Salvataggio non riuscito. " + str(error))

    def export_history(self):
        self._export("Esporta cronologia", "BC-Sentinel-cronologia.json", self.events)

    def export_diagnostics(self):
        self._export("Esporta diagnostica", "BC-Sentinel-diagnostica.json",
            {"programma": "BC Sentinel", "stato_defender": self.engine.last_result,
             "errore": self.engine.last_error, "storage_disponibile": self.storage_page.launch_button.isEnabled()})

    def _load_auto_refresh(self):
        try:
            value = json.loads((self.data_root / "settings.json").read_text(encoding="utf-8"))
            return isinstance(value, dict) and value.get("auto_refresh") is True
        except (OSError, ValueError):
            return False

    def save_settings(self, enabled):
        try:
            write_json(self.data_root / "settings.json", {"auto_refresh": enabled})
            self.refresh_timer.start() if enabled else self.refresh_timer.stop()
            self.statusBar().showMessage("Preferenze salvate.", 4000)
        except OSError as error:
            QMessageBox.warning(self, "Preferenze", str(error))

    def _open_url(self, url):
        if not QDesktopServices.openUrl(QUrl(url)):
            QMessageBox.warning(self, "Apertura non riuscita", "Windows non ha aperto la destinazione richiesta.")

    def open_windows_security(self):
        self._open_url("ms-settings:windowsdefender")

    def open_data_folder(self):
        try:
            self.data_root.mkdir(parents=True, exist_ok=True)
            self._open_url(QUrl.fromLocalFile(str(self.data_root)).toString())
        except OSError as error:
            QMessageBox.warning(self, "Cartella dati", str(error))

    def elevate(self):
        if not getattr(sys, "frozen", False):
            QMessageBox.information(self, "Permessi amministrativi", "Usa questo comando dalla versione .exe di BC Sentinel.")
            return
        if self.engine.busy() or self.storage_page.process is not None or (
            self.offline_dialog is not None and self.offline_dialog._thread is not None
        ):
            QMessageBox.information(self, "Operazione in corso", "Concludi le operazioni e chiudi Storage Analyzer prima di riavviare.")
            return
        old = os.environ.get("PYINSTALLER_RESET_ENVIRONMENT")
        os.environ["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        try:
            result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, None, None, 1)
            if result > 32:
                self.close()
            else:
                QMessageBox.warning(self, "Avvio amministrativo", "Avvio non completato o annullato.")
        finally:
            if old is None:
                os.environ.pop("PYINSTALLER_RESET_ENVIRONMENT", None)
            else:
                os.environ["PYINSTALLER_RESET_ENVIRONMENT"] = old

    def open_offline(self):
        from sentinel.offline_scan_dialog import OfflineScanDialog
        if self.offline_dialog is None:
            self.offline_dialog = OfflineScanDialog(self)
        self.offline_dialog.show()
        self.offline_dialog.raise_()

    def show_help(self):
        QMessageBox.information(self, "Come usare BC Sentinel",
            "1. Dashboard legge lo stato reale di Microsoft Defender.\n"
            "2. Scansione avvia i controlli antivirus e la rimozione delle minacce attive.\n"
            "3. Scansione offline esamina un altro volume Windows.\n"
            "4. Quarantena apre la gestione di Windows per gli elementi isolati.\n"
            "5. Storage Analyzer analizza spazio e RAM e offre rimozioni con conferma.\n"
            "6. Cronologia e diagnostica possono essere esportate dalle rispettive pagine.")

    def show_about(self):
        QMessageBox.information(self, "BC Sentinel", "BC Sentinel · desktop operativo Windows\n"
            "Storage Analyzer incluso. Le scansioni antivirus del PC utilizzano Microsoft Defender.\n"
            "La rilevazione dipende dal motore e dalle firme disponibili.")

    def closeEvent(self, event):
        if self.engine.busy():
            self.navigate("Scansione")
            QMessageBox.information(self, "Operazione in corso", "Attendi il termine del comando antivirus prima di chiudere.")
            event.ignore()
            return
        if self.offline_dialog is not None and self.offline_dialog._thread is not None:
            self.offline_dialog.show()
            event.ignore()
            return
        if self.storage_page.process is not None and self.storage_page.process.poll() is None:
            QMessageBox.information(self, "Storage Analyzer", "Chiudi Storage Analyzer prima di chiudere Sentinel.")
            event.ignore()
            return
        self.refresh_timer.stop()
        self.storage_page.poll_timer.stop()
        super().closeEvent(event)


def smoke_test():
    app = QApplication.instance() or QApplication([])
    window = OperationalWindow(auto_status=False)
    overflow = {}
    try:
        window.show()
        for width in (1440, 960, 760):
            window.resize(width, 820)
            app.processEvents()
            for name, button in window.nav_buttons.items():
                button.click()
                app.processEvents()
                window.pages[name].sync_width()
                app.processEvents()
                overflow[f"{width}/{name}"] = window.pages[name].horizontalScrollBar().maximum()
                assert window.stack.currentWidget() is window.pages[name]
        return {
            "passed": all(value == 0 for value in overflow.values()) and
                (window.storage_page.launch_button.isEnabled() or not getattr(sys, "frozen", False)),
            "page_count": window.stack.count(), "command_count": len(window.command_buttons),
            "horizontal_overflow": overflow, "operational_desktop": True,
            "storage_ready": window.storage_page.launch_button.isEnabled(),
        }
    finally:
        window.close()
