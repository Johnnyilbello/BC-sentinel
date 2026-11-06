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
    QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QStackedWidget, QTextEdit, QVBoxLayout, QWidget,
)

from sentinel.home_security_ui import _PageScroll
from sentinel.storage_analyzer_ui import StorageAnalyzerPage
from sentinel.ui_design_system import COLORS, make_icon
from sentinel.ui_pages import PageHeader
from sentinel.ui_styles import home_stylesheet
from sentinel.windows_defender_ui import WindowsDefenderDialog
from sentinel.bc_scan_ui import BCScanPage
from sentinel.bc_quarantine_ui import BCVaultPane
from sentinel.operational_overview import OperationalOverview


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
        self._closing_monitor = False
        self._unread_bc_notices = 0
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
        brand_row = QHBoxLayout()
        mark = QLabel()
        mark.setPixmap(make_icon("shield", "#4ceba2", 42).pixmap(42))
        brand_row.addWidget(mark)
        brand_copy = QVBoxLayout()
        brand_copy.setSpacing(1)
        brand = QLabel("BC Sentinel")
        brand.setObjectName("OverviewBrand")
        brand_copy.addWidget(brand)
        subtitle = QLabel("Sicurezza e archiviazione")
        subtitle.setObjectName("OverviewMuted")
        brand_copy.addWidget(subtitle)
        brand_row.addLayout(brand_copy, 1)
        navigation.addLayout(brand_row)
        navigation.addSpacing(20)
        self.stack = QStackedWidget()
        self.stack.setObjectName("PageStack")
        root.addWidget(sidebar)
        root.addWidget(self.stack, 1)
        self.setCentralWidget(shell)
        for name, icon in (
            ("Dashboard", "dashboard"), ("Motore BC", "scan"), ("Scansione", "scan"), ("Scansione offline", "folder"),
            ("Quarantena", "quarantine"), ("Cronologia", "history"),
            ("Protezione", "shield"), ("Storage Analyzer", "folder"), ("Impostazioni e aiuto", "settings"),
        ):
            label = {"Dashboard": "Panoramica", "Motore BC": "Scansione",
                     "Scansione": "Microsoft Defender", "Quarantena": "Minacce",
                     "Storage Analyzer": "Archivio", "Impostazioni e aiuto": "Impostazioni"}.get(name, name)
            button = QPushButton(label)
            button.setObjectName("NavItem")
            button.setIcon(make_icon(icon))
            button.setMinimumHeight(44)
            button.setCheckable(True)
            button.setAccessibleName(label)
            button.clicked.connect(lambda checked=False, route=name: self.navigate(route))
            navigation.addWidget(button)
            self.nav_buttons[name] = button
        navigation.addStretch()
        self.sidebar = sidebar

        self.bc_page = BCScanPage()
        self.bc_folder = None
        self.dashboard = OperationalOverview(self)
        self._add_page("Dashboard", self.dashboard)
        self._add_page("Motore BC", self.bc_page)
        self.bc_page.scan_started.connect(self._bc_started)
        self.bc_page.scan_completed.connect(self._bc_completed)
        self.bc_page.scan_failed.connect(self._bc_failed)
        self.bc_page.monitor_stopped.connect(self._close_after_monitor)

        page = self._page("Scansione", "Controlli operativi del motore Microsoft Defender")
        self.engine = WindowsDefenderDialog()
        self.engine.setParent(page)
        self.engine.setWindowFlags(Qt.WindowType.Widget)
        page.layout().addWidget(self.engine)
        self._button("custom_scan", "Scansiona una cartella…", self.custom_scan, page)
        self._button("dashboard_quick", "Scansione rapida con Defender", lambda: self.request_scan("quick"), page)
        self._button("dashboard_full", "Scansione completa con Defender", lambda: self.request_scan("full"), page)
        self.engine.process.finished.connect(self._engine_finished)
        self.engine.process.errorOccurred.connect(self._engine_error)
        self.engine.dispatch_failed.connect(self._engine_error)
        self.engine.setMinimumHeight(500)

        page = self._page("Scansione offline", "Esamina un’installazione Windows offline con SHA-256 e YARA")
        self._label("Scegli il volume Windows da esaminare e una cartella dei report su un altro volume. "
                    "La scansione legge i file e segnala rilevamenti, errori e limiti della copertura.", page)
        self._button("offline_open", "Apri scansione offline", self.open_offline, page, primary=True)

        page = self._page("Quarantena", "Segnalazioni del motore BC e rilevamenti di Microsoft Defender")
        self.bc_vault = BCVaultPane(self.data_root / "quarantine")
        page.layout().addWidget(self.bc_vault)
        self.bc_page.monitor_finding.connect(self.bc_vault.add_finding)
        self._label("Motore BC · avvisi della sessione", page)
        self.bc_notices = QPlainTextEdit()
        self.bc_notices.setReadOnly(True)
        self.bc_notices.setMaximumBlockCount(200)
        self.bc_notices.setPlaceholderText("Le corrispondenze e gli avvisi del monitor appariranno qui.")
        self.bc_notices.setMinimumHeight(112)
        page.layout().addWidget(self.bc_notices)
        self.bc_page.monitor_notice.connect(self._add_bc_notice)
        self._label("Microsoft Defender", page)
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
        self.overview = self.protection
        self._button("dashboard_refresh", "Aggiorna stato", self.refresh_status, page)
        self._button("protection_refresh", "Aggiorna stato protezione", self.refresh_status, page)
        self._button("signatures", "Aggiorna firme antivirus", lambda: self.request_scan("update"), page)
        self._button("security_settings", "Apri Sicurezza di Windows", self.open_windows_security, page)
        self._button("administrator", "Apri BC Sentinel come amministratore", self.elevate, page)

        self.storage_page = StorageAnalyzerPage()
        self._add_page("Storage Analyzer", self.storage_page)
        self.command_buttons["dashboard_storage"] = self.nav_buttons["Storage Analyzer"]

        page = self._page("Impostazioni e aiuto", "Preferenze locali, diagnostica e istruzioni")
        self.auto_refresh = QCheckBox("Aggiorna lo stato antivirus ogni 60 secondi")
        self.auto_refresh.setChecked(self._load_auto_refresh())
        self.auto_refresh.toggled.connect(self.save_settings)
        page.layout().addWidget(self.auto_refresh)
        self._label("Motore BC analizza su richiesta con un catalogo hash limitato; Scansione usa Microsoft Defender. Storage Analyzer mostra spazio e RAM e offre rimozioni con conferma. "
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
            #Sidebar {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #151b1e,stop:0.68 #101618,stop:1 #0b2b22); border-right: 1px solid #222d32; }}
            QPushButton {{ padding: 10px; border: 1px solid {COLORS['border_strong']};
                border-radius: 8px; background: {COLORS['surface_1']}; text-align: left; }}
            QPushButton:hover {{ background: {COLORS['hover']}; }}
            QPushButton:checked {{ background: {COLORS['selected']}; border-color: {COLORS['accent']}; }}
            QPushButton:disabled {{ color: {COLORS['disabled_text']}; }}
            #PrimaryButton {{ background: {COLORS['accent_container']}; color: {COLORS['text_primary']}; }}
            #Sidebar QLabel, #OperationalOverview QLabel {{ background: transparent; }}
            #Sidebar #NavItem {{ background: transparent; border: 1px solid transparent; }}
            #Sidebar #NavItem:hover {{ background: #1b2829; }}
            #Sidebar #NavItem:checked {{ background: #193b2e; border-color: #387e61; }}
            #OverviewBrand {{ font-size: 20px; font-weight: 700; }}
            #OverviewKicker {{ color: #c6d0da; font-size: 12px; letter-spacing: 1px; }}
            #OverviewTitle {{ font-size: 30px; font-weight: 700; }}
            #OverviewStatus {{ font-size: 24px; font-weight: 700; }}
            #OverviewMuted {{ color: #b8c5ce; }}
            #OverviewMetric {{ font-size: 17px; font-weight: 650; }}
            #DashboardPanel {{ background: #171e22; border: 1px solid #343f46; border-radius: 12px; }}
            #OverviewHero {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #123229,stop:0.52 #131b1d,stop:1 #111719); border-radius: 12px; }}
            #OverviewEvent {{ border-top: 1px solid #344047; padding-top: 8px; padding-bottom: 4px; }}
            #OverviewPrimary {{ color: #052016; font-size: 16px; font-weight: 700; text-align: center;
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #58eda8,stop:1 #23ca72); border: 1px solid #54e6a0; }}
            #OverviewPrimary:hover {{ background: #75f1b6; }}
            #OverviewSecondary {{ text-align: center; background: #141a1e; border: 1px solid #83919a; }}
            #OverviewSecondary:hover {{ background: #222d33; }}
            QPushButton:focus {{ border-color: #72f0b6; }}
            #OverviewDisk {{ background: #323e43; border: none; border-radius: 6px; }}
            #OverviewDisk::chunk {{ background: #45e294; border-radius: 6px; }}
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
        if name == "Quarantena":
            self.bc_vault.refresh()
            self._unread_bc_notices = 0
            self.nav_buttons["Quarantena"].setText("Minacce")
            self.nav_buttons["Quarantena"].setAccessibleName("Minacce")
        if name == "Dashboard":
            self.dashboard.update_disk()
        self.pages[name].sync_width()

    def choose_bc_from_dashboard(self):
        self.bc_page.choose_folder()

    def start_bc_from_dashboard(self):
        if self.bc_page.worker is not None:
            self.navigate("Motore BC")
        elif self.bc_folder is not None:
            self.bc_page.start_scan(self.bc_folder)
        else:
            self.choose_bc_from_dashboard()

    def _bc_started(self, folder):
        self.bc_folder = folder
        self.dashboard.status.setText("Scansione in corso")
        self.dashboard.detail.setText(folder)
        self.dashboard.shield.set_state("working", animate=True)

    def _bc_completed(self, result):
        for finding in result["findings"][-100:]:
            self._add_bc_notice(f"{finding['name']} — {finding['path']}")
            self.bc_vault.add_finding(finding)
        self._record("Scansione BC",
                     f"{result['files']} file analizzati · {result['skipped']} saltati",
                     rilevazioni=len(result["findings"]),
                     parziale=bool(result["cancelled"] or result["skipped"]))
        self.dashboard.shield.set_state(self.dashboard.shield.state, animate=True)

    def _add_bc_notice(self, notice):
        self.bc_notices.appendPlainText(notice)
        if self.stack.currentWidget() is self.pages["Quarantena"]:
            return
        self._unread_bc_notices += 1
        count = min(self._unread_bc_notices, 99)
        suffix = "+" if self._unread_bc_notices > 99 else ""
        button = self.nav_buttons["Quarantena"]
        button.setText(f"Minacce  ·  {count}{suffix}")
        button.setAccessibleName(f"Minacce, {count}{suffix} nuovi avvisi")

    def _bc_failed(self, message):
        self._record("Scansione BC", message, parziale=True, errore=True)
        self.dashboard.render_events(self.events)

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
            self.protection.setText(self.engine.report.toPlainText() + "\nProtezione in tempo reale: " +
                                    ("attiva" if data.get("realtime_enabled") else "non attiva"))
            records = data.get("threat_history", [])
            self.threats.setPlainText("\n".join(
                str(item.get("name", "")) + (" · attiva" if item.get("active") else " · rilevata in passato")
                for item in records if isinstance(item, dict)
            ) or "Defender non riporta minacce nella cronologia disponibile.")
        else:
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

    def _record(self, action, result, **metadata):
        self.events.append({"ora": datetime.now().isoformat(timespec="seconds"), "azione": action, "esito": result,
                            **metadata})
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
        if self.bc_page.worker is None or self.bc_page.last_result is not None:
            self.dashboard.render_events(self.events)

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
        if self.bc_page.worker is not None or self.bc_page.monitor is not None or self.engine.busy() or self.storage_page.process is not None or (
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
            "Storage Analyzer incluso. Il motore BC controlla gli hash su richiesta; "
            "Defender è un motore distinto. BC non offre protezione in tempo reale.")

    def closeEvent(self, event):
        if self.bc_page.worker is not None:
            self.bc_page.cancel()
            self.navigate("Motore BC")
            QMessageBox.information(self, "Scansione in corso", "Annullamento richiesto. Attendi il termine prima di chiudere.")
            event.ignore()
            return
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
        if self.bc_page.monitor is not None:
            self._closing_monitor = True
            self.bc_page.stop_monitor()
            event.ignore()
            return
        self.refresh_timer.stop()
        self.storage_page.poll_timer.stop()
        super().closeEvent(event)

    def _close_after_monitor(self):
        if self._closing_monitor:
            self._closing_monitor = False
            QTimer.singleShot(0, self.close)


def _smoke_folder_monitor(page):
    from hashlib import sha256
    from tempfile import TemporaryDirectory
    from PySide6.QtCore import QEventLoop
    from sentinel.bc_rename_activity import MIN_RENAMES

    def wait_for(predicate):
        loop = QEventLoop()
        poll = QTimer()
        poll.setInterval(40)
        poll.timeout.connect(lambda: loop.quit() if predicate() else None)
        timeout = QTimer()
        timeout.setSingleShot(True)
        timeout.timeout.connect(loop.quit)
        poll.start()
        timeout.start(8000)
        loop.exec()
        return predicate()

    with TemporaryDirectory(prefix="bc-monitor-smoke-") as folder:
        base = Path(folder)
        root = base / "watched"
        root.mkdir()
        fixture = b"BC Sentinel harmless smoke fixture"
        documents = [root / f"document-{index}.txt" for index in range(MIN_RENAMES)]
        for document in documents:
            document.write_bytes(b"Harmless document")
        catalog = base / "catalog.json"
        write_json(catalog, {
            "schema": "bc-sentinel-offline-intel-v1", "approved": True,
            "sha256": [{"value": sha256(fixture).hexdigest(), "name": "Campione di prova BC", "source": "smoke"}],
        })
        page.catalog = catalog
        page.start_monitor(str(root))
        detected = False
        alerted = False
        try:
            if wait_for(lambda: page.monitor is None or page.monitor_status.text().startswith("Monitoraggio attivo")) and page.monitor is not None:
                (root / "fixture.txt").write_bytes(fixture)
                detected = wait_for(lambda: "Campione di prova BC" in page.monitor_report.toPlainText())
                for document in documents:
                    document.rename(document.with_suffix(".bc-test"))
                alerted = wait_for(lambda: "Attività da verificare" in page.monitor_report.toPlainText())
        finally:
            page.stop_monitor()
            stopped = wait_for(lambda: page.monitor is None)
        healthy = stopped and page.monitor_error is None
        return detected and healthy, alerted and healthy


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
        monitor_passed, activity_passed = _smoke_folder_monitor(window.bc_page)
        activity_passed = activity_passed and "Attività da verificare" in window.bc_notices.toPlainText()
        activity_passed = activity_passed and window._unread_bc_notices >= 1
        window.navigate("Quarantena")
        activity_passed = activity_passed and window._unread_bc_notices == 0
        vault_passed = _smoke_quarantine()
        return {
            "passed": monitor_passed and activity_passed and vault_passed and all(value == 0 for value in overflow.values()) and
                (window.storage_page.launch_button.isEnabled() or not getattr(sys, "frozen", False)),
            "page_count": window.stack.count(), "command_count": len(window.command_buttons),
            "horizontal_overflow": overflow, "operational_desktop": True,
            "storage_ready": window.storage_page.launch_button.isEnabled(),
            "bc_folder_monitor": monitor_passed,
            "bc_rename_activity": activity_passed,
            "bc_quarantine": vault_passed,
        }
    finally:
        window.close()


def _smoke_quarantine():
    if os.name != "nt":
        return True
    from hashlib import sha256
    from tempfile import TemporaryDirectory
    from sentinel.bc_quarantine import BCQuarantine

    with TemporaryDirectory(prefix="bc-vault-smoke-") as folder:
        root = Path(folder).resolve()
        profile = root / "profile"
        target = profile / "Documents" / "innocuous.txt"
        target.parent.mkdir(parents=True)
        data = b"BC Sentinel harmless quarantine smoke"
        target.write_bytes(data)
        previous = os.environ.get("LOCALAPPDATA")
        os.environ["LOCALAPPDATA"] = str(root / "disposable-appdata")
        try:
            vault = BCQuarantine(root / "vault", user_profile=profile)
            entry = vault.isolate(target, sha256(data).hexdigest())
            if target.exists() or vault.entries() != [entry]:
                return False
            vault.restore(entry.token)
            return target.read_bytes() == data and not vault.entries()
        finally:
            if previous is None:
                os.environ.pop("LOCALAPPDATA", None)
            else:
                os.environ["LOCALAPPDATA"] = previous
