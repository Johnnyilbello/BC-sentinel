"""Sentinel-themed entry page. Storage actions run only in the companion."""
from __future__ import annotations

from PySide6.QtCore import QSize, QTimer
from PySide6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget, QMessageBox

from sentinel import storage_analyzer
from sentinel import home_security_ui
from sentinel.ui_design_system import COLORS, make_icon
from sentinel.ui_pages import PageHeader
from sentinel.ui_styles import home_stylesheet

PAGE_NAME = "Storage Analyzer"


class StorageWindowMixin:
    """Append the utility without changing existing page indexes or security state."""

    def _install_storage_analyzer(self) -> None:
        self.storage_page = StorageAnalyzerPage()
        self.storage_scroll = home_security_ui._PageScroll(self.storage_page)
        self.stack.addWidget(self.storage_scroll)
        self.secondary_scrolls.append(self.storage_scroll)
        button = QPushButton(PAGE_NAME)
        button.setObjectName("NavItem")
        button.setIcon(make_icon("folder", COLORS["text_secondary"], 20))
        button.setIconSize(QSize(20, 20))
        button.setCheckable(True)
        button.setAccessibleName(PAGE_NAME)
        button.setToolTip("Spazio su disco e RAM")
        button.clicked.connect(lambda checked=False: self._navigate(PAGE_NAME))
        layout = self.sidebar.layout()
        layout.insertWidget(max(layout.indexOf(b) for b in self.nav_buttons.values()) + 1, button)
        self.nav_buttons[PAGE_NAME] = button

    def closeEvent(self, event) -> None:
        page = getattr(self, "storage_page", None)
        if page is not None and page.process is not None and page.process.poll() is None:
            QMessageBox.information(self, "Storage Analyzer aperto",
                "Chiudi la finestra di Storage Analyzer prima di chiudere BC Sentinel.")
            event.ignore()
            return
        super().closeEvent(event)

    def _navigate(self, page: str) -> None:
        if page != PAGE_NAME or not hasattr(self, "storage_scroll"):
            super()._navigate(page)
            return
        self._current_page = page
        self.stack.setCurrentWidget(self.storage_scroll)
        for name, button in self.nav_buttons.items():
            button.setChecked(name == page)
            button.setObjectName("NavActive" if name == page else "NavItem")
            button.style().unpolish(button)
            button.style().polish(button)
        self.storage_page.refresh_availability()
        if self._layout_mode != "mobile":
            self.topbar_title.setText("BC SENTINEL · Storage Analyzer")
        QTimer.singleShot(0, self._sync_all_scroll_widths)


class StorageAnalyzerPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("StorageAnalyzerPage")
        self.setMinimumWidth(0)
        self.process = None
        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(1000)
        self.poll_timer.timeout.connect(self._poll)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(20)
        layout.addWidget(PageHeader(
            "BC Storage Analyzer",
            "Scopri cosa occupa spazio sui dischi e quali processi usano più RAM.",
        ))
        self.summary = QLabel(
            "Confronta lo spazio libero e occupato delle unità locali, le cartelle e i file più grandi. "
            "Consulta le estensioni, le stime delle applicazioni installate e la RAM per processo. "
            "Puoi aprire i percorsi in Esplora file ed esportare le classifiche in CSV."
        )
        self.summary.setObjectName("CardSummary")
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        self.launch_button = QPushButton("Apri BC Storage Analyzer")
        self.launch_button.setObjectName("PrimaryButton")
        self.launch_button.setAccessibleName("Apri BC Storage Analyzer")
        self.launch_button.setMinimumHeight(44)
        self.launch_button.clicked.connect(self.launch)
        layout.addWidget(self.launch_button)
        self.status = QLabel()
        self.status.setObjectName("SectionHint")
        self.status.setWordWrap(True)
        self.status.setAccessibleName("Stato di Storage Analyzer")
        layout.addWidget(self.status)
        actions = QLabel(
            "La scansione legge i metadati dei file. Per rimuovere una voce, selezionala nello strumento "
            "e scegli Sposta nel Cestino oppure Elimina definitivamente. Ogni rimozione richiede conferma. "
            "Nella scheda Applicazioni puoi avviare la procedura di disinstallazione di Windows."
        )
        actions.setObjectName("CardSummary")
        actions.setWordWrap(True)
        layout.addWidget(actions)
        self.refresh_availability()
        self.setStyleSheet(home_stylesheet())

    def refresh_availability(self) -> None:
        if self.process is not None:
            return
        ready, message = storage_analyzer.availability()
        self.launch_button.setEnabled(ready)
        self.status.setText(message)

    def launch(self) -> None:
        if self.process is not None:
            return
        self.refresh_availability()
        if not self.launch_button.isEnabled():
            return
        self.launch_button.setEnabled(False)
        self.status.setText("Apertura di BC Storage Analyzer…")
        try:
            self.process = storage_analyzer.launch()
        except OSError as error:
            self.refresh_availability()
            self.status.setText("Impossibile aprire Storage Analyzer. " + str(error))
            return
        self.status.setText("BC Storage Analyzer è aperto nella finestra dedicata. Chiudilo per poterlo riaprire.")
        self.poll_timer.start()

    def _poll(self) -> None:
        exit_code = self.process.poll() if self.process is not None else 0
        if exit_code is None:
            return
        self.poll_timer.stop()
        self.process = None
        self.refresh_availability()
        if exit_code != 0:
            self.status.setText("Storage Analyzer si è chiuso con un errore. Puoi riprovare ad aprirlo.")
