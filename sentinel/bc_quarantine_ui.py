"""Confirmation and recovery controls for the BC vault."""
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget

from sentinel.bc_quarantine import BCQuarantine


class BCVaultPane(QWidget):
    def __init__(self, root):
        super().__init__()
        self.vault = BCQuarantine(root)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        title = QLabel("Quarantena BC")
        title.setObjectName("OverviewMetric")
        layout.addWidget(title)
        scope = QLabel("Isola i file fino a 16 MiB corrispondenti a un hash del catalogo in Desktop, Documenti o Download. Il deposito cifrato permette il ripristino.")
        scope.setWordWrap(True)
        layout.addWidget(scope)
        self.candidates = self._selector("File rilevati dal catalogo BC")
        layout.addWidget(self.candidates)
        self.isolate_button = QPushButton("Isola il file selezionato…")
        self.isolate_button.setMinimumHeight(44)
        self.isolate_button.clicked.connect(self._isolate)
        layout.addWidget(self.isolate_button)
        self.stored = self._selector("File nel deposito cifrato")
        layout.addWidget(self.stored)
        self.restore_button = QPushButton("Ripristina nel percorso originale…")
        self.restore_button.setMinimumHeight(44)
        self.restore_button.clicked.connect(self._restore)
        layout.addWidget(self.restore_button)
        self.status = QLabel("Seleziona una corrispondenza o un elemento in quarantena.")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.isolate_button.setEnabled(False)
        self.restore_button.setEnabled(False)

    @staticmethod
    def _selector(label):
        selector = QComboBox()
        selector.setAccessibleName(label)
        selector.setPlaceholderText(label)
        selector.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        selector.setMinimumContentsLength(20)
        selector.setMinimumHeight(34)
        return selector

    def add_finding(self, item):
        path = item.get("isolate_path")
        if not path:
            return
        identity = (path, item["sha256"])
        if self.candidates.findData(identity) >= 0:
            return
        if self.candidates.count() >= 100:
            self.candidates.removeItem(0)
        self.candidates.addItem(Path(path).name, identity)
        self.candidates.setItemData(self.candidates.count() - 1, path, Qt.ItemDataRole.ToolTipRole)
        if self.candidates.currentIndex() < 0:
            self.candidates.setCurrentIndex(0)
        self.isolate_button.setEnabled(True)

    def refresh(self):
        selection = self.stored.currentData()
        self.stored.clear()
        try:
            for entry in self.vault.entries():
                self.stored.addItem(Path(entry.original).name, entry)
                self.stored.setItemData(self.stored.count() - 1, entry.original, Qt.ItemDataRole.ToolTipRole)
            if self.vault.incomplete_listing:
                self.status.setText("Deposito visualizzato in parte. Alcuni record non sono leggibili o superano il limite della lista.")
        except (OSError, ValueError) as exc:
            self.status.setText(str(exc))
        if self.stored.count():
            index = self.stored.findData(selection)
            self.stored.setCurrentIndex(max(index, 0))
        self.restore_button.setEnabled(self.stored.count() > 0)

    def _isolate(self):
        identity = self.candidates.currentData()
        if not identity:
            return
        path, digest = identity
        if QMessageBox.question(self, "Conferma isolamento BC",
                f"Isolare questo file?\n\n{path}\n\nSHA-256: {digest}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        try:
            self.vault.isolate(path, digest)
        except (OSError, ValueError) as exc:
            self.status.setText(str(exc))
        else:
            self.candidates.removeItem(self.candidates.currentIndex())
            self.isolate_button.setEnabled(self.candidates.count() > 0)
            self.status.setText("File isolato nel deposito cifrato.")
        self.refresh()

    def _restore(self):
        entry = self.stored.currentData()
        if not entry:
            return
        if QMessageBox.question(self, "Conferma ripristino BC",
                f"Ripristinare il file? L'operazione riporta il contenuto nella cartella originale.\n\n{entry.original}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        try:
            self.vault.restore(entry.token)
        except (OSError, ValueError) as exc:
            self.status.setText(str(exc))
        else:
            self.status.setText("File ripristinato nel percorso originale.")
        self.refresh()
