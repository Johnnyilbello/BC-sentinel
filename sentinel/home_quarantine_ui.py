from __future__ import annotations

"""B6-5.7 Home UI for explicit, reversible quarantine."""

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget

from sentinel import home_quarantine as home_quarantine
from sentinel.ui_live_polish import PolishedB65SmartScanPage, _polish_wrapped_labels


class B657SmartScanPage(PolishedB65SmartScanPage):
    """Polished Smart Scan page with explicit per-finding quarantine controls."""

    def __init__(
        self,
        *args,
        quarantine_controller: home_quarantine.HomeQuarantineController,
        quarantine_changed_callback: Callable[[], None] | None = None,
        **kwargs,
    ) -> None:
        self.quarantine_controller = quarantine_controller
        self.quarantine_changed_callback = quarantine_changed_callback
        super().__init__(*args, **kwargs)

    def set_result(self, result) -> None:
        super().set_result(result)
        for card in self.threat_card_widgets:
            self._install_quarantine_action(card)
            _polish_wrapped_labels(card)
        self._apply_live_text_safety()

    def _install_quarantine_action(self, card: QWidget) -> None:
        layout = card.layout()
        if layout is None or not hasattr(card, "model") or not hasattr(card, "resolution_model"):
            return

        panel = QFrame(card)
        panel.setObjectName("QuarantineActionPanel")
        panel.setMinimumWidth(0)
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(14, 12, 14, 12)
        panel_layout.setSpacing(8)

        title = QLabel("Azione reversibile")
        title.setObjectName("ThreatRecommendationTitle")
        panel_layout.addWidget(title)

        status = QLabel()
        status.setObjectName("SafetyNote")
        status.setWordWrap(True)
        status.setMinimumWidth(0)
        panel_layout.addWidget(status)

        button = QPushButton()
        button.setObjectName("SecondaryAction")
        button.setMinimumHeight(40)
        button.setAccessibleName(f"Quarantena reversibile: {card.title_label.text()}")
        panel_layout.addWidget(button, 0, Qt.AlignmentFlag.AlignLeft)

        if self.quarantine_controller.has_active_quarantine(card.model.finding_id):
            self._set_restore_state(card, button, status)
        else:
            availability = self.quarantine_controller.assess(card.model, card.resolution_model)
            if availability.ready:
                status.setText(
                    "Disponibile solo su conferma esplicita. BC Sentinel ricontrollerà SHA-256 e percorso prima dell'azione."
                )
                button.setText("Metti in quarantena")
                button.setToolTip("Richiede conferma e una nuova verifica del file.")
                button.setProperty("quarantineMode", "quarantine")
                button.setEnabled(True)
            else:
                status.setText(availability.reason)
                button.setText("Quarantena non disponibile")
                button.setProperty("quarantineMode", "blocked")
                button.setEnabled(False)
                button.setToolTip(availability.reason)

        button.clicked.connect(
            lambda checked=False, c=card, b=button, s=status: self._handle_action(c, b, s)
        )
        layout.addWidget(panel)

    def _handle_action(self, card: QWidget, button: QPushButton, status: QLabel) -> None:
        mode = str(button.property("quarantineMode") or "")
        if mode == "restore":
            self._confirm_restore(card, button, status)
        elif mode == "quarantine":
            self._confirm_quarantine(card, button, status)

    def _confirm_quarantine(self, card: QWidget, button: QPushButton, status: QLabel) -> None:
        try:
            session = self.quarantine_controller.prepare_confirmation(card.model, card.resolution_model)
        except Exception as exc:
            self._blocked_dialog("Quarantena bloccata", str(exc))
            status.setText("BC Sentinel ha bloccato l'azione perché i requisiti non sono più validi.")
            button.setEnabled(False)
            return

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Conferma quarantena")
        box.setText("Mettere questo file in quarantena?")
        box.setInformativeText(
            f"File: {session.plan.target.locator}\n\n"
            "L'azione è reversibile e non elimina il file. BC Sentinel ricontrollerà nuovamente SHA-256 e contesto prima di eseguire."
        )
        confirm_button = box.addButton("Metti in quarantena", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Annulla", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is not confirm_button:
            status.setText("Quarantena annullata. Nessuna modifica eseguita.")
            return

        button.setEnabled(False)
        status.setText("Verifica finale e quarantena in corso...")
        try:
            result = self.quarantine_controller.confirm_and_execute(session)
        except Exception as exc:
            self._blocked_dialog("Quarantena non eseguita", str(exc))
            status.setText("Operazione bloccata in sicurezza. Il file non è stato autorizzato alla quarantena.")
            button.setEnabled(True)
            return

        status.setText(f"In quarantena e verificato · {result.result_id}")
        self._set_restore_state(card, button, status)
        self._notify_quarantine_changed()

    def _set_restore_state(self, card: QWidget, button: QPushButton, status: QLabel) -> None:
        button.setText("Ripristina file")
        button.setToolTip("Richiede conferma e verifica del file prima del ripristino.")
        button.setProperty("quarantineMode", "restore")
        button.setEnabled(True)
        button.setAccessibleName(f"Ripristina dalla quarantena: {card.title_label.text()}")
        if not status.text().strip():
            status.setText("File in quarantena. Il ripristino richiede un'altra conferma esplicita.")

    def _confirm_restore(self, card: QWidget, button: QPushButton, status: QLabel) -> None:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Conferma ripristino")
        box.setText("Ripristinare il file nella posizione originale?")
        box.setInformativeText(
            "BC Sentinel verificherà il rollback e l'SHA-256 del file ripristinato. Nessuna eliminazione verrà eseguita."
        )
        restore_button = box.addButton("Ripristina", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Annulla", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is not restore_button:
            return

        button.setEnabled(False)
        status.setText("Ripristino e verifica in corso...")
        try:
            rollback = self.quarantine_controller.rollback(card.model.finding_id)
        except Exception as exc:
            self._blocked_dialog("Ripristino non eseguito", str(exc))
            status.setText("Ripristino bloccato. I dati di quarantena restano conservati.")
            button.setEnabled(True)
            return

        status.setText(f"Ripristinato e verificato · {rollback.rollback_id}")
        button.setText("Ripristinato")
        button.setProperty("quarantineMode", "restored")
        button.setEnabled(False)
        self._notify_quarantine_changed()

    def _blocked_dialog(self, title: str, technical_reason: str) -> None:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(title)
        box.setText("BC Sentinel ha interrotto l'operazione in modalità fail-closed.")
        box.setDetailedText(technical_reason)
        box.exec()

    def _notify_quarantine_changed(self) -> None:
        if self.quarantine_changed_callback is not None:
            self.quarantine_changed_callback()
