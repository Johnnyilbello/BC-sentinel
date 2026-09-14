from __future__ import annotations

"""B6-5.0 passive Guided Resolution UI layered on B6-4 Threat Cards."""

import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QPlainTextEdit, QPushButton, QSizePolicy, QVBoxLayout, QWidget

from sentinel import home_guided_resolution as guided
from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat
from sentinel.home_smart_scan_ui import SmartScanPage
from sentinel.home_threat_cards_ui import B64SmartScanPage, ThreatCardWidget


class GuidedResolutionPanel(QFrame):
    """Report-only guidance. It deliberately exposes no mutation control."""

    def __init__(self, model: guided.GuidedResolutionModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        model.validate()
        self.model = model
        self.setObjectName("GuidedResolutionPanel")
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(8)

        self.eyebrow = QLabel("Risoluzione guidata")
        self.eyebrow.setObjectName("CardSummary")
        root.addWidget(self.eyebrow)

        self.headline_label = QLabel(model.headline)
        self.headline_label.setObjectName("CardTitle")
        self.headline_label.setWordWrap(True)
        self.headline_label.setMinimumWidth(0)
        root.addWidget(self.headline_label)

        self.state_label = QLabel(
            f"Stato: {model.review_state} · Autorità: {model.authority_state} · Azione: solo verifica"
        )
        self.state_label.setObjectName("CardSummary")
        self.state_label.setWordWrap(True)
        self.state_label.setMinimumWidth(0)
        root.addWidget(self.state_label)

        self.next_step_label = QLabel(model.next_step)
        self.next_step_label.setObjectName("CardDescription")
        self.next_step_label.setWordWrap(True)
        self.next_step_label.setMinimumWidth(0)
        root.addWidget(self.next_step_label)

        self.safety_label = QLabel(
            "Nessuna quarantena, riparazione, eliminazione o terminazione viene eseguita in questo checkpoint."
        )
        self.safety_label.setObjectName("CardSummary")
        self.safety_label.setWordWrap(True)
        root.addWidget(self.safety_label)

        self.details_button = QPushButton("Dettagli risoluzione")
        self.details_button.setObjectName("InlineButton")
        self.details_button.setCheckable(True)
        self.details_button.setAccessibleName(f"Dettagli risoluzione: {model.title}")
        self.details_button.toggled.connect(self._toggle_details)
        root.addWidget(self.details_button, 0, Qt.AlignmentFlag.AlignLeft)

        self.details_text = QPlainTextEdit()
        self.details_text.setObjectName("AdvancedText")
        self.details_text.setReadOnly(True)
        self.details_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.details_text.setMinimumHeight(150)
        self.details_text.setMaximumHeight(260)
        self.details_text.setPlainText(
            json.dumps(model.advanced_details, indent=2, ensure_ascii=False, sort_keys=True)
        )
        self.details_text.setVisible(False)
        root.addWidget(self.details_text)

    def _toggle_details(self, checked: bool) -> None:
        self.details_text.setVisible(bool(checked))


class B65ThreatCardWidget(ThreatCardWidget):
    """Accepted B6-4 card plus passive B6-5.0 guidance."""

    def __init__(self, model: threat.ThreatCardModel, parent: QWidget | None = None) -> None:
        super().__init__(model, parent)
        self.resolution_model = guided.build_guided_resolution(model)
        self.resolution_panel = GuidedResolutionPanel(self.resolution_model, self)
        layout = self.layout()
        if layout is not None:
            layout.addWidget(self.resolution_panel)


class B65SmartScanPage(B64SmartScanPage):
    """B6-4 findings with non-executing B6-5.0 Guided Resolution guidance."""

    def set_result(self, result: smart.SmartScanResult) -> None:
        # Call the accepted B6-3 page directly so B6-4 does not first create
        # transient B64 widgets that we would immediately replace.
        SmartScanPage.set_result(self, result)
        self._clear_threat_cards()
        cards = threat.build_threat_cards(result)
        if not cards:
            return

        count = len(cards)
        self.threat_title.setText(f"Rilevamenti da verificare · {count}")
        self.threat_hint.setText(
            "Ogni rilevamento mantiene severità, confidenza e prove originali. "
            "Risoluzione guidata indica il prossimo passo ma non modifica ancora il sistema."
        )
        for card_model in cards:
            widget = B65ThreatCardWidget(card_model, self.threat_cards_host)
            self.threat_cards_layout.addWidget(widget)
            self.threat_card_widgets.append(widget)
        self.threat_section.setVisible(True)
