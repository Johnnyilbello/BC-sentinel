from __future__ import annotations

"""B6-5.0 passive Guided Resolution UI layered on B6-4 Threat Cards."""

import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QBoxLayout,
    QFrame,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from sentinel import home_guided_resolution as guided
from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat
from sentinel.home_smart_scan_ui import SmartScanPage
from sentinel.home_threat_cards_ui import B64SmartScanPage, ThreatCardWidget


def _review_label(model: guided.GuidedResolutionModel) -> str:
    if model.review_state == guided.EVIDENCE_INCOMPLETE:
        return "Evidenza da completare"
    return "Revisione richiesta"


def _plain_next_step(model: guided.GuidedResolutionModel) -> str:
    if model.review_state == guided.EVIDENCE_INCOMPLETE:
        return "Apri i Dettagli avanzati e completa la verifica delle prove prima di qualsiasi intervento."
    return "Apri i Dettagli avanzati e verifica prove e contesto del rilevamento prima di intervenire."


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
        root.setSpacing(9)

        self.eyebrow = QLabel("Risoluzione guidata")
        self.eyebrow.setObjectName("GuidanceEyebrow")
        root.addWidget(self.eyebrow)

        self.headline_label = QLabel(model.headline)
        self.headline_label.setObjectName("GuidanceHeadline")
        self.headline_label.setWordWrap(True)
        self.headline_label.setMinimumWidth(0)
        root.addWidget(self.headline_label)

        self.status_layout = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.status_layout.setSpacing(8)
        self.review_badge = QLabel(_review_label(model))
        self.review_badge.setObjectName("GuidanceStatus")
        self.review_badge.setToolTip(f"Stato tecnico: {model.review_state}")
        self.authority_badge = QLabel("Solo verifica")
        self.authority_badge.setObjectName("GuidanceStatus")
        self.authority_badge.setToolTip(f"Autorità tecnica: {model.authority_state}")
        self.status_layout.addWidget(self.review_badge)
        self.status_layout.addWidget(self.authority_badge)
        self.status_layout.addStretch(1)
        root.addLayout(self.status_layout)

        # Preserve the accepted predecessor API for deterministic tests and
        # assistive/diagnostic inspection, but keep raw internal enums out of the
        # primary visual hierarchy. The full payload remains in advanced details.
        self.state_label = QLabel(
            f"Stato: {model.review_state} · Autorità: {model.authority_state} · Azione: solo verifica"
        )
        self.state_label.setObjectName("TechnicalStateCompatibility")
        self.state_label.setVisible(False)

        self.next_step_heading = QLabel("Prossimo passo")
        self.next_step_heading.setObjectName("GuidanceStepLabel")
        root.addWidget(self.next_step_heading)

        self.next_step_label = QLabel(_plain_next_step(model))
        self.next_step_label.setObjectName("GuidanceStepText")
        self.next_step_label.setWordWrap(True)
        self.next_step_label.setMinimumWidth(0)
        root.addWidget(self.next_step_label)

        self.safety_label = QLabel("Nessuna azione sul sistema viene eseguita automaticamente.")
        self.safety_label.setObjectName("SafetyNote")
        self.safety_label.setWordWrap(True)
        root.addWidget(self.safety_label)

        self.details_button = QPushButton("Dettagli risoluzione")
        self.details_button.setObjectName("AdvancedToggle")
        self.details_button.setCheckable(True)
        self.details_button.setAccessibleName(f"Dettagli risoluzione: {model.title}")
        self.details_button.toggled.connect(self._toggle_details)
        root.addWidget(self.details_button, 0, Qt.AlignmentFlag.AlignLeft)

        self.details_text = QPlainTextEdit()
        self.details_text.setObjectName("AdvancedText")
        self.details_text.setReadOnly(True)
        self.details_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.details_text.setMinimumHeight(160)
        self.details_text.setMaximumHeight(280)
        self.details_text.setPlainText(
            json.dumps(model.advanced_details, indent=2, ensure_ascii=False, sort_keys=True)
        )
        self.details_text.setVisible(False)
        root.addWidget(self.details_text)

    def _toggle_details(self, checked: bool) -> None:
        self.details_text.setVisible(bool(checked))
        self.details_button.setText("Nascondi dettagli risoluzione" if checked else "Dettagli risoluzione")

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        self.status_layout.setDirection(
            QBoxLayout.Direction.TopToBottom if mobile else QBoxLayout.Direction.LeftToRight
        )
        pad = 13 if mobile else 14 if compact else 16
        if self.layout() is not None:
            self.layout().setContentsMargins(pad, 13, pad, 13)


class B65ThreatCardWidget(ThreatCardWidget):
    """Accepted B6-4 card plus passive B6-5.0 guidance."""

    def __init__(self, model: threat.ThreatCardModel, parent: QWidget | None = None) -> None:
        super().__init__(model, parent)
        self.resolution_model = guided.build_guided_resolution(model)
        self.resolution_panel = GuidedResolutionPanel(self.resolution_model, self)
        layout = self.layout()
        if layout is not None:
            layout.addWidget(self.resolution_panel)

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        super().set_compact(compact, mobile)
        self.resolution_panel.set_compact(compact, mobile)


class B65SmartScanPage(B64SmartScanPage):
    """B6-4 findings with non-executing B6-5.0 Guided Resolution guidance."""

    def set_result(self, result: smart.SmartScanResult) -> None:
        SmartScanPage.set_result(self, result)
        self._clear_threat_cards()
        cards = threat.build_threat_cards(result)
        if not cards:
            return

        count = len(cards)
        self.threat_title.setText(f"Rilevamenti da verificare · {count}")
        self.threat_hint.setText(
            "Verifica ogni rilevamento prima di agire. La Risoluzione guidata indica il prossimo passo senza modificare il sistema."
        )
        for card_model in cards:
            widget = B65ThreatCardWidget(card_model, self.threat_cards_host)
            self.threat_cards_layout.addWidget(widget)
            self.threat_card_widgets.append(widget)
        self.threat_section.setVisible(True)
