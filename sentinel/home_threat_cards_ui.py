from __future__ import annotations

"""B6-4 threat-card UI layered onto the accepted B6-3 Smart Scan page."""

import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QBoxLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat
from sentinel.home_smart_scan_ui import SmartScanPage


class ThreatCardWidget(QFrame):
    """Review-only threat card with clear hierarchy and progressive disclosure."""

    def __init__(self, model: threat.ThreatCardModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        model.validate()
        self.model = model
        self.setObjectName("ThreatCard")
        self.setProperty("severity", model.severity)
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 20)
        root.setSpacing(14)

        header = QHBoxLayout()
        header.setSpacing(12)
        self.title_label = QLabel(model.title)
        self.title_label.setObjectName("CardTitle")
        self.title_label.setWordWrap(True)
        self.title_label.setMinimumWidth(0)
        header.addWidget(self.title_label, 1)

        self.severity_badge = QLabel(model.severity_label)
        self.severity_badge.setObjectName("ThreatSeverityBadge")
        self.severity_badge.setProperty("severity", model.severity)
        self.severity_badge.setToolTip(f"Severità canonica: {model.severity}")
        self.severity_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.addWidget(self.severity_badge, 0, Qt.AlignmentFlag.AlignTop)
        root.addLayout(header)

        self.reason_heading = QLabel("Perché è stato segnalato")
        self.reason_heading.setObjectName("ThreatFieldLabel")
        root.addWidget(self.reason_heading)

        self.reason_label = QLabel(model.reason)
        self.reason_label.setObjectName("ThreatBodyText")
        self.reason_label.setWordWrap(True)
        self.reason_label.setMinimumWidth(0)
        root.addWidget(self.reason_label)

        self.meta_layout = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.meta_layout.setSpacing(10)
        self.meta_blocks: list[QFrame] = []
        for label, value in (
            ("Categoria", model.category),
            ("Confidenza", model.confidence_label),
            ("Fonte", model.source_check_id),
        ):
            block = self._build_meta_block(label, value)
            self.meta_layout.addWidget(block, 1)
            self.meta_blocks.append(block)
        root.addLayout(self.meta_layout)

        self.location_heading = QLabel("Posizione")
        self.location_heading.setObjectName("ThreatFieldLabel")
        root.addWidget(self.location_heading)

        self.location_label = QLabel(model.location)
        self.location_label.setObjectName("ThreatLocation")
        self.location_label.setWordWrap(True)
        self.location_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.location_label.setMinimumWidth(0)
        root.addWidget(self.location_label)

        self.recommendation_panel = QFrame()
        self.recommendation_panel.setObjectName("ThreatRecommendationPanel")
        recommendation_layout = QVBoxLayout(self.recommendation_panel)
        recommendation_layout.setContentsMargins(14, 12, 14, 12)
        recommendation_layout.setSpacing(5)

        self.recommendation_heading = QLabel("Cosa fare adesso")
        self.recommendation_heading.setObjectName("ThreatRecommendationTitle")
        recommendation_layout.addWidget(self.recommendation_heading)

        self.recommendation_label = QLabel(model.recommendation)
        self.recommendation_label.setObjectName("ThreatRecommendationText")
        self.recommendation_label.setWordWrap(True)
        self.recommendation_label.setMinimumWidth(0)
        recommendation_layout.addWidget(self.recommendation_label)
        root.addWidget(self.recommendation_panel)

        self.advanced_button = QPushButton("Dettagli avanzati")
        self.advanced_button.setObjectName("AdvancedToggle")
        self.advanced_button.setCheckable(True)
        self.advanced_button.setAccessibleName(f"Dettagli avanzati: {model.title}")
        self.advanced_button.toggled.connect(self._toggle_advanced)
        root.addWidget(self.advanced_button, 0, Qt.AlignmentFlag.AlignLeft)

        self.advanced_text = QPlainTextEdit()
        self.advanced_text.setObjectName("AdvancedText")
        self.advanced_text.setReadOnly(True)
        self.advanced_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.advanced_text.setMinimumHeight(160)
        self.advanced_text.setMaximumHeight(280)
        self.advanced_text.setPlainText(
            json.dumps(model.advanced_details, indent=2, ensure_ascii=False, sort_keys=True)
        )
        self.advanced_text.setVisible(False)
        root.addWidget(self.advanced_text)

    @staticmethod
    def _build_meta_block(label: str, value: str) -> QFrame:
        block = QFrame()
        block.setObjectName("ThreatMetaBlock")
        block.setMinimumWidth(0)
        layout = QVBoxLayout(block)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(3)

        key = QLabel(label)
        key.setObjectName("ThreatMetaLabel")
        value_label = QLabel(value)
        value_label.setObjectName("ThreatMetaValue")
        value_label.setWordWrap(True)
        value_label.setMinimumWidth(0)

        layout.addWidget(key)
        layout.addWidget(value_label)
        return block

    def _toggle_advanced(self, checked: bool) -> None:
        self.advanced_text.setVisible(bool(checked))
        self.advanced_button.setText("Nascondi dettagli avanzati" if checked else "Dettagli avanzati")

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        self.meta_layout.setDirection(
            QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight
        )
        pad = 16 if mobile else 18 if compact else 22
        if self.layout() is not None:
            self.layout().setContentsMargins(pad, 18 if compact else 20, pad, 18 if compact else 20)


class B64SmartScanPage(SmartScanPage):
    """B6-3 Smart Scan surface plus review-only B6-4 finding cards."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.setObjectName("ScanPage")
        self.threat_card_widgets: list[ThreatCardWidget] = []

        self.threat_section = QFrame()
        self.threat_section.setObjectName("ThreatSection")
        self.threat_section.setMinimumWidth(0)
        self.threat_section.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        section_layout = QVBoxLayout(self.threat_section)
        section_layout.setContentsMargins(0, 0, 0, 0)
        section_layout.setSpacing(12)

        self.threat_title = QLabel("Rilevamenti")
        self.threat_title.setObjectName("PanelTitle")
        section_layout.addWidget(self.threat_title)

        self.threat_hint = QLabel(
            "Controlla ogni rilevamento prima di agire. Le prove tecniche restano disponibili nei Dettagli avanzati."
        )
        self.threat_hint.setObjectName("PanelDescription")
        self.threat_hint.setWordWrap(True)
        self.threat_hint.setMaximumWidth(840)
        section_layout.addWidget(self.threat_hint)

        self.threat_cards_host = QWidget()
        self.threat_cards_host.setObjectName("ThreatCardsHost")
        self.threat_cards_host.setMinimumWidth(0)
        self.threat_cards_layout = QVBoxLayout(self.threat_cards_host)
        self.threat_cards_layout.setContentsMargins(0, 0, 0, 0)
        self.threat_cards_layout.setSpacing(14)
        section_layout.addWidget(self.threat_cards_host)

        self.threat_section.setVisible(False)
        root = self.layout()
        if root is not None:
            insert_at = max(0, root.count() - 1)
            root.insertWidget(insert_at, self.threat_section)

    def _clear_threat_cards(self) -> None:
        for widget in self.threat_card_widgets:
            self.threat_cards_layout.removeWidget(widget)
            widget.deleteLater()
        self.threat_card_widgets.clear()
        self.threat_section.setVisible(False)

    def set_running(self) -> None:
        self._clear_threat_cards()
        super().set_running()

    def set_result(self, result: smart.SmartScanResult) -> None:
        super().set_result(result)
        self._clear_threat_cards()
        cards = threat.build_threat_cards(result)
        if not cards:
            return

        count = len(cards)
        self.threat_title.setText(f"Rilevamenti da verificare · {count}")
        self.threat_hint.setText(
            "Ogni scheda mantiene severità, confidenza e prove originali. Verifica il contesto prima di qualsiasi intervento."
        )
        for card_model in cards:
            widget = ThreatCardWidget(card_model, self.threat_cards_host)
            self.threat_cards_layout.addWidget(widget)
            self.threat_card_widgets.append(widget)
        self.threat_section.setVisible(True)

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        super().set_compact(compact, mobile)
        for widget in self.threat_card_widgets:
            widget.setMinimumWidth(0)
            setter = getattr(widget, "set_compact", None)
            if callable(setter):
                setter(compact, mobile)
