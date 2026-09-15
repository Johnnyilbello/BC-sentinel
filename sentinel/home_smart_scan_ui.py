from __future__ import annotations

"""B6-3 Smart Scan presentation surface.

This component keeps the accepted truthful scan contract while presenting the
primary task, live status and advanced evidence with clearer hierarchy.
"""

import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QBoxLayout,
    QFrame,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from sentinel import home_smart_scan as smart
from sentinel.ui_design_system import COLORS, apply_icon
from sentinel.ui_motion_components import AnimatedNumberLabel, StatusOrb
from sentinel.ui_pages import PageHeader


class SmartScanPage(QWidget):
    """B6-3 scan page with one explicit Smart Scan action and truthful results."""

    def __init__(
        self,
        *,
        start_callback=None,
        cancel_callback=None,
        provider_available: bool = False,
        unavailable_reason: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("ScanPage")
        self.setMinimumWidth(0)
        self._start_callback = start_callback
        self._cancel_callback = cancel_callback
        self._provider_available = bool(provider_available)
        self._unavailable_reason = str(unavailable_reason or "")
        self._last_result: smart.SmartScanResult | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(24)
        root.addWidget(
            PageHeader(
                "Scansione",
                "Controlla rapidamente le aree più rilevanti, segui il progresso reale e verifica ogni risultato prima di agire.",
            )
        )

        self.panel = QFrame()
        self.panel.setObjectName("TaskPanel")
        self.panel.setMinimumWidth(0)
        self.panel.setMinimumHeight(300)
        self.panel.setMaximumHeight(560)
        self.panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        lay = QVBoxLayout(self.panel)
        lay.setContentsMargins(32, 30, 32, 28)
        lay.setSpacing(14)

        # Thinking-orb inspired native status feedback. It is intentionally
        # restrained and obeys BC_SENTINEL_REDUCED_MOTION.
        self.mark = StatusOrb(58)
        self.mark.setToolTip("Stato della Smart Scan")

        self.task_title = QLabel("Smart Scan pronta" if self._provider_available else "Smart Scan non disponibile")
        self.task_title.setObjectName("TaskTitle")
        self.task_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.task_title.setWordWrap(True)

        initial_copy = (
            "Avvia una scansione rapida controllata. Nessuna quarantena o riparazione viene eseguita automaticamente."
            if self._provider_available
            else "Il motore di scansione verificato non è disponibile in questa build. Nessun risultato viene simulato."
        )
        self.task_subtitle = QLabel(initial_copy)
        self.task_subtitle.setObjectName("TaskSubtitle")
        self.task_subtitle.setWordWrap(True)
        self.task_subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.task_subtitle.setMaximumWidth(720)

        # Number-flow inspired progress readout. The progress bar remains the
        # canonical visual channel; this value adds fast glanceability.
        self.progress_value = AnimatedNumberLabel(0, suffix="%")
        self.progress_value.setObjectName("ScanProgressValue")
        self.progress_value.setAccessibleName("Percentuale completamento Smart Scan")
        self.progress_value.setVisible(False)

        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("ScanProgressBar")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setAccessibleName("Progresso Smart Scan")
        self.progress_bar.setVisible(False)

        self.progress_label = QLabel("Progresso 0%")
        self.progress_label.setObjectName("ScanProgressText")
        self.progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.progress_label.setWordWrap(True)
        self.progress_label.setVisible(False)

        self.coverage_label = QLabel("")
        self.coverage_label.setObjectName("ScanSummary")
        self.coverage_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.coverage_label.setWordWrap(True)
        self.coverage_label.setVisible(False)

        self.actions = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.actions.setSpacing(12)
        self.actions.addStretch(1)

        self.quick_scan = QPushButton("Scansione rapida")
        self.quick_scan.setAccessibleName("Avvia Smart Scan")
        self.quick_scan.setToolTip("Analizza le aree prioritarie con il piano Smart Scan verificato")
        self.quick_scan.clicked.connect(self._request_start)
        self.actions.addWidget(self.quick_scan)

        self.full_scan = QPushButton("Scansione completa")
        self.full_scan.setObjectName("SecondaryDisabled")
        self.full_scan.setEnabled(False)
        self.full_scan.setAccessibleName("Scansione completa non disponibile")
        self.full_scan.setToolTip("La scansione completa sarà mostrata quando avrà un contratto di esecuzione verificato.")
        apply_icon(self.full_scan, "search", COLORS["disabled_text"], 18)
        self.actions.addWidget(self.full_scan)

        self.cancel_scan = QPushButton("Annulla")
        self.cancel_scan.setObjectName("SecondaryAction")
        self.cancel_scan.setVisible(False)
        self.cancel_scan.setAccessibleName("Annulla Smart Scan")
        self.cancel_scan.setToolTip("Interrompe in sicurezza la scansione in corso")
        self.cancel_scan.clicked.connect(self._request_cancel)
        self.actions.addWidget(self.cancel_scan)
        self.actions.addStretch(1)

        self.advanced_button = QPushButton("Dettagli avanzati")
        self.advanced_button.setObjectName("AdvancedToggle")
        self.advanced_button.setCheckable(True)
        self.advanced_button.setVisible(False)
        self.advanced_button.setAccessibleName("Mostra dettagli avanzati della Smart Scan")
        self.advanced_button.setToolTip("Mostra prove tecniche, provider, copertura e payload completo")
        self.advanced_button.toggled.connect(self._toggle_advanced)

        self.advanced_text = QPlainTextEdit()
        self.advanced_text.setObjectName("AdvancedEvidence")
        self.advanced_text.setReadOnly(True)
        self.advanced_text.setVisible(False)
        self.advanced_text.setMinimumHeight(150)
        self.advanced_text.setMaximumHeight(240)
        self.advanced_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        lay.addWidget(self.mark, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addWidget(self.task_title)
        lay.addWidget(self.task_subtitle, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addWidget(self.progress_value, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addWidget(self.progress_bar)
        lay.addWidget(self.progress_label)
        lay.addWidget(self.coverage_label)
        lay.addLayout(self.actions)
        lay.addWidget(self.advanced_button, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addWidget(self.advanced_text)
        root.addWidget(self.panel)
        root.addStretch(1)

        self.configure_provider(self._provider_available, self._unavailable_reason)

    def _request_start(self) -> None:
        if self._provider_available and callable(self._start_callback):
            self._start_callback()

    def _request_cancel(self) -> None:
        if callable(self._cancel_callback):
            self._cancel_callback()

    def _toggle_advanced(self, checked: bool) -> None:
        self.advanced_text.setVisible(bool(checked))
        self.advanced_button.setText("Nascondi dettagli avanzati" if checked else "Dettagli avanzati")
        self.panel.setMaximumHeight(800 if checked else 560)

    def configure_provider(self, available: bool, reason: str = "") -> None:
        self._provider_available = bool(available)
        self._unavailable_reason = str(reason or "")
        self.quick_scan.setEnabled(self._provider_available)
        self.quick_scan.setObjectName("PrimaryAction" if self._provider_available else "PrimaryDisabled")
        apply_icon(
            self.quick_scan,
            "bolt",
            "#062016" if self._provider_available else COLORS["disabled_text"],
            18,
        )
        if not self._provider_available and self._last_result is None:
            self.mark.set_state("unavailable")
            self.task_title.setText("Smart Scan non disponibile")
            self.task_subtitle.setText(
                "Il motore di scansione verificato non è disponibile in questa build. Nessun risultato viene simulato."
            )
            self.quick_scan.setToolTip(self._unavailable_reason or "Provider Smart Scan non disponibile")
        elif self._last_result is None:
            self.mark.set_state("idle")
            self.task_title.setText("Smart Scan pronta")
            self.task_subtitle.setText(
                "Avvia una scansione rapida controllata. Nessuna quarantena o riparazione viene eseguita automaticamente."
            )
            self.quick_scan.setToolTip("Analizza le aree prioritarie con il piano Smart Scan verificato")
        self.quick_scan.style().unpolish(self.quick_scan)
        self.quick_scan.style().polish(self.quick_scan)

    def set_running(self) -> None:
        self._last_result = None
        self.quick_scan.setEnabled(False)
        self.full_scan.setEnabled(False)
        self.cancel_scan.setVisible(True)
        self.cancel_scan.setEnabled(True)
        self.mark.set_state("working")
        self.progress_value.set_target(0, immediate=True)
        self.progress_value.setVisible(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_label.setVisible(True)
        self.progress_label.setText("Avvio dei controlli verificati…")
        self.coverage_label.setVisible(False)
        self.advanced_button.setChecked(False)
        self.advanced_button.setVisible(False)
        self.advanced_text.setVisible(False)
        self.advanced_text.clear()
        self.task_title.setText("Smart Scan in corso")
        self.task_subtitle.setText("BC Sentinel sta eseguendo solo i controlli previsti dal piano di scansione verificato.")

    def set_progress(self, progress: smart.SmartScanProgress) -> None:
        progress.validate()
        self.mark.set_state("working")
        self.progress_value.setVisible(True)
        self.progress_value.set_target(progress.percent)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(int(progress.percent))
        self.progress_label.setVisible(True)
        suffix = f" · {progress.message}" if progress.message else ""
        self.progress_label.setText(
            f"{progress.completed_checks}/{progress.total_checks} controlli completati{suffix}"
        )

    def set_result(self, result: smart.SmartScanResult) -> None:
        result.validate()
        self._last_result = result
        self.cancel_scan.setVisible(False)
        self.cancel_scan.setEnabled(False)
        self.progress_value.setVisible(False)
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        self.mark.set_state(self._orb_state_for_result(result.state))
        self.task_title.setText(self._title_for_state(result.state))
        self.task_subtitle.setText(f"{result.summary} {result.recommendation}")
        self.coverage_label.setText(
            f"Copertura: {result.coverage} · Controlli {result.completed_checks}/{result.total_checks} · "
            f"Rilevamenti {len(result.findings)} · Severità massima {result.highest_severity}"
        )
        self.coverage_label.setVisible(True)
        self.advanced_text.setPlainText(json.dumps(result.to_dict(), indent=2, ensure_ascii=False, sort_keys=True))
        self.advanced_button.setVisible(True)
        self.advanced_button.setChecked(False)
        self.configure_provider(self._provider_available, self._unavailable_reason)
        # configure_provider must not erase the terminal visual state.
        self.mark.set_state(self._orb_state_for_result(result.state))

    @staticmethod
    def _orb_state_for_result(state: str) -> str:
        return {
            smart.STATE_COMPLETED_CLEAN: "clean",
            smart.STATE_COMPLETED_FINDINGS: "findings",
            smart.STATE_INCOMPLETE: "attention",
            smart.STATE_FAILED: "attention",
            smart.STATE_CANCELLED: "cancelled",
        }.get(state, "attention")

    @staticmethod
    def _title_for_state(state: str) -> str:
        return {
            smart.STATE_COMPLETED_CLEAN: "Smart Scan completata",
            smart.STATE_COMPLETED_FINDINGS: "Elementi da verificare",
            smart.STATE_INCOMPLETE: "Scansione incompleta",
            smart.STATE_FAILED: "Scansione non completata",
            smart.STATE_CANCELLED: "Scansione annullata",
        }.get(state, "Smart Scan")

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        self.actions.setDirection(
            QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight
        )
        if self.panel.layout():
            pad = 20 if compact else 32
            self.panel.layout().setContentsMargins(pad, 24 if compact else 30, pad, 24 if compact else 28)
        if compact:
            self.panel.setMaximumHeight(860 if self.advanced_text.isVisible() else 660)
        else:
            self.panel.setMaximumHeight(800 if self.advanced_text.isVisible() else 560)
