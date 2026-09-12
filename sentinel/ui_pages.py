from __future__ import annotations

"""Dashboard-derived secondary surfaces for BC Sentinel.

The accepted Dashboard is the visual source of truth. These widgets extend its
surface hierarchy, typography, spacing and interaction language without
inventing security data or enabling actions that the runtime has not verified.
"""

from collections.abc import Callable
from typing import Mapping

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QBoxLayout,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sentinel import home_security_model as model
from sentinel.ui_design_system import COLORS, ReadOnlyToggle, apply_icon


def _status_role(status: str) -> str:
    if status in {model.STATUS_ACTIVE, model.STATUS_READY}:
        return "positive"
    if status in {model.STATUS_ATTENTION, model.STATUS_OFF}:
        return "attention"
    return "neutral"


def _runtime_copy(card: model.HomeProtectionCard) -> str:
    if card.status == model.STATUS_ACTIVE and card.runtime_verified:
        return "Runtime verificato"
    if card.status == model.STATUS_OFF and card.runtime_verified:
        return "Runtime verificato · disattivato"
    if card.runtime_verified:
        return "Stato runtime verificato"
    return "Runtime non verificato"


class PageHeader(QWidget):
    """Shared title/subtitle origin for every secondary page."""

    def __init__(self, title: str, subtitle: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("PageHeader")
        self.setMinimumWidth(0)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        heading = QLabel(title)
        heading.setObjectName("PageTitle")
        heading.setWordWrap(True)
        body = QLabel(subtitle)
        body.setObjectName("PageSubtitle")
        body.setWordWrap(True)
        body.setMaximumWidth(840)

        layout.addWidget(heading)
        layout.addWidget(body)


class SectionHeader(QWidget):
    """Compact reusable section hierarchy used by Protection and Settings."""

    def __init__(self, title: str, description: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SectionHeader")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        heading = QLabel(title)
        heading.setObjectName("PanelTitle")
        heading.setWordWrap(True)
        layout.addWidget(heading)

        if description:
            body = QLabel(description)
            body.setObjectName("PanelDescription")
            body.setWordWrap(True)
            layout.addWidget(body)


class EmptyState(QFrame):
    """Single reusable empty-state pattern for scan, quarantine and history."""

    def __init__(self, title: str, text: str, icon: str = "info", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("EmptyState")
        self.setMinimumWidth(0)
        self.setMinimumHeight(168)
        self.setMaximumHeight(220)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(9)

        icon_label = QLabel()
        icon_label.setObjectName("EmptyIcon")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        apply_icon(icon_label, icon, COLORS["text_muted"], 28)

        heading = QLabel(title)
        heading.setObjectName("EmptyTitle")
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        heading.setWordWrap(True)

        body = QLabel(text)
        body.setObjectName("EmptyBody")
        body.setWordWrap(True)
        body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        body.setMaximumWidth(680)

        layout.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(heading)
        layout.addWidget(body, 0, Qt.AlignmentFlag.AlignHCenter)


class ScanPage(QWidget):
    """Scan surface without inventing an active scan before B6-3."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ScanPage")
        self.setMinimumWidth(0)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(24)
        root.addWidget(
            PageHeader(
                "Scansione",
                "Avvia e monitora le scansioni di BC Sentinel. Le azioni restano visivamente disabilitate finché il runtime Home non espone l’autorità prevista.",
            )
        )

        panel = QFrame()
        panel.setObjectName("TaskPanel")
        panel.setMinimumWidth(0)
        panel.setMinimumHeight(250)
        panel.setMaximumHeight(340)
        panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        lay = QVBoxLayout(panel)
        lay.setContentsMargins(32, 28, 32, 26)
        lay.setSpacing(14)

        mark = QLabel()
        mark.setObjectName("TaskIcon")
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        apply_icon(mark, "radar", COLORS["info"], 40)

        title = QLabel("Nessuna scansione in corso")
        title.setObjectName("TaskTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setWordWrap(True)

        subtitle = QLabel(
            "Quando Smart Scan sarà collegata, questa area mostrerà esclusivamente progresso e risultati reali."
        )
        subtitle.setObjectName("TaskSubtitle")
        subtitle.setWordWrap(True)
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setMaximumWidth(660)

        self.actions = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.actions.setSpacing(12)
        self.actions.addStretch(1)

        self.quick_scan = QPushButton("Scansione rapida")
        self.quick_scan.setObjectName("PrimaryDisabled")
        self.quick_scan.setEnabled(False)
        self.quick_scan.setAccessibleName("Scansione rapida non disponibile in B6-2")
        apply_icon(self.quick_scan, "bolt", COLORS["disabled_text"], 18)

        self.full_scan = QPushButton("Scansione completa")
        self.full_scan.setObjectName("SecondaryDisabled")
        self.full_scan.setEnabled(False)
        self.full_scan.setAccessibleName("Scansione completa non disponibile in B6-2")
        apply_icon(self.full_scan, "search", COLORS["disabled_text"], 18)

        self.actions.addWidget(self.quick_scan)
        self.actions.addWidget(self.full_scan)
        self.actions.addStretch(1)

        note = QLabel("Azioni operative previste in B6-3")
        note.setObjectName("Microcopy")
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lay.addWidget(mark, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addWidget(title)
        lay.addWidget(subtitle, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addLayout(self.actions)
        lay.addWidget(note)
        root.addWidget(panel)
        root.addStretch(1)

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        self.actions.setDirection(
            QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight
        )
        panel = self.findChild(QFrame, "TaskPanel")
        if panel and panel.layout():
            pad = 20 if compact else 32
            panel.layout().setContentsMargins(pad, 24 if compact else 28, pad, 24 if compact else 26)
            panel.setMaximumHeight(410 if compact else 340)


class _DataTable(QTableWidget):
    def __init__(self, headers: list[str], parent: QWidget | None = None) -> None:
        super().__init__(0, len(headers), parent)
        self.setObjectName("DataTable")
        self.setHorizontalHeaderLabels(headers)
        self.setShowGrid(False)
        self.setAlternatingRowColors(False)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.setMinimumHeight(260)
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Expanding)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)


class QuarantinePage(QWidget):
    def __init__(
        self,
        rows_provider: Callable[[], list[Mapping]] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("QuarantinePage")
        self.setMinimumWidth(0)
        self.rows_provider = rows_provider

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(20)

        self.header_row = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.header_row.setSpacing(16)
        self.header_row.addWidget(
            PageHeader(
                "Gestione Quarantena",
                "Analizza e gestisci le minacce isolate dal sistema di protezione senza perdere la distinzione tra dati reali e stato non collegato.",
            ),
            1,
        )
        self.refresh_button = QPushButton("Aggiorna lista")
        self.refresh_button.setObjectName("SecondaryAction")
        self.refresh_button.setAccessibleName("Aggiorna la lista reale della quarantena")
        apply_icon(self.refresh_button, "refresh", COLORS["text_secondary"], 16)
        self.refresh_button.clicked.connect(self.refresh)
        self.header_row.addWidget(self.refresh_button, 0, Qt.AlignmentFlag.AlignTop)
        root.addLayout(self.header_row)

        panel = QFrame()
        panel.setObjectName("TablePanel")
        panel.setMinimumWidth(0)
        panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        tabs = QHBoxLayout()
        tabs.setContentsMargins(18, 14, 18, 12)
        tabs.setSpacing(8)
        active = QPushButton("In quarantena")
        active.setObjectName("FilterActive")
        active.setCheckable(True)
        active.setChecked(True)

        restored = QPushButton("Ripristinati")
        restored.setObjectName("FilterButton")
        restored.setEnabled(False)
        restored.setToolTip("Disponibile quando il provider di quarantena espone lo storico dei ripristini.")

        self.filter_button = QPushButton("Filtri")
        self.filter_button.setObjectName("FilterButton")
        apply_icon(self.filter_button, "filter", COLORS["text_secondary"], 16)
        self.filter_button.setEnabled(False)
        self.filter_button.setToolTip("I filtri diventano disponibili con dati reali.")

        tabs.addWidget(active)
        tabs.addWidget(restored)
        tabs.addStretch(1)
        tabs.addWidget(self.filter_button)
        lay.addLayout(tabs)

        self.table = _DataTable(["File", "Percorso", "Data", "Rischio", "Motivo", "Stato", "Azioni"])
        lay.addWidget(self.table)

        self.empty = EmptyState(
            "Nessun dato di quarantena disponibile",
            "I file appariranno qui solo quando un provider di quarantena reale verrà collegato.",
            "quarantine",
        )
        lay.addWidget(self.empty)

        root.addWidget(panel)
        root.addStretch(1)
        self.refresh()

    def refresh(self) -> None:
        rows = list(self.rows_provider() if self.rows_provider else [])
        self.table.setRowCount(0)
        for payload in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [payload.get(k, "") for k in ("file", "path", "date", "risk", "reason", "status", "action")]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(str(value)))
        has_rows = bool(rows)
        self.table.setVisible(has_rows)
        self.empty.setVisible(not has_rows)
        self.filter_button.setEnabled(has_rows)

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        self.header_row.setDirection(
            QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight
        )
        self.refresh_button.setSizePolicy(
            QSizePolicy.Policy.Expanding if compact else QSizePolicy.Policy.Fixed,
            QSizePolicy.Policy.Fixed,
        )


class HistoryPage(QWidget):
    def __init__(
        self,
        rows_provider: Callable[[], list[Mapping]] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("HistoryPage")
        self.setMinimumWidth(0)
        self.rows_provider = rows_provider

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(20)

        self.header_row = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.header_row.setSpacing(18)
        self.header_row.addWidget(
            PageHeader(
                "Cronologia Eventi",
                "Registro delle attività di sistema e degli interventi di sicurezza collegati alla Home.",
            ),
            1,
        )
        self.filters = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.filters.setSpacing(6)
        self.filter_buttons: list[QPushButton] = []
        for index, label in enumerate(("Tutti", "Critical", "High", "Suspicious")):
            button = QPushButton(label)
            button.setObjectName("FilterActive" if index == 0 else "FilterButton")
            button.setCheckable(index == 0)
            button.setChecked(index == 0)
            button.setEnabled(index == 0)
            self.filters.addWidget(button)
            self.filter_buttons.append(button)
        self.header_row.addLayout(self.filters)
        root.addLayout(self.header_row)

        panel = QFrame()
        panel.setObjectName("CommandPanel")
        panel.setMinimumWidth(0)
        panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        self.table = _DataTable(["Data", "File / Processo", "Score", "Livello", "Stato"])
        self.table.setObjectName("HistoryTable")
        lay.addWidget(self.table)

        self.empty = EmptyState(
            "Nessun evento collegato",
            "La cronologia mostrerà esclusivamente eventi reali quando il relativo provider verrà collegato.",
            "history",
        )
        lay.addWidget(self.empty)

        root.addWidget(panel)
        root.addStretch(1)
        self.refresh()

    def refresh(self) -> None:
        rows = list(self.rows_provider() if self.rows_provider else [])
        self.table.setRowCount(0)
        for payload in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            for column, key in enumerate(("date", "process", "score", "level", "status")):
                self.table.setItem(row, column, QTableWidgetItem(str(payload.get(key, ""))))
        has_rows = bool(rows)
        self.table.setVisible(has_rows)
        self.empty.setVisible(not has_rows)
        for button in self.filter_buttons[1:]:
            button.setEnabled(has_rows)

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        self.header_row.setDirection(
            QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight
        )
        self.filters.setDirection(
            QBoxLayout.Direction.TopToBottom if mobile else QBoxLayout.Direction.LeftToRight
        )


class StatusBadge(QLabel):
    def __init__(self, text: str, role: str = "neutral", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("StatusBadge")
        self.setProperty("statusRole", role)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)


class ProtectionRow(QFrame):
    """Protection hierarchy: identity -> engine state -> runtime state -> control/action."""

    def __init__(
        self,
        card: model.HomeProtectionCard,
        on_action: Callable[[], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("ProtectionRow")
        self.setMinimumWidth(0)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 15, 16, 15)
        lay.setSpacing(13)

        icon = QLabel()
        icon.setObjectName("SettingIcon")
        icon.setFixedSize(40, 40)
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        kind = {
            model.LAYER_MALWARE: "radar",
            model.LAYER_BEHAVIOR: "behavior",
            model.LAYER_WEB: "web",
            model.LAYER_RECOVERY: "recovery",
        }.get(card.card_id, "info")
        apply_icon(icon, kind, COLORS["accent"], 20)
        lay.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)

        copy = QVBoxLayout()
        copy.setSpacing(4)

        title = QLabel(card.label)
        title.setObjectName("SettingTitle")
        title.setWordWrap(True)
        desc = QLabel(card.description)
        desc.setObjectName("SettingDescription")
        desc.setWordWrap(True)

        state_line = QHBoxLayout()
        state_line.setSpacing(8)
        badge = StatusBadge(card.status_label, _status_role(card.status))
        runtime = QLabel(_runtime_copy(card))
        runtime.setObjectName("SettingMeta")
        runtime.setWordWrap(True)
        state_line.addWidget(badge)
        state_line.addWidget(runtime)
        state_line.addStretch(1)

        copy.addWidget(title)
        copy.addWidget(desc)
        copy.addLayout(state_line)
        lay.addLayout(copy, 1)

        controls = QVBoxLayout()
        controls.setSpacing(8)
        controls.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        toggle = ReadOnlyToggle(card.status == model.STATUS_ACTIVE and card.runtime_verified)
        toggle.setToolTip("Indicatore in sola lettura: non modifica lo stato runtime.")
        controls.addWidget(toggle, 0, Qt.AlignmentFlag.AlignRight)

        if card.action_enabled and on_action is not None:
            action = QPushButton("Apri")
            action.setObjectName("PrimaryCompact")
            action.setAccessibleName(card.action_label)
            apply_icon(action, "recovery", "#062016", 15)
            action.clicked.connect(on_action)
            controls.addWidget(action, 0, Qt.AlignmentFlag.AlignRight)

        lay.addLayout(controls)


class SettingsRow(QFrame):
    """Reusable settings row; controls are read-only unless a real provider is connected."""

    def __init__(
        self,
        title: str,
        description: str,
        *,
        icon_kind: str | None = None,
        control: QWidget | None = None,
        meta: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("SettingRow")
        self.setMinimumWidth(0)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 13, 14, 13)
        lay.setSpacing(12)

        if icon_kind:
            icon = QLabel()
            icon.setObjectName("SettingIconSmall")
            icon.setFixedSize(34, 34)
            icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            apply_icon(icon, icon_kind, COLORS["text_secondary"], 17)
            lay.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)

        copy = QVBoxLayout()
        copy.setSpacing(3)
        heading = QLabel(title)
        heading.setObjectName("SettingTitle")
        heading.setWordWrap(True)
        body = QLabel(description)
        body.setObjectName("SettingDescription")
        body.setWordWrap(True)
        copy.addWidget(heading)
        copy.addWidget(body)
        if meta:
            meta_label = QLabel(meta)
            meta_label.setObjectName("SettingMeta")
            meta_label.setWordWrap(True)
            copy.addWidget(meta_label)
        lay.addLayout(copy, 1)

        if control is not None:
            lay.addWidget(control, 0, Qt.AlignmentFlag.AlignVCenter)


class SettingsSection(QFrame):
    def __init__(self, title: str, description: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SettingsPanel")
        self.setMinimumWidth(0)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 17, 18, 18)
        layout.setSpacing(10)
        layout.addWidget(SectionHeader(title, description))
        self.body = QVBoxLayout()
        self.body.setSpacing(8)
        layout.addLayout(self.body)


class ProtectionPage(QWidget):
    def __init__(
        self,
        snapshot: model.HomeSecuritySnapshot,
        open_recovery: Callable[[], None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("ProtectionPage")
        self.setMinimumWidth(0)
        self.snapshot = snapshot
        self.open_recovery = open_recovery

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(20)
        root.addWidget(
            PageHeader(
                "Protezione",
                "Controlla i livelli di protezione disponibili. Motore presente, stato runtime e controllo restano informazioni distinte.",
            )
        )

        panel = SettingsSection(
            "Moduli di protezione",
            "Lo stato verde viene usato solo quando BC Sentinel dispone di evidenza runtime corrente.",
        )
        for card in snapshot.cards:
            panel.body.addWidget(
                ProtectionRow(
                    card,
                    self.open_recovery if card.card_id == model.LAYER_RECOVERY and card.action_enabled else None,
                )
            )
        root.addWidget(panel)
        root.addStretch(1)

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        return


class SettingsPage(QWidget):
    def __init__(self, snapshot: model.HomeSecuritySnapshot, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SettingsPage")
        self.setMinimumWidth(0)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(20)
        root.addWidget(
            PageHeader(
                "Impostazioni",
                "Gestisci preferenze e configurazioni senza mostrare come attivo ciò che il runtime non ha verificato.",
            )
        )

        self.grid = QGridLayout()
        self.grid.setHorizontalSpacing(16)
        self.grid.setVerticalSpacing(16)

        self.protection_panel = SettingsSection(
            "Protezione",
            "Indicatori in sola lettura derivati dallo stato realmente disponibile.",
        )
        for card in snapshot.cards[:3]:
            toggle = ReadOnlyToggle(card.status == model.STATUS_ACTIVE and card.runtime_verified)
            toggle.setToolTip("Indicatore in sola lettura in B6-2.")
            self.protection_panel.body.addWidget(
                SettingsRow(
                    card.label,
                    card.description,
                    icon_kind={
                        model.LAYER_MALWARE: "radar",
                        model.LAYER_BEHAVIOR: "behavior",
                        model.LAYER_WEB: "web",
                    }.get(card.card_id, "protection"),
                    control=toggle,
                    meta=f"{card.status_label} · {_runtime_copy(card)}",
                )
            )

        self.general_panel = SettingsSection(
            "Generale",
            "Preferenze dell’applicazione disponibili solo quando collegate a un provider reale.",
        )
        startup_toggle = ReadOnlyToggle(False)
        startup_toggle.setToolTip("Impostazione non collegata in B6-2.")
        self.general_panel.body.addWidget(
            SettingsRow(
                "Avvia BC Sentinel con Windows",
                "L’impostazione non è collegata alla Home B6-2.",
                icon_kind="settings",
                control=startup_toggle,
                meta="Non collegato",
            )
        )

        self.folders_panel = SettingsSection(
            "Cartelle monitorate",
            "Percorsi inclusi nel monitoraggio quando la configurazione runtime sarà disponibile.",
        )
        self.folders_panel.body.addWidget(
            SettingsRow(
                "Nessun provider di configurazione collegato",
                "BC Sentinel non mostra cartelle simulate.",
                icon_kind="folder",
                meta="Nessun dato reale disponibile",
            )
        )

        self.allow_panel = SettingsSection(
            "Esclusioni / Allowlist",
            "Esclusioni esplicite e verificabili, senza valori precompilati fittizi.",
        )
        self.allow_panel.body.addWidget(
            SettingsRow(
                "Nessuna esclusione mostrata",
                "Le esclusioni appariranno qui solo quando fornite dal backend reale.",
                icon_kind="protection",
                meta="Nessun dato reale disponibile",
            )
        )

        root.addLayout(self.grid)
        root.addStretch(1)
        self._render(False)

    def _render(self, compact: bool) -> None:
        while self.grid.count():
            item = self.grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)

        panels = (
            self.protection_panel,
            self.general_panel,
            self.folders_panel,
            self.allow_panel,
        )
        if compact:
            for row, widget in enumerate(panels):
                self.grid.addWidget(widget, row, 0)
            self.grid.setColumnStretch(0, 1)
            self.grid.setColumnStretch(1, 0)
        else:
            self.grid.addWidget(self.protection_panel, 0, 0, 2, 1)
            self.grid.addWidget(self.general_panel, 0, 1)
            self.grid.addWidget(self.folders_panel, 1, 1)
            self.grid.addWidget(self.allow_panel, 2, 0, 1, 2)
            self.grid.setColumnStretch(0, 1)
            self.grid.setColumnStretch(1, 1)

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        self._render(compact)


class ThreatAlertDialog(QDialog):
    """Critical surface instantiated only by a real detection event."""

    def __init__(
        self,
        threat: Mapping[str, object],
        quarantine_callback: Callable[[], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("ThreatDialog")
        self.setModal(True)
        self.setWindowTitle("BC Sentinel - Minaccia rilevata")
        self.setMinimumWidth(420)
        self.resize(620, 420)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        header = QFrame()
        header.setObjectName("ThreatHeader")
        h = QHBoxLayout(header)
        h.setContentsMargins(18, 12, 18, 12)
        icon = QLabel()
        apply_icon(icon, "warning", COLORS["danger"], 18)
        h.addWidget(icon)
        title = QLabel("Minaccia rilevata")
        title.setObjectName("ThreatHeaderTitle")
        h.addWidget(title)
        h.addStretch(1)
        root.addWidget(header)

        body = QFrame()
        body.setObjectName("ThreatBody")
        lay = QVBoxLayout(body)
        lay.setContentsMargins(22, 20, 22, 20)
        lay.setSpacing(12)

        name = QLabel(str(threat.get("name") or threat.get("file") or "Minaccia"))
        name.setObjectName("ThreatName")
        name.setWordWrap(True)
        lay.addWidget(name)

        details = QLabel(str(threat.get("reason") or "Rilevamento di sicurezza confermato dal motore."))
        details.setObjectName("ThreatText")
        details.setWordWrap(True)
        lay.addWidget(details)

        for label, key in (("Percorso", "path"), ("SHA-256", "sha256"), ("Score", "score")):
            if threat.get(key):
                row = QHBoxLayout()
                meta_label = QLabel(label)
                meta_label.setObjectName("ThreatMetaLabel")
                value = QLabel(str(threat[key]))
                value.setObjectName("ThreatMetaValue")
                value.setWordWrap(True)
                row.addWidget(meta_label)
                row.addWidget(value, 1)
                lay.addLayout(row)
        root.addWidget(body)

        footer = QFrame()
        footer.setObjectName("ThreatFooter")
        actions = QHBoxLayout(footer)
        actions.setContentsMargins(18, 12, 18, 12)

        details_button = QPushButton("Dettagli")
        details_button.setObjectName("InlineButton")
        actions.addWidget(details_button)
        actions.addStretch(1)

        ignore = QPushButton("Ignora per ora")
        ignore.setObjectName("SecondaryAction")
        ignore.clicked.connect(self.reject)
        actions.addWidget(ignore)

        self.quarantine_button = QPushButton("Metti in quarantena")
        self.quarantine_button.setObjectName("DangerAction")
        apply_icon(self.quarantine_button, "protection", "#2b0907", 16)
        self.quarantine_button.setEnabled(quarantine_callback is not None)
        if quarantine_callback:
            self.quarantine_button.clicked.connect(quarantine_callback)
            self.quarantine_button.clicked.connect(self.accept)
        actions.addWidget(self.quarantine_button)
        root.addWidget(footer)
