from __future__ import annotations

"""Stitch-aligned BC Sentinel secondary surfaces.

Presentation adapters only: when an operational provider is not connected the UI shows
an explicit empty/unavailable state instead of inventing security data or enabling actions.
"""

from collections.abc import Callable
from typing import Mapping

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QBoxLayout, QDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QPushButton, QSizePolicy, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from sentinel import home_security_model as model
from sentinel.ui_design_system import COLORS, ReadOnlyToggle, apply_icon


class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str, parent: QWidget | None = None) -> None:
        super().__init__(parent); self.setMinimumWidth(0)
        layout=QVBoxLayout(self); layout.setContentsMargins(0,0,0,0); layout.setSpacing(5)
        heading=QLabel(title); heading.setObjectName("PageTitle"); heading.setWordWrap(True)
        body=QLabel(subtitle); body.setObjectName("PageSubtitle"); body.setWordWrap(True)
        layout.addWidget(heading); layout.addWidget(body)


class EmptyState(QFrame):
    def __init__(self, title: str, text: str, icon: str = "info", parent: QWidget | None = None) -> None:
        super().__init__(parent); self.setObjectName("EmptyState"); self.setMinimumWidth(0)
        layout=QVBoxLayout(self); layout.setContentsMargins(28,28,28,28); layout.setSpacing(10)
        icon_label=QLabel(); icon_label.setObjectName("EmptyIcon"); icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter); apply_icon(icon_label,icon,COLORS["text_muted"],28)
        heading=QLabel(title); heading.setObjectName("EmptyTitle"); heading.setAlignment(Qt.AlignmentFlag.AlignCenter); heading.setWordWrap(True)
        body=QLabel(text); body.setObjectName("EmptyBody"); body.setWordWrap(True); body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label); layout.addWidget(heading); layout.addWidget(body)


class ScanPage(QWidget):
    """Stitch scan surface without inventing an active scan before B6-3."""
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent); self.setObjectName("ScanPage"); self.setMinimumWidth(0)
        root=QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(24)
        root.addWidget(PageHeader("Scansione","Avvia e monitora le scansioni di BC Sentinel. Le azioni operative restano disabilitate finché il motore Home non viene collegato nel milestone previsto."))
        panel=QFrame(); panel.setObjectName("TaskPanel"); panel.setMinimumWidth(0)
        lay=QVBoxLayout(panel); lay.setContentsMargins(32,30,32,30); lay.setSpacing(18)
        mark=QLabel(); mark.setAlignment(Qt.AlignmentFlag.AlignCenter); apply_icon(mark,"radar",COLORS["info"],44)
        title=QLabel("Nessuna scansione in corso"); title.setObjectName("TaskTitle"); title.setAlignment(Qt.AlignmentFlag.AlignCenter); title.setWordWrap(True)
        subtitle=QLabel("Quando Smart Scan sarà collegata, questa schermata mostrerà progresso reale, file corrente, tempo trascorso e rilevamenti senza dati simulati."); subtitle.setObjectName("TaskSubtitle"); subtitle.setWordWrap(True); subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.actions=QBoxLayout(QBoxLayout.Direction.LeftToRight); self.actions.setSpacing(12); self.actions.addStretch(1)
        self.quick_scan=QPushButton("Scansione rapida"); self.quick_scan.setObjectName("PrimaryDisabled"); self.quick_scan.setEnabled(False); apply_icon(self.quick_scan,"bolt","#79a892",18)
        self.full_scan=QPushButton("Scansione completa"); self.full_scan.setObjectName("SecondaryDisabled"); self.full_scan.setEnabled(False); apply_icon(self.full_scan,"search","#7d8c84",18)
        self.actions.addWidget(self.quick_scan); self.actions.addWidget(self.full_scan); self.actions.addStretch(1)
        note=QLabel("Azioni operative previste in B6-3"); note.setObjectName("Microcopy"); note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addStretch(1); lay.addWidget(mark); lay.addWidget(title); lay.addWidget(subtitle); lay.addLayout(self.actions); lay.addWidget(note); lay.addStretch(1); root.addWidget(panel,1)
    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        self.actions.setDirection(QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight)
        panel=self.findChild(QFrame,"TaskPanel")
        if panel and panel.layout(): panel.layout().setContentsMargins(20 if compact else 32,24 if compact else 30,20 if compact else 32,24 if compact else 30)


class _DataTable(QTableWidget):
    def __init__(self, headers: list[str], parent: QWidget | None = None) -> None:
        super().__init__(0,len(headers),parent); self.setObjectName("DataTable"); self.setHorizontalHeaderLabels(headers); self.setShowGrid(False); self.setAlternatingRowColors(False); self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows); self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection); self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); self.verticalHeader().setVisible(False); self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch); self.setMinimumHeight(240); self.setMinimumWidth(0); self.setSizePolicy(QSizePolicy.Policy.Ignored,QSizePolicy.Policy.Expanding); self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel); self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)


class QuarantinePage(QWidget):
    def __init__(self, rows_provider: Callable[[], list[Mapping]] | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent); self.setObjectName("QuarantinePage"); self.setMinimumWidth(0); self.rows_provider=rows_provider
        root=QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(20)
        self.header_row=QBoxLayout(QBoxLayout.Direction.LeftToRight); self.header_row.setSpacing(16); self.header_row.addWidget(PageHeader("Gestione Quarantena","Analizza e gestisci le minacce isolate dal sistema di protezione."),1)
        self.refresh_button=QPushButton("Aggiorna lista"); self.refresh_button.setObjectName("SecondaryAction"); apply_icon(self.refresh_button,"refresh",COLORS["text_secondary"],16); self.refresh_button.clicked.connect(self.refresh); self.header_row.addWidget(self.refresh_button,0,Qt.AlignmentFlag.AlignTop); root.addLayout(self.header_row)
        panel=QFrame(); panel.setObjectName("TablePanel"); panel.setMinimumWidth(0); lay=QVBoxLayout(panel); lay.setContentsMargins(0,0,0,0); lay.setSpacing(0)
        tabs=QHBoxLayout(); tabs.setContentsMargins(18,14,18,10); tabs.setSpacing(8)
        active=QPushButton("In quarantena"); active.setObjectName("FilterActive"); restored=QPushButton("Ripristinati"); restored.setObjectName("FilterButton"); restored.setEnabled(False); filter_btn=QPushButton(""); filter_btn.setObjectName("IconButton"); apply_icon(filter_btn,"filter",COLORS["text_secondary"],17); filter_btn.setEnabled(False)
        tabs.addWidget(active); tabs.addWidget(restored); tabs.addStretch(1); tabs.addWidget(filter_btn); lay.addLayout(tabs)
        self.table=_DataTable(["File","Percorso","Data","Rischio","Motivo","Stato","Azioni"]); lay.addWidget(self.table)
        self.empty=EmptyState("Nessun dato di quarantena disponibile","La Home non inventa elementi. I file appariranno qui solo quando un provider di quarantena reale verrà collegato.","quarantine"); lay.addWidget(self.empty); root.addWidget(panel,1); self.refresh()
    def refresh(self) -> None:
        rows=list(self.rows_provider() if self.rows_provider else []); self.table.setRowCount(0)
        for payload in rows:
            r=self.table.rowCount(); self.table.insertRow(r)
            for c,value in enumerate([payload.get(k,"") for k in ("file","path","date","risk","reason","status","action")]): self.table.setItem(r,c,QTableWidgetItem(str(value)))
        self.table.setVisible(bool(rows)); self.empty.setVisible(not rows)
    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        self.header_row.setDirection(QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight); self.refresh_button.setSizePolicy(QSizePolicy.Policy.Expanding if compact else QSizePolicy.Policy.Fixed,QSizePolicy.Policy.Fixed)


class HistoryPage(QWidget):
    def __init__(self, rows_provider: Callable[[], list[Mapping]] | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent); self.setObjectName("HistoryPage"); self.setMinimumWidth(0); self.rows_provider=rows_provider
        root=QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(20)
        self.header_row=QBoxLayout(QBoxLayout.Direction.LeftToRight); self.header_row.setSpacing(18); self.header_row.addWidget(PageHeader("Cronologia Eventi","Registro completo delle attività di sistema e degli interventi di sicurezza."),1)
        self.filters=QBoxLayout(QBoxLayout.Direction.LeftToRight); self.filters.setSpacing(6)
        for i,label in enumerate(("Tutti","Critical","High","Suspicious")):
            b=QPushButton(label); b.setObjectName("FilterActive" if i==0 else "FilterButton"); b.setEnabled(i==0); self.filters.addWidget(b)
        self.header_row.addLayout(self.filters); root.addLayout(self.header_row)
        panel=QFrame(); panel.setObjectName("CommandPanel"); panel.setMinimumWidth(0); lay=QVBoxLayout(panel); lay.setContentsMargins(0,0,0,0); lay.setSpacing(0)
        self.table=_DataTable(["Data","File / Processo","Score","Livello","Stato"]); self.table.setObjectName("HistoryTable"); lay.addWidget(self.table)
        self.empty=EmptyState("Nessun evento collegato","La cronologia mostrerà esclusivamente eventi reali quando il relativo provider verrà collegato alla Home.","history"); lay.addWidget(self.empty); root.addWidget(panel,1); self.refresh()
    def refresh(self) -> None:
        rows=list(self.rows_provider() if self.rows_provider else []); self.table.setRowCount(0)
        for payload in rows:
            r=self.table.rowCount(); self.table.insertRow(r)
            for c,k in enumerate(("date","process","score","level","status")): self.table.setItem(r,c,QTableWidgetItem(str(payload.get(k,""))))
        self.table.setVisible(bool(rows)); self.empty.setVisible(not rows)
    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        self.header_row.setDirection(QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight); self.filters.setDirection(QBoxLayout.Direction.TopToBottom if mobile else QBoxLayout.Direction.LeftToRight)


class ProtectionRow(QFrame):
    def __init__(self, card: model.HomeProtectionCard, parent: QWidget | None = None) -> None:
        super().__init__(parent); self.setObjectName("SettingRow"); self.setMinimumWidth(0)
        lay=QHBoxLayout(self); lay.setContentsMargins(16,14,16,14); lay.setSpacing(12)
        icon=QLabel(); icon.setObjectName("SettingIcon"); icon.setFixedSize(38,38); icon.setAlignment(Qt.AlignmentFlag.AlignCenter); kind={model.LAYER_MALWARE:"radar",model.LAYER_BEHAVIOR:"behavior",model.LAYER_WEB:"web",model.LAYER_RECOVERY:"recovery"}.get(card.card_id,"info"); apply_icon(icon,kind,COLORS["accent"],20); lay.addWidget(icon)
        copy=QVBoxLayout(); copy.setSpacing(3); title=QLabel(card.label); title.setObjectName("SettingTitle"); title.setWordWrap(True); desc=QLabel(card.description); desc.setObjectName("SettingDescription"); desc.setWordWrap(True); copy.addWidget(title); copy.addWidget(desc); lay.addLayout(copy,1); lay.addWidget(ReadOnlyToggle(card.status==model.STATUS_ACTIVE and card.runtime_verified))


class ProtectionPage(QWidget):
    def __init__(self, snapshot: model.HomeSecuritySnapshot, open_recovery: Callable[[], None], parent: QWidget | None = None) -> None:
        super().__init__(parent); self.setObjectName("ProtectionPage"); self.setMinimumWidth(0); self.snapshot=snapshot; self.open_recovery=open_recovery
        root=QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(20); root.addWidget(PageHeader("Protezione","Controlla i livelli di protezione disponibili e distingui sempre motore presente da stato runtime verificato."))
        panel=QFrame(); panel.setObjectName("SettingsPanel"); panel.setMinimumWidth(0); lay=QVBoxLayout(panel); lay.setContentsMargins(20,18,20,20); lay.setSpacing(10)
        for card in snapshot.cards: lay.addWidget(ProtectionRow(card))
        recovery=next((c for c in snapshot.cards if c.card_id==model.LAYER_RECOVERY),None)
        if recovery and recovery.action_enabled:
            actions=QHBoxLayout(); actions.addStretch(1); b=QPushButton("Apri System & Recovery"); b.setObjectName("PrimaryAction"); apply_icon(b,"recovery","#062016",17); b.clicked.connect(open_recovery); actions.addWidget(b); lay.addLayout(actions)
        root.addWidget(panel); root.addStretch(1)
    def set_compact(self, compact: bool, mobile: bool = False) -> None: return


class SettingsPage(QWidget):
    def __init__(self, snapshot: model.HomeSecuritySnapshot, parent: QWidget | None = None) -> None:
        super().__init__(parent); self.setObjectName("SettingsPage"); self.setMinimumWidth(0)
        root=QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(20); root.addWidget(PageHeader("Impostazioni","Gestisci le preferenze di sicurezza e il comportamento del sistema senza mostrare controlli fittizi."))
        self.grid=QGridLayout(); self.grid.setHorizontalSpacing(16); self.grid.setVerticalSpacing(16)
        self.protection_panel=QFrame(); self.protection_panel.setObjectName("SettingsPanel"); self.protection_panel.setMinimumWidth(0); p=QVBoxLayout(self.protection_panel); p.setContentsMargins(20,18,20,20); p.setSpacing(10); h=QLabel("Protezione"); h.setObjectName("PanelTitle"); p.addWidget(h)
        for card in snapshot.cards[:3]: p.addWidget(ProtectionRow(card))
        self.general_panel=QFrame(); self.general_panel.setObjectName("SettingsPanel"); self.general_panel.setMinimumWidth(0); g=QVBoxLayout(self.general_panel); g.setContentsMargins(18,18,18,18); g.setSpacing(12); t=QLabel("Generale"); t.setObjectName("PanelTitle"); g.addWidget(t); row=QHBoxLayout(); copy=QVBoxLayout(); st=QLabel("Avvia BC Sentinel con Windows"); st.setObjectName("SettingTitle"); sd=QLabel("Impostazione non collegata alla Home B6-2."); sd.setObjectName("SettingDescription"); sd.setWordWrap(True); copy.addWidget(st); copy.addWidget(sd); row.addLayout(copy,1); row.addWidget(ReadOnlyToggle(False)); g.addLayout(row)
        self.folders_panel=QFrame(); self.folders_panel.setObjectName("SettingsPanel"); self.folders_panel.setMinimumWidth(0); f=QVBoxLayout(self.folders_panel); f.setContentsMargins(18,18,18,18); f.setSpacing(10); ft=QLabel("Cartelle monitorate"); ft.setObjectName("PanelTitle"); f.addWidget(ft); fx=QLabel("Nessun provider di configurazione collegato."); fx.setObjectName("SettingDescription"); fx.setWordWrap(True); f.addWidget(fx)
        self.allow_panel=QFrame(); self.allow_panel.setObjectName("SettingsPanel"); self.allow_panel.setMinimumWidth(0); a=QVBoxLayout(self.allow_panel); a.setContentsMargins(18,18,18,18); at=QLabel("Esclusioni / Allowlist"); at.setObjectName("PanelTitle"); a.addWidget(at); ax=QLabel("Nessuna esclusione mostrata senza dati reali."); ax.setObjectName("SettingDescription"); ax.setWordWrap(True); a.addWidget(ax)
        root.addLayout(self.grid); root.addStretch(1); self._render(False)
    def _render(self, compact: bool) -> None:
        while self.grid.count():
            item=self.grid.takeAt(0); w=item.widget()
            if w is not None: w.setParent(None)
        if compact:
            for row,w in enumerate((self.protection_panel,self.general_panel,self.folders_panel,self.allow_panel)): self.grid.addWidget(w,row,0)
            self.grid.setColumnStretch(0,1); self.grid.setColumnStretch(1,0); self.grid.setColumnStretch(2,0)
        else:
            self.grid.addWidget(self.protection_panel,0,0,2,2); self.grid.addWidget(self.general_panel,0,2); self.grid.addWidget(self.folders_panel,1,2); self.grid.addWidget(self.allow_panel,2,0,1,3)
            for c in range(3): self.grid.setColumnStretch(c,1)
    def set_compact(self, compact: bool, mobile: bool = False) -> None: self._render(compact)


class ThreatAlertDialog(QDialog):
    """Critical Stitch surface; instantiated only by a real detection event."""
    def __init__(self, threat: Mapping[str, object], quarantine_callback: Callable[[], None] | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent); self.setObjectName("ThreatDialog"); self.setModal(True); self.setWindowTitle("BC Sentinel - Minaccia rilevata"); self.setMinimumWidth(420); self.resize(620,420)
        root=QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(0)
        header=QFrame(); header.setObjectName("ThreatHeader"); h=QHBoxLayout(header); h.setContentsMargins(18,12,18,12); icon=QLabel(); apply_icon(icon,"warning",COLORS["danger"],18); h.addWidget(icon); title=QLabel("Minaccia rilevata"); title.setObjectName("ThreatHeaderTitle"); h.addWidget(title); h.addStretch(1); root.addWidget(header)
        body=QFrame(); body.setObjectName("ThreatBody"); lay=QVBoxLayout(body); lay.setContentsMargins(22,20,22,20); lay.setSpacing(12); name=QLabel(str(threat.get("name") or threat.get("file") or "Minaccia")); name.setObjectName("ThreatName"); name.setWordWrap(True); lay.addWidget(name); details=QLabel(str(threat.get("reason") or "Rilevamento di sicurezza confermato dal motore.")); details.setObjectName("ThreatText"); details.setWordWrap(True); lay.addWidget(details)
        for label,key in (("Percorso","path"),("SHA-256","sha256"),("Score","score")):
            if threat.get(key):
                row=QHBoxLayout(); ml=QLabel(label); ml.setObjectName("ThreatMetaLabel"); value=QLabel(str(threat[key])); value.setObjectName("ThreatMetaValue"); value.setWordWrap(True); row.addWidget(ml); row.addWidget(value,1); lay.addLayout(row)
        root.addWidget(body)
        footer=QFrame(); footer.setObjectName("ThreatFooter"); actions=QHBoxLayout(footer); actions.setContentsMargins(18,12,18,12); details_b=QPushButton("Dettagli"); details_b.setObjectName("InlineButton"); actions.addWidget(details_b); actions.addStretch(1); ignore=QPushButton("Ignora per ora"); ignore.setObjectName("SecondaryAction"); ignore.clicked.connect(self.reject); actions.addWidget(ignore); self.quarantine_button=QPushButton("Metti in quarantena"); self.quarantine_button.setObjectName("DangerAction"); apply_icon(self.quarantine_button,"protection","#2b0907",16); self.quarantine_button.setEnabled(quarantine_callback is not None)
        if quarantine_callback: self.quarantine_button.clicked.connect(quarantine_callback); self.quarantine_button.clicked.connect(self.accept)
        actions.addWidget(self.quarantine_button); root.addWidget(footer)
