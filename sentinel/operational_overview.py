"""Native overview with live BC scan, disk and activity data."""
import ctypes
import os
import shutil

from PySide6.QtCore import Property, QEasingCurve, QPropertyAnimation, Qt
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QProgressBar, QPushButton, QVBoxLayout, QWidget

from sentinel.ui_design_system import make_icon
from sentinel.ui_motion_components import reduced_motion_enabled


def motion_allowed():
    if reduced_motion_enabled():
        return False
    if os.name == "nt":
        enabled = ctypes.c_int()
        if ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(enabled), 0):
            return bool(enabled.value)
    return True


class Shield(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedSize(116, 116)
        self.state = "idle"
        self._sweep = 1.0
        self.animation = QPropertyAnimation(self, b"sweep", self)
        self.animation.setDuration(620)
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    def _set_sweep(self, value):
        self._sweep = value
        self.update()

    sweep = Property(float, lambda self: self._sweep, _set_sweep)

    def set_state(self, state, *, animate=False):
        self.state = state
        self.animation.stop()
        self._set_sweep(1.0)
        if animate and self.isVisible() and motion_allowed():
            self.animation.setStartValue(0.0)
            self.animation.setEndValue(1.0)
            self.animation.start()

    def hideEvent(self, event):
        self.animation.stop()
        self._set_sweep(1.0)
        super().hideEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        path = QPainterPath()
        path.moveTo(58, 10)
        path.lineTo(99, 24)
        path.lineTo(99, 55)
        path.quadTo(98, 84, 58, 106)
        path.quadTo(18, 84, 17, 55)
        path.lineTo(17, 24)
        path.closeSubpath()
        accent = QColor("#f6bf69" if self.state == "findings" else "#4ceba2")
        fill = QLinearGradient(14, 14, 100, 104)
        fill.setColorAt(0, accent.darker(380))
        fill.setColorAt(1, QColor("#0d201b"))
        painter.setBrush(fill)
        painter.setPen(QPen(accent, 4))
        painter.drawPath(path)
        if self._sweep < 1:
            painter.save()
            painter.setClipPath(path)
            y = 112 * self._sweep
            beam = QLinearGradient(0, y - 24, 0, y + 8)
            beam.setColorAt(0, QColor(80, 249, 173, 0))
            beam.setColorAt(0.7, QColor(80, 249, 173, 125))
            beam.setColorAt(1, QColor(80, 249, 173, 0))
            painter.fillRect(self.rect(), beam)
            painter.restore()
        pen = QPen(accent.lighter(135))
        pen.setWidthF(5)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        mark = QPainterPath()
        if self.state == "clean":
            mark.moveTo(40, 57)
            mark.lineTo(53, 69)
            mark.lineTo(76, 43)
        elif self.state == "findings":
            mark.moveTo(58, 39)
            mark.lineTo(58, 58)
            mark.moveTo(58, 69)
            mark.lineTo(58, 70)
        else:
            mark.moveTo(43, 56)
            mark.lineTo(73, 56)
        painter.drawPath(mark)


def _label(value, name=""):
    label = QLabel(value)
    label.setObjectName(name)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    return label


def _panel(title, icon):
    panel = QFrame()
    panel.setObjectName("DashboardPanel")
    layout = QVBoxLayout(panel)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(8)
    heading = QHBoxLayout()
    symbol = QLabel()
    symbol.setPixmap(make_icon(icon, "#cbd4dc", 19).pixmap(19))
    heading.addWidget(symbol)
    heading.addWidget(_label(title), 1)
    layout.addLayout(heading)
    return panel


class OperationalOverview(QWidget):
    def __init__(self, window):
        super().__init__()
        self.setObjectName("OperationalOverview")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)
        header = QVBoxLayout()
        header.setSpacing(4)
        header.addWidget(_label("PANORAMICA", "OverviewKicker"))
        header.addWidget(_label("Benvenuto in BC Sentinel", "OverviewTitle"))
        header.addWidget(_label("Sicurezza e gestione dello spazio di archiviazione del tuo PC.", "OverviewMuted"))
        layout.addLayout(header)

        hero = QFrame()
        hero.setObjectName("OverviewHero")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(20, 16, 20, 16)
        hero_layout.setSpacing(20)
        self.shield = Shield()
        hero_layout.addWidget(self.shield)
        copy = QVBoxLayout()
        copy.setSpacing(6)
        copy.addWidget(_label("Stato della scansione BC"))
        self.status = _label("Nessuna scansione eseguita", "OverviewStatus")
        copy.addWidget(self.status)
        self.detail = _label("Scegli una cartella per analizzarla con il motore locale.", "OverviewMuted")
        copy.addWidget(self.detail)
        hero_layout.addLayout(copy, 1)
        layout.addWidget(hero)

        actions = QHBoxLayout()
        for key, title, icon, action, primary in (
            ("dashboard_bc", "Avvia scansione", "scan", window.start_bc_from_dashboard, True),
            ("dashboard_folder", "Scegli cartella", "folder", window.choose_bc_from_dashboard, False),
        ):
            button = QPushButton(make_icon(icon, "#052016" if primary else "#eaf1f5"), title)
            button.setObjectName("OverviewPrimary" if primary else "OverviewSecondary")
            button.setMinimumHeight(48)
            button.clicked.connect(action)
            actions.addWidget(button, 1)
            window.command_buttons[key] = button
        layout.addLayout(actions)

        cards = QHBoxLayout()
        cards.setSpacing(12)
        last = _panel("Ultima scansione", "history")
        self.last = _label("Nessuna", "OverviewMetric")
        last.layout().addWidget(self.last)
        last.layout().addWidget(_label("Motore BC", "OverviewMuted"))
        findings = _panel("Rilevazioni", "shield")
        self.count = _label("—", "OverviewMetric")
        findings.layout().addWidget(self.count)
        findings.layout().addWidget(_label("Nell’ultima scansione BC", "OverviewMuted"))
        disk = _panel("Spazio su disco", "folder")
        self.disk = _label("Non disponibile", "OverviewMetric")
        disk.layout().addWidget(self.disk)
        self.disk_bar = QProgressBar()
        self.disk_bar.setObjectName("OverviewDisk")
        self.disk_bar.setFixedHeight(12)
        self.disk_bar.setTextVisible(False)
        self.disk_bar.setAccessibleName("Percentuale libera sul disco di sistema")
        disk.layout().addWidget(self.disk_bar)
        for panel in (last, findings, disk):
            cards.addWidget(panel, 1)
        layout.addLayout(cards)

        activity = _panel("Attività recenti", "history")
        history_button = QPushButton("Vedi tutto  ›")
        history_button.clicked.connect(lambda: window.navigate("Cronologia"))
        activity.layout().itemAt(0).layout().addWidget(history_button)
        self.events = [_label("", "OverviewEvent") for _ in range(4)]
        for row in self.events:
            activity.layout().addWidget(row)
        layout.addWidget(activity)

    def update_disk(self):
        try:
            total, _, free = shutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\")
        except OSError:
            return
        self.disk.setText(f"{free / 1024**3:.1f} GiB liberi\nsu {total / 1024**3:.1f} GiB".replace(".", ","))
        self.disk_bar.setValue(round(100 * free / total) if total else 0)

    def render_events(self, events):
        recent = [item for item in reversed(events) if item.get("azione") != "status"]
        last = next((item for item in recent if item.get("azione") == "Scansione BC"), None)
        if last:
            count = last.get("rilevazioni")
            self.last.setText(str(last.get("ora", "")).replace("T", " "))
            self.count.setText(str(count) if type(count) is int else "—")
            self.detail.setText(str(last.get("esito", "")))
            state = "findings" if count else "idle" if last.get("parziale") else "clean"
            self.shield.set_state(state)
            self.status.setText("Scansione non riuscita" if last.get("errore") else
                                "Rilevazioni da esaminare" if count else
                                "Scansione parziale" if last.get("parziale") else "Nessuna corrispondenza rilevata")
        for index, row in enumerate(self.events):
            if index < len(recent):
                item = recent[index]
                row.setText(f"{item.get('azione', '')}  ·  {item.get('esito', '')}  ·  "
                            f"{str(item.get('ora', '')).replace('T', ' ')}")
                row.show()
            else:
                row.setText("Le attività compariranno qui." if index == 0 else "")
                row.setVisible(index == 0)
