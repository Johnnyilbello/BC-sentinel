from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from PySide6.QtCore import (
    Qt, QThread, Signal, QSize, QTimer, QPropertyAnimation, QEasingCurve, Property
)
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap, QAction
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QSystemTrayIcon,
    QGraphicsOpacityEffect,
    QGraphicsDropShadowEffect,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QVBoxLayout,
    QWidget,
)

from sentinel.ai_analyst import OllamaAnalyst
from sentinel.config import APP_ROOT, APP_VERSION, Settings
from sentinel.database import Database
from sentinel.process_monitor import ProcessMonitor
from sentinel.quarantine import QuarantineManager
from sentinel.realtime import RealtimeMonitor
from sentinel.scanner import StaticScanner
from sentinel.process_tree import ProcessTree
from sentinel.process_identity import ProcessIdentityResolver
from sentinel.correlation import FileProcessCorrelator
from sentinel.etw_monitor import ETWMonitor
from sentinel.persistence_monitor import PersistenceMonitor
from sentinel.notifications import WindowsNotifier
from sentinel.startup import StartupManager
from sentinel.logging_setup import LOG_DIR, event_log
from sentinel.telemetry_client import TelemetryServiceClient
from sentinel.core.events import SecurityEvent, ProcessAttribution
from sentinel.network_monitor import NetworkMonitor
from sentinel.network_intelligence import NetworkReputationEngine
from sentinel.web_protection import DNSCorrelationCache, WebProtectionEngine
from sentinel.reputation import ReputationEngine
from sentinel.correlation_engine import (
    BehavioralCorrelationEngine,
    EventDeduplicator,
)
from sentinel.incident_engine import IncidentCorrelationEngine
from sentinel.ioc_denylist import SignedIOCVerifier
from sentinel.threat_packages import SignedThreatPackageVerifier
from sentinel.response_engine import ResponseEngine
from sentinel.scoring import ThreatAssessment


# BC Sentinel premium desktop design system — centralized semantic tokens.
# Keep QSS values here so states remain coherent across dashboard, dialogs and tables.
C = {
    "bg": "#0a0e0d",
    "sidebar": "#0d1210",
    "surface": "#121816",
    "surface_low": "#0e1412",
    "surface_high": "#19211e",
    "surface_top": "#222c28",
    "border": "#2b3933",
    "border_soft": "#1d2924",
    "border_strong": "#3c4d45",
    "text": "#e8efeb",
    "text_strong": "#f7faf8",
    "muted": "#a0afa6",
    "muted2": "#718178",
    "disabled": "#59665f",
    "primary": "#42d79b",
    "primary_hover": "#58e5aa",
    "primary_dark": "#0a5037",
    "primary_soft": "#102d23",
    "safe": "#42d79b",
    "safe_soft": "#102d23",
    "warning": "#e8b55d",
    "warning_soft": "#302713",
    "danger": "#ff6b6b",
    "danger_soft": "#34191d",
    "info": "#84aef8",
    "info_soft": "#17243a",
    "inactive": "#7d8a82",
    "focus": "#8bb7ff",
    "shadow": "#050706",
}

# Motion tokens (milliseconds). Animations only affect presentation; security actions
# and worker threads never wait for them.
MOTION = {
    "instant": 90,
    "fast": 150,
    "base": 210,
    "slow": 320,
}

SPACING = {
    "xs": 4,
    "sm": 8,
    "md": 12,
    "lg": 16,
    "xl": 24,
    "xxl": 32,
}

RADIUS = {
    "sm": 8,
    "md": 11,
    "lg": 15,
    "xl": 18,
    "pill": 10,
}

ICON_SIZE = {
    "status": 20,
    "scan": 24,
    "brand": 40,
    "hero": 72,
}

ELEVATION = {
    "hero_blur": 30,
    "hero_y": 7,
    "hero_alpha": 72,
}

APP_STYLE = f"""
QWidget {{
    background: {C['bg']};
    color: {C['text']};
    font-family: "Segoe UI Variable Text", "Segoe UI";
    font-size: 13px;
}}
QMainWindow, QDialog {{ background:{C['bg']}; }}
QLabel {{ background: transparent; }}
QLabel[role="pageTitle"] {{ color:{C['text_strong']}; font-size:20px; font-weight:700; }}
QLabel[role="pageSubtitle"] {{ color:{C['muted2']}; font-size:12px; }}
QLabel[role="heroTitle"] {{ color:{C['text_strong']}; font-size:30px; font-weight:700; }}
QLabel[role="sectionTitle"] {{ color:{C['text_strong']}; font-size:16px; font-weight:700; }}
QLabel[role="subsectionTitle"] {{ color:{C['text']}; font-size:14px; font-weight:650; }}
QLabel[role="bodyMuted"] {{ color:{C['muted']}; }}
QLabel[role="caption"] {{ color:{C['muted2']}; font-size:11px; }}
QLabel[role="eyebrow"] {{ color:{C['muted2']}; font-size:10px; font-weight:700; letter-spacing:1px; }}
QLabel[role="metricValue"] {{ color:{C['text_strong']}; font-size:27px; font-weight:700; }}
QLabel[role="empty"] {{ color:{C['muted2']}; font-size:12px; padding:10px 4px; }}
QLabel[role="scanStatus"] {{ color:{C['text_strong']}; font-size:23px; font-weight:700; }}
QFrame#sidebar {{ background:{C['sidebar']}; border-right:1px solid {C['border_soft']}; }}
QFrame#card {{ background:{C['surface']}; border:1px solid {C['border']}; border-radius:15px; }}
QFrame#softCard {{ background:{C['surface_low']}; border:1px solid {C['border_soft']}; border-radius:11px; }}
QFrame#hero {{ background:{C['surface']}; border:1px solid {C['border_strong']}; border-radius:18px; }}
QFrame#scanPanel {{ background:{C['surface']}; border:1px solid {C['border']}; border-radius:16px; }}
QFrame#scanPanel[state="scanning"], QFrame#scanPanel[state="analyzing"] {{ border-color:{C['primary_dark']}; }}
QFrame#scanPanel[state="safe"] {{ border-color:{C['primary_dark']}; }}
QFrame#scanPanel[state="warning"] {{ border-color:{C['warning']}; }}
QFrame#scanPanel[state="threat"] {{ border-color:{C['danger']}; }}
QFrame#dangerCard {{ background:{C['danger_soft']}; border:1px solid {C['danger']}; border-radius:14px; }}
QPushButton {{
    background:{C['surface_high']};
    color:{C['text']};
    border:1px solid {C['border']};
    padding:9px 14px;
    border-radius:9px;
    min-height:22px;
    font-weight:600;
}}
QPushButton:hover {{ background:{C['surface_top']}; border-color:{C['border_strong']}; }}
QPushButton:pressed {{ background:{C['surface_low']}; padding-top:10px; padding-bottom:8px; }}
QPushButton:focus {{ border-color:{C['focus']}; }}
QPushButton:disabled {{ color:{C['disabled']}; background:{C['surface_low']}; border-color:{C['border_soft']}; }}
QPushButton#primary {{ background:{C['primary']}; color:#03110b; border:none; font-weight:700; padding:10px 17px; }}
QPushButton#primary:hover {{ background:{C['primary_hover']}; }}
QPushButton#primary:pressed {{ background:{C['safe']}; }}
QPushButton#danger {{ background:{C['danger_soft']}; color:{C['danger']}; border:1px solid #673038; }}
QPushButton#danger:hover {{ background:#402027; border-color:{C['danger']}; }}
QPushButton#nav {{ background:transparent; border:none; text-align:left; padding:10px 13px; color:{C['muted']}; border-radius:9px; font-weight:550; }}
QPushButton#nav:hover {{ background:{C['surface_high']}; color:{C['text']}; }}
QPushButton#navActive {{ background:{C['primary_soft']}; border:none; text-align:left; padding:10px 13px; color:{C['safe']}; font-weight:700; border-radius:9px; }}
QLabel#footerLabel {{ color:{C['disabled']}; font-size:11px; padding:4px 2px 0 2px; }}
QLabel#statusBadge {{ border-radius:8px; padding:4px 9px; font-size:11px; font-weight:700; }}
QLabel#statusBadge[tone="safe"] {{ background:{C['safe_soft']}; color:{C['safe']}; border:1px solid {C['primary_dark']}; }}
QLabel#statusBadge[tone="warning"] {{ background:{C['warning_soft']}; color:{C['warning']}; border:1px solid #5f4c25; }}
QLabel#statusBadge[tone="danger"] {{ background:{C['danger_soft']}; color:{C['danger']}; border:1px solid #673038; }}
QLabel#statusBadge[tone="info"] {{ background:{C['info_soft']}; color:{C['info']}; border:1px solid #31486e; }}
QLabel#statusBadge[tone="inactive"] {{ background:{C['surface_high']}; color:{C['inactive']}; border:1px solid {C['border']}; }}
QLabel#inlineStatus {{ border-radius:8px; padding:7px 10px; font-size:11px; }}
QLabel#inlineStatus[tone="safe"] {{ background:{C['safe_soft']}; color:{C['safe']}; border:1px solid {C['primary_dark']}; }}
QLabel#inlineStatus[tone="warning"] {{ background:{C['warning_soft']}; color:{C['warning']}; border:1px solid #5f4c25; }}
QLabel#inlineStatus[tone="danger"] {{ background:{C['danger_soft']}; color:{C['danger']}; border:1px solid #673038; }}
QLabel#inlineStatus[tone="info"] {{ background:{C['info_soft']}; color:{C['info']}; border:1px solid #31486e; }}
QProgressBar {{ border:1px solid {C['border']}; border-radius:7px; text-align:center; background:{C['surface_low']}; min-height:14px; color:{C['text']}; font-size:11px; font-weight:700; }}
QProgressBar::chunk {{ background:{C['primary']}; border-radius:6px; }}
QTableWidget {{ background:{C['surface_low']}; alternate-background-color:{C['surface']}; border:1px solid {C['border_soft']}; border-radius:10px; gridline-color:transparent; selection-background-color:{C['primary_soft']}; selection-color:{C['text_strong']}; outline:0; }}
QTableWidget::item {{ padding:8px; border-bottom:1px solid {C['border_soft']}; }}
QTableWidget::item:hover {{ background:{C['surface_high']}; }}
QHeaderView::section {{ background:{C['surface_high']}; border:none; border-bottom:1px solid {C['border']}; padding:9px; font-weight:700; color:{C['muted']}; }}
QTabWidget::pane {{ border:1px solid {C['border_soft']}; border-radius:10px; top:-1px; background:{C['surface_low']}; }}
QTabBar::tab {{ background:{C['surface_low']}; color:{C['muted']}; border:1px solid {C['border_soft']}; padding:9px 15px; margin-right:4px; border-top-left-radius:8px; border-top-right-radius:8px; }}
QTabBar::tab:hover {{ color:{C['text']}; background:{C['surface_high']}; }}
QTabBar::tab:selected {{ background:{C['surface_high']}; color:{C['safe']}; font-weight:700; }}
QLineEdit {{ background:{C['surface_low']}; border:1px solid {C['border']}; border-radius:8px; padding:9px 11px; selection-background-color:{C['primary_dark']}; }}
QLineEdit:hover {{ border-color:{C['border_strong']}; }}
QLineEdit:focus {{ border-color:{C['focus']}; }}
QListWidget {{ background:{C['surface_low']}; border:1px solid {C['border_soft']}; border-radius:9px; padding:4px; outline:0; }}
QListWidget::item {{ padding:7px 8px; border-radius:6px; }}
QListWidget::item:selected {{ background:{C['primary_soft']}; color:{C['text_strong']}; }}
QScrollArea {{ border:none; background:transparent; }}
QScrollBar:vertical {{ background:transparent; width:10px; margin:2px; }}
QScrollBar::handle:vertical {{ background:{C['border_strong']}; border-radius:4px; min-height:28px; }}
QScrollBar::handle:vertical:hover {{ background:{C['muted2']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0px; }}
QMenu {{ background:{C['surface']}; border:1px solid {C['border']}; border-radius:8px; padding:6px; }}
QMenu::item {{ padding:7px 24px 7px 10px; border-radius:6px; }}
QMenu::item:selected {{ background:{C['primary_soft']}; color:{C['text_strong']}; }}
QToolTip {{ background:{C['surface_top']}; color:{C['text_strong']}; border:1px solid {C['border_strong']}; padding:6px; }}
"""



class MetricValueLabel(QLabel):
    """Animates integer metrics without blocking database/security work."""
    def __init__(self, text="—", parent=None):
        super().__init__(text, parent)
        self._number_value = 0
        self._number_animation = QPropertyAnimation(self, b"numberValue", self)
        self._number_animation.setDuration(MOTION["slow"])
        self._number_animation.setEasingCurve(QEasingCurve.OutCubic)

    def getNumberValue(self):
        return self._number_value

    def setNumberValue(self, value):
        self._number_value = int(value)
        self.setText(f"{self._number_value:,}")

    numberValue = Property(int, getNumberValue, setNumberValue)

    def set_display(self, value, animate=True):
        try:
            target = int(value)
        except (TypeError, ValueError):
            self._number_animation.stop()
            self.setText(str(value))
            return
        current_text = self.text().replace(",", "").strip()
        start = int(current_text) if current_text.lstrip("-").isdigit() else target
        self._number_value = start
        if not animate or start == target:
            self.setNumberValue(target)
            return
        self._number_animation.stop()
        self._number_animation.setStartValue(start)
        self._number_animation.setEndValue(target)
        self._number_animation.start()


class AnimatedStackedWidget(QStackedWidget):
    def __init__(self, animations_getter=None, parent=None):
        super().__init__(parent)
        self.animations_getter = animations_getter or (lambda: True)
        self._animation = None

    def fade_to(self, index):
        if index == self.currentIndex():
            return
        super().setCurrentIndex(index)
        if not self.animations_getter():
            return
        page = self.currentWidget()
        effect = QGraphicsOpacityEffect(page)
        page.setGraphicsEffect(effect)
        effect.setOpacity(0.0)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(220)
        anim.setStartValue(0.16)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.finished.connect(lambda: page.setGraphicsEffect(None))
        self._animation = anim
        anim.start()


class PulseDot(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(ICON_SIZE["status"], ICON_SIZE["status"])
        self._phase=0
        self._timer=QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(55)

    def _tick(self):
        if not self.isVisible():
            return
        self._phase=(self._phase+1)%40
        self.update()

    def paintEvent(self,event):
        p=QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        alpha=35+int(45*abs(20-self._phase)/20)
        halo=QColor(C["primary"]); halo.setAlpha(alpha)
        p.setPen(Qt.NoPen); p.setBrush(halo); p.drawEllipse(2,2,16,16)
        p.setBrush(QColor(C["primary"])); p.drawEllipse(7,7,6,6); p.end()


class ScanActivityIndicator(QWidget):
    """Small premium activity ring. Animation never drives scan logic."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(ICON_SIZE["scan"], ICON_SIZE["scan"])
        self._angle=0
        self._active=False
        self._animate=True
        self._timer=QTimer(self)
        self._timer.setInterval(36)
        self._timer.timeout.connect(self._tick)

    def set_active(self,active,animate=True):
        self._active=bool(active)
        self._animate=bool(animate)
        if self._active and self._animate:
            self._timer.start()
        else:
            self._timer.stop()
        self.update()

    def _tick(self):
        self._angle=(self._angle+12)%360
        self.update()

    def paintEvent(self,event):
        p=QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(QPen(QColor("#294238"),2.2))
        p.setBrush(Qt.NoBrush)
        p.drawEllipse(4,4,16,16)
        if self._active:
            pen=QPen(QColor(C["primary"]),2.6)
            pen.setCapStyle(Qt.RoundCap)
            p.setPen(pen)
            p.drawArc(4,4,16,16,(90-self._angle)*16,-105*16)
        else:
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(C["primary"]))
            p.drawEllipse(9,9,6,6)
        p.end()


class AIExplainThread(QThread):
    ready=Signal(str)
    failed=Signal()

    def __init__(self,analyst,payload,parent=None):
        super().__init__(parent); self.analyst=analyst; self.payload=payload

    def run(self):
        text=self.analyst.explain(self.payload,timeout=10.0)
        if text:self.ready.emit(text)
        else:self.failed.emit()


class CinematicDialog(QDialog):
    def showEvent(self,event):
        super().showEvent(event)
        parent=self.parent()
        if not bool(getattr(parent,"animations_enabled",True)):
            return
        self.setWindowOpacity(0.0)
        anim=QPropertyAnimation(self,b"windowOpacity",self)
        anim.setDuration(210); anim.setStartValue(0.05); anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        self._cinematic_animation=anim
        anim.start()


class ToggleSwitch(QCheckBox):
    """Accessible animated switch. Presentation never delays the toggled signal."""
    def __init__(self, checked=False, parent=None):
        super().__init__(parent)
        self.setChecked(bool(checked))
        self.setFixedSize(46, 26)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self._thumb_position = 1.0 if self.isChecked() else 0.0
        self._toggle_animation = QPropertyAnimation(self, b"thumbPosition", self)
        self._toggle_animation.setDuration(MOTION["fast"])
        self._toggle_animation.setEasingCurve(QEasingCurve.OutCubic)
        self.toggled.connect(self._animate_state)

    def _motion_enabled(self):
        win = self.window()
        return bool(getattr(win, "animations_enabled", True))

    def _animate_state(self, checked):
        target = 1.0 if checked else 0.0
        if not self._motion_enabled():
            self.setThumbPosition(target)
            return
        self._toggle_animation.stop()
        self._toggle_animation.setStartValue(self._thumb_position)
        self._toggle_animation.setEndValue(target)
        self._toggle_animation.start()

    def getThumbPosition(self):
        return self._thumb_position

    def setThumbPosition(self, value):
        self._thumb_position = max(0.0, min(1.0, float(value)))
        self.update()

    thumbPosition = Property(float, getThumbPosition, setThumbPosition)

    @staticmethod
    def _mix(a, b, t):
        ca, cb = QColor(a), QColor(b)
        return QColor(
            int(ca.red() + (cb.red() - ca.red()) * t),
            int(ca.green() + (cb.green() - ca.green()) * t),
            int(ca.blue() + (cb.blue() - ca.blue()) * t),
        )

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        t = self._thumb_position
        track = self._mix(C["surface_top"], C["primary_dark"], t)
        if not self.isEnabled():
            track = QColor(C["surface_high"])
        p.setPen(QPen(QColor(C["focus"] if self.hasFocus() else C["border"]), 1.0))
        p.setBrush(track)
        p.drawRoundedRect(1, 3, 44, 20, RADIUS["pill"], RADIUS["pill"])
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(C["text_strong"] if self.isEnabled() else C["disabled"]))
        x = 4 + int(20 * t)
        p.drawEllipse(x, 5, 16, 16)
        p.end()


class ScanThread(QThread):
    progress = Signal(int, int, str)
    detection = Signal(object)
    finished_summary = Signal(int, int, bool, float)

    def __init__(self, roots, settings=None, reputation_engine=None):
        super().__init__()
        self.roots = roots
        self.settings = settings
        self.reputation_engine = reputation_engine
        self._cancel = False
        self._seen_detection_hashes = set()

    def cancel(self):
        self._cancel = True

    def run(self):
        started = time.monotonic()
        scanner = StaticScanner(self.settings, reputation_engine=self.reputation_engine)
        scanned = detections = 0
        for report in scanner.scan_paths(
            self.roots,
            progress=lambda i,t,p: self.progress.emit(i,t,p),
            cancelled=lambda: self._cancel,
        ):
            scanned += 1
            if report.assessment.score >= 50 and report.sha256 not in self._seen_detection_hashes:
                self._seen_detection_hashes.add(report.sha256)
                detections += 1
                self.detection.emit(report)
        self.finished_summary.emit(scanned, detections, self._cancel, time.monotonic()-started)


class ThreatDialog(CinematicDialog):
    def __init__(self, report, parent=None, analyst=None, attribution=None):
        super().__init__(parent)
        self.report = report
        self.analyst = analyst
        self.attribution = attribution
        self.ai_thread = None
        self.should_quarantine = False
        self.decision = ""
        self.setWindowTitle("BC Sentinel — Minaccia rilevata")
        self.setModal(True)
        self.setMinimumWidth(560)
        self.setStyleSheet(APP_STYLE)

        a = report.assessment
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 22)
        root.setSpacing(14)

        top = QHBoxLayout()
        icon = QLabel("!")
        icon.setAlignment(Qt.AlignCenter)
        icon.setFixedSize(46,46)
        icon.setStyleSheet(f"background:{C['danger_soft']};color:{C['danger']};border:1px solid #673038;border-radius:23px;font-size:26px;font-weight:800;")
        text = QVBoxLayout()
        title = QLabel("Minaccia rilevata")
        title.setProperty("role", "pageTitle")
        subtitle = QLabel(Path(report.path).name)
        subtitle.setProperty("role", "bodyMuted")
        text.addWidget(title); text.addWidget(subtitle)
        top.addWidget(icon); top.addLayout(text); top.addStretch()
        root.addLayout(top)

        score = QLabel(f"{a.level}  ·  {a.score}/100")
        score.setStyleSheet(f"color:{C['danger']};font-weight:700;font-size:14px;")
        root.addWidget(score)
        recommendation = QLabel("Azione consigliata: Quarantena · reversibile e verificata")
        recommendation.setStyleSheet(f"color:{C['good']};font-weight:700;font-size:13px;")
        root.addWidget(recommendation)

        card = QFrame(); card.setObjectName("softCard")
        cv = QVBoxLayout(card); cv.setContentsMargins(16,14,16,14); cv.setSpacing(7)
        cap = QLabel("Perché BC Sentinel lo ha rilevato")
        cap.setProperty("role", "subsectionTitle")
        cv.addWidget(cap)
        for reason in a.reasons[:3]:
            r = QLabel("•  " + reason)
            r.setWordWrap(True)
            r.setProperty("role", "bodyMuted")
            cv.addWidget(r)
        root.addWidget(card)

        attribution_lines = []
        if attribution is not None and getattr(attribution, "available", False):
            attribution_lines.append(
                f"Processo: {attribution.name or 'sconosciuto'} · PID {attribution.pid or '—'} · PPID {attribution.ppid or '—'}"
            )
            if attribution.path:
                attribution_lines.append(f"Eseguibile: {attribution.path}")
            if getattr(attribution, "signer", ""):
                attribution_lines.append(f"Firmatario: {attribution.signer}")
            if getattr(attribution, "signature_status", ""):
                attribution_lines.append(f"Firma: {attribution.signature_status}")
            if getattr(attribution, "sha256", ""):
                attribution_lines.append(f"SHA-256 processo: {attribution.sha256}")

        detail_text = f"Percorso: {report.path}\nSHA-256: {report.sha256}"
        rep=getattr(report,"reputation",None) or {}
        reputation_lines=[]
        if rep:
            if rep.get("signature_status"):
                reputation_lines.append(f"Authenticode: {rep.get('signature_status')}")
            if rep.get("publisher"):
                reputation_lines.append(f"Publisher: {rep.get('publisher')}")
            if rep.get("issuer"):
                reputation_lines.append(f"Issuer: {rep.get('issuer')}")
            if rep.get("thumbprint"):
                reputation_lines.append(f"Certificato: {rep.get('thumbprint')}")
            if rep.get("first_seen"):
                reputation_lines.append(f"First seen locale: {rep.get('first_seen')} · prevalenza {rep.get('prevalence') or 'new'}")
        if attribution_lines:
            detail_text += "\n\n" + "\n".join(attribution_lines)
        if reputation_lines:
            detail_text += "\n\nReputazione file\n" + "\n".join(reputation_lines)
        detail_text += "\n\n" + "\n".join("• " + x for x in a.reasons)
        self.details = QLabel(detail_text)
        self.details.setWordWrap(True)
        self.details.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.details.setStyleSheet(f"color:{C['muted']};background:{C['surface_low']};border:1px solid {C['border_soft']};border-radius:8px;padding:10px;")
        self.details.hide()
        root.addWidget(self.details)

        self.ai_box = QLabel("")
        self.ai_box.setWordWrap(True)
        self.ai_box.setStyleSheet(
            f"color:{C['muted']};background:{C['surface_low']};"
            f"border:1px solid {C['border_soft']};border-radius:8px;padding:10px;"
        )
        self.ai_box.hide()
        root.addWidget(self.ai_box)

        actions = QHBoxLayout()
        ai_btn = QPushButton("Spiega con AI")
        ai_btn.setEnabled(self.analyst is not None)
        ai_btn.setToolTip(
            "Richiede Ollama locale" if self.analyst is None
            else "Spiega soltanto le evidenze già prodotte dal motore"
        )
        ai_btn.clicked.connect(self._run_ai)
        details_btn = QPushButton("Dettagli")
        details_btn.clicked.connect(lambda: self.details.setVisible(not self.details.isVisible()))
        keep_once = QPushButton("Mantieni questa volta")
        keep_once.setToolTip("Non crea alcuna esclusione permanente.")
        keep_once.clicked.connect(self._accept_keep_once)
        allow_hash = QPushButton("Consenti hash")
        allow_hash.setToolTip("Aggiunge soltanto questo SHA-256 alla allowlist locale.")
        allow_hash.clicked.connect(self._accept_allow_hash)
        delete = QPushButton("Elimina definitivamente")
        delete.setObjectName("danger")
        delete.setToolTip("Richiede conferma e una nuova verifica SHA-256 prima della rimozione.")
        delete.clicked.connect(self._accept_delete)
        quarantine = QPushButton("Quarantena · consigliato")
        quarantine.setObjectName("primary")
        quarantine.clicked.connect(self._accept_quarantine)
        actions.addWidget(ai_btn)
        actions.addWidget(details_btn)
        actions.addStretch()
        actions.addWidget(keep_once)
        actions.addWidget(allow_hash)
        root.addLayout(actions)

        response_actions = QHBoxLayout()
        response_actions.addStretch()
        response_actions.addWidget(delete)
        response_actions.addWidget(quarantine)
        root.addLayout(response_actions)

    def _run_ai(self):
        if self.analyst is None or (self.ai_thread and self.ai_thread.isRunning()):
            return
        self.ai_box.setText("Analisi locale in corso…")
        self.ai_box.show()
        payload={
            "score":self.report.assessment.score,
            "level":self.report.assessment.level,
            "file":Path(self.report.path).name,
            "path":self.report.path,
            "sha256":self.report.sha256,
            "signals":self.report.assessment.reasons,
            "reputation":getattr(self.report,"reputation",None) or {},
            "process": (
                self.attribution.to_dict()
                if self.attribution is not None and getattr(self.attribution, "available", False)
                else {}
            ),
        }
        self.ai_thread=AIExplainThread(self.analyst,payload,self)
        self.ai_thread.ready.connect(self.ai_box.setText)
        self.ai_thread.failed.connect(
            lambda:self.ai_box.setText(
                "Ollama non è raggiungibile o il modello non è disponibile."
            )
        )
        self.ai_thread.start()

    def _accept_quarantine(self):
        self.should_quarantine = True
        self.decision = "quarantine"
        self.accept()

    def _accept_keep_once(self):
        self.decision = "keep_once"
        self.accept()

    def _accept_allow_hash(self):
        answer = QMessageBox.question(
            self,
            "Consenti questo file",
            "Aggiungere esclusivamente questo SHA-256 alla allowlist di BC Sentinel?\n\n"
            f"{self.report.sha256}\n\n"
            "Se il file cambia, verrà analizzato nuovamente.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self.decision = "allow_hash"
            self.accept()

    def _accept_delete(self):
        answer = QMessageBox.question(
            self,
            "Eliminazione permanente",
            "Confermi l'eliminazione definitiva del file rilevato?\n\n"
            f"File: {Path(self.report.path).name}\n"
            f"Percorso: {self.report.path}\n"
            f"SHA-256: {self.report.sha256}\n\n"
            "BC Sentinel verificherà nuovamente l'identità del file prima di eliminarlo. "
            "Questa azione non è ripristinabile dalla quarantena.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self.decision = "delete"
            self.accept()


class RansomwareDialog(CinematicDialog):
    """Calm, evidence-first alert for strongly correlated ransomware-like activity."""

    def __init__(self, path, assessment, parent=None, attribution=None):
        super().__init__(parent)
        self.setWindowTitle("BC Sentinel — Attività file sospetta")
        self.setModal(True)
        self.setMinimumWidth(600)
        self.setStyleSheet(APP_STYLE)

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 22)
        root.setSpacing(14)

        top = QHBoxLayout()

        icon = QLabel("!")
        icon.setAlignment(Qt.AlignCenter)
        icon.setFixedSize(46, 46)
        icon.setStyleSheet(
            f"background:{C['warning_soft']};color:{C['warning']};"
            "border:1px solid #5f4c25;border-radius:23px;"
            "font-size:23px;font-weight:800;"
        )

        text = QVBoxLayout()
        title = QLabel("Attività file sospetta")
        title.setProperty("role", "pageTitle")

        subtitle = QLabel(
            "BC Sentinel ha correlato più segnali compatibili con attività ransomware."
        )
        subtitle.setWordWrap(True)
        subtitle.setProperty("role", "bodyMuted")

        text.addWidget(title)
        text.addWidget(subtitle)

        top.addWidget(icon)
        top.addLayout(text, 1)
        root.addLayout(top)

        severity = QLabel(f"{assessment.level}  ·  {assessment.score}/100")
        severity.setStyleSheet(
            f"color:{C['warning']};font-weight:700;font-size:14px;"
        )
        root.addWidget(severity)

        evidence = QFrame()
        evidence.setObjectName("softCard")
        ev = QVBoxLayout(evidence)
        ev.setContentsMargins(16, 14, 16, 14)
        ev.setSpacing(7)

        cap = QLabel("Evidenze osservate")
        cap.setProperty("role", "subsectionTitle")
        ev.addWidget(cap)

        for reason in assessment.reasons[:4]:
            lbl = QLabel("•  " + reason)
            lbl.setWordWrap(True)
            lbl.setProperty("role", "bodyMuted")
            ev.addWidget(lbl)

        if attribution is not None and getattr(attribution,"available",False):
            process_text=f"Processo: {attribution.name or 'sconosciuto'} · PID {attribution.pid or '—'}"
            if attribution.path:
                process_text += f"\n{attribution.path}"
            if getattr(attribution, "signer", ""):
                process_text += f"\nFirmatario: {attribution.signer}"
            if getattr(attribution, "sha256", ""):
                process_text += f"\nSHA-256: {attribution.sha256[:16]}…"
        else:
            process_text="Processo responsabile: non ancora attribuito"
        process = QLabel(process_text)
        process.setWordWrap(True)
        process.setStyleSheet(f"color:{C['muted']};margin-top:5px;")
        ev.addWidget(process)

        root.addWidget(evidence)

        note = QLabel(
            "BC Sentinel rileva e registra l'evento, ma non termina "
            "automaticamente processi sulla base di questa euristica."
        )
        note.setWordWrap(True)
        note.setProperty("role", "pageSubtitle")
        root.addWidget(note)

        path_label = QLabel(f"Evento più recente: {path}")
        path_label.setWordWrap(True)
        path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        path_label.setProperty("role", "caption")
        root.addWidget(path_label)

        actions = QHBoxLayout()
        actions.addStretch()

        protection = QPushButton("Apri Protezione")
        protection.clicked.connect(self.accept)

        ok = QPushButton("Chiudi")
        ok.setObjectName("primary")
        ok.clicked.connect(self.accept)

        actions.addWidget(protection)
        actions.addWidget(ok)
        root.addLayout(actions)


class FirewallAlertDialog(CinematicDialog):
    """Evidence-first alert for firewall drift/policy conflicts.

    The dialog is intentionally read-only. Reconciliation stays behind the
    explicit privileged/UAC action path in the Protection Service.
    """

    def __init__(self, event: SecurityEvent, parent=None):
        super().__init__(parent)
        self.setWindowTitle("BC Sentinel — Protezione firewall modificata")
        self.setModal(True)
        self.setMinimumWidth(590)
        self.setStyleSheet(APP_STYLE)

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 22)
        root.setSpacing(14)

        title = QLabel("Protezione firewall modificata")
        title.setProperty("role", "pageTitle")
        root.addWidget(title)

        action = str(event.action or "")
        data = dict(event.data or {})
        if action == "rule_drift_detected":
            summary = (
                f"BC Sentinel ha rilevato {int(data.get('issue_count') or 0)} "
                "differenza tra le regole approvate e Windows Firewall."
            )
        else:
            summary = (
                f"BC Sentinel ha rilevato {int(data.get('blocking_count') or 0)} conflitti "
                f"e {int(data.get('advisory_count') or 0)} sovrapposizioni da verificare."
            )
        subtitle = QLabel(summary)
        subtitle.setWordWrap(True)
        subtitle.setProperty("role", "bodyMuted")
        root.addWidget(subtitle)

        evidence = QFrame()
        evidence.setObjectName("softCard")
        ev = QVBoxLayout(evidence)
        ev.setContentsMargins(16, 14, 16, 14)
        cap = QLabel("Evidenze")
        cap.setProperty("role", "subsectionTitle")
        ev.addWidget(cap)
        reasons = list(event.reasons or [])[:6]
        if not reasons:
            reasons = ["Stato firewall da verificare"]
        for reason in reasons:
            lbl = QLabel("•  " + str(reason))
            lbl.setWordWrap(True)
            lbl.setProperty("role", "bodyMuted")
            ev.addWidget(lbl)
        root.addWidget(evidence)

        note = QLabel(
            "Nessuna regola di terze parti viene modificata automaticamente. "
            "Il ripristino delle sole regole BC Sentinel richiede approvazione esplicita."
        )
        note.setWordWrap(True)
        note.setProperty("role", "pageSubtitle")
        root.addWidget(note)

        actions = QHBoxLayout()
        actions.addStretch()
        open_protection = QPushButton("Apri Protezione")
        open_protection.setObjectName("primary")
        open_protection.clicked.connect(self.accept)
        close = QPushButton("Chiudi")
        close.clicked.connect(self.reject)
        actions.addWidget(close)
        actions.addWidget(open_protection)
        root.addLayout(actions)


class TelemetryServicePoller(QThread):
    events_ready = Signal(list)
    status_ready = Signal(object)

    def __init__(self, client, db_path=None, parent=None):
        super().__init__(parent)
        self.client = client
        self.db_path = db_path
        self._running = True
        self.sequence = 0

    def stop(self):
        self._running = False

    def run(self):
        last_status = None
        network_intelligence=None
        if self.db_path:
            try:
                network_intelligence=NetworkReputationEngine(Database(self.db_path))
            except Exception:
                network_intelligence=None
        while self._running:
            status = self.client.status()
            snapshot = (
                json.dumps(status, sort_keys=True, ensure_ascii=False)
                if status else ""
            )
            if snapshot != last_status:
                last_status = snapshot
                self.status_ready.emit(status)

            if status:
                events, sequence = self.client.events(self.sequence, 200)
                if events and network_intelligence is not None:
                    for raw in events:
                        if str(raw.get("category") or "") != "network":
                            continue
                        try:
                            event=SecurityEvent(
                                category="network",
                                action=str(raw.get("action") or "connect"),
                                source=str(raw.get("source") or "telemetry_service"),
                                score=int(raw.get("score") or 0),
                                path=str(raw.get("path") or ""),
                                pid=int(raw.get("pid")) if raw.get("pid") else None,
                                ppid=int(raw.get("ppid")) if raw.get("ppid") else None,
                                process_name=str(raw.get("process_name") or ""),
                                process_path=str(raw.get("process_path") or ""),
                                reasons=list(raw.get("reasons") or []),
                                data=dict(raw.get("data") or {}),
                                ts=float(raw.get("ts") or time.time()),
                            )
                            result=network_intelligence.assess_event(event)
                            event.score=min(100,event.score+result.score_delta)
                            event.reasons=list(dict.fromkeys(event.reasons+result.reasons))
                            event.data.update({
                                "endpoint_indicator":result.indicator,
                                "endpoint_kind":result.kind,
                                "endpoint_class":result.address_class,
                                "endpoint_status":result.status,
                                "endpoint_source":result.source,
                                "endpoint_confidence":result.confidence,
                                "endpoint_first_seen":result.first_seen,
                                "endpoint_connection_count":result.connection_count,
                                "endpoint_process_count":result.process_count,
                            })
                            raw.update(event.to_dict())
                        except Exception:
                            continue
                if events:
                    self.events_ready.emit(events)
                self.sequence = max(self.sequence, sequence)

            self.msleep(700)


class MainWindow(QMainWindow):
    realtime_report = Signal(object)
    ransomware_report = Signal(str, object, object)
    persistence_report = Signal(object)

    NAV = [
        ("Dashboard", "⌂"),
        ("Scansione", "⌕"),
        ("Quarantena", "□"),
        ("Cronologia", "◷"),
        ("Attività", "≋"),
        ("Protezione", "◇"),
        ("Impostazioni", "⚙"),
    ]

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"BC Sentinel {APP_VERSION}")
        app_icon = APP_ROOT / "app" / "assets" / "bc_sentinel_icon.png"
        if not app_icon.exists():
            app_icon = APP_ROOT / "app" / "assets" / "bc_sentinel.ico"
        if app_icon.exists():
            qicon = QIcon(str(app_icon))
            if not qicon.isNull():
                self.setWindowIcon(qicon)
        self.resize(1180, 760)
        self.setMinimumSize(820, 520)
        self.setStyleSheet(APP_STYLE)

        self.db = Database()
        self.settings = self._load_settings()
        self.animations_enabled = self.settings.animations_enabled
        self.quarantine = QuarantineManager(self.db)
        self.process_tree = ProcessTree()
        self.process_identity = ProcessIdentityResolver(self.db)
        self.correlator = FileProcessCorrelator(process_tree=self.process_tree)
        self.startup = StartupManager()
        self.telemetry_client = TelemetryServiceClient()
        self.telemetry_service_status = None
        self.telemetry_advanced_active = False
        self.correlation_engine = BehavioralCorrelationEngine(
            window_seconds=45.0
        )
        self.event_deduplicator = EventDeduplicator(
            ttl_seconds=1.5
        )
        self.reputation_engine = ReputationEngine(self.db)
        self.network_intelligence = NetworkReputationEngine(self.db)
        self.web_protection = WebProtectionEngine(self.db)
        self.dns_cache = DNSCorrelationCache()
        self.incident_engine = IncidentCorrelationEngine(
            self.db,
            process_tree=self.process_tree,
            incident_window_seconds=90.0,
        )
        self.response_engine = ResponseEngine(self.db, self.quarantine)
        self.network_monitor = NetworkMonitor(
            callback=self.on_security_event,
            interval=2.0,
            process_tree=self.process_tree,
            identity_resolver=self.process_identity,
            intelligence=self.network_intelligence,
            dns_cache=self.dns_cache,
            web_engine=self.web_protection,
        )
        self.network_running = False
        self.scan_thread = None
        self._alerted_hashes = set()
        self._current_scan_db_id = None
        self._current_scan_kind = "manual"

        self.realtime = RealtimeMonitor(
            self.settings,self.db,
            self.on_realtime_detection,
            self.on_ransomware_detection,
            correlator=self.correlator,
        )
        self.procmon = ProcessMonitor(
            self.db,
            process_tree=self.process_tree,
            event_callback=self.on_security_event,
            identity_resolver=self.process_identity,
        )
        self.etw = ETWMonitor(
            self.process_tree,
            self.correlator,
            event_callback=self.on_security_event,
            identity_resolver=self.process_identity,
            dns_cache=self.dns_cache,
            web_engine=self.web_protection,
        )
        self.persistence = PersistenceMonitor(
            self.db,
            callback=self.on_persistence_event,
        )

        # v0.6: probe the privileged Protection Service before starting any
        # duplicate user-space engines in the GUI process. When the service is
        # healthy/degraded and protection is enabled, it is the canonical owner
        # of realtime/process/ETW/persistence/network monitoring.
        initial_service = self.telemetry_client.status()
        service_owns_protection = bool(
            initial_service
            and initial_service.get("health") in {"HEALTHY", "DEGRADED"}
            and initial_service.get("protection_enabled", True)
        )
        self.telemetry_service_status = initial_service

        if service_owns_protection:
            self.realtime_running = bool(initial_service.get("realtime"))
            self.telemetry_advanced_active = bool(
                initial_service.get("etw", {}).get("running")
                and self.settings.etw_enabled
            )
            self.etw_running = self.telemetry_advanced_active
            self.persistence_running = bool(initial_service.get("persistence"))
            self.network_running = bool(initial_service.get("network"))
        else:
            self.realtime_running = self.realtime.start() if self.settings.realtime_enabled else False
            if self.settings.behavior_enabled:
                self.procmon.start()
            self.telemetry_advanced_active = False
            self.etw_running = False
            self.persistence_running = False
            self.network_running = False
            if self.settings.network_enabled:
                self.network_running = bool(self.network_monitor.start())
            if self.settings.persistence_enabled:
                self.persistence_running = bool(self.persistence.start())

        self.analyst = OllamaAnalyst(
            model=self.db.get_setting("ai_model","qwen3:4b") or "qwen3:4b"
        )

        self.realtime_report.connect(self._handle_realtime_detection)
        self.ransomware_report.connect(self._handle_ransomware_detection)
        self.persistence_report.connect(self._handle_persistence_event)

        central = QWidget()
        shell = QHBoxLayout(central)
        shell.setContentsMargins(0,0,0,0)
        shell.setSpacing(0)
        self.setCentralWidget(central)

        self.sidebar = self._sidebar()
        shell.addWidget(self.sidebar)

        content = QWidget()
        cv = QVBoxLayout(content)
        cv.setContentsMargins(SPACING["xl"], 20, SPACING["xl"], 22)
        cv.setSpacing(14)
        self.page_title = QLabel("Dashboard")
        self.page_title.setProperty("role", "pageTitle")
        self.page_subtitle = QLabel("Stato e attività principali di BC Sentinel")
        self.page_subtitle.setProperty("role", "pageSubtitle")
        cv.addWidget(self.page_title)
        cv.addWidget(self.page_subtitle)

        self.pages = AnimatedStackedWidget(lambda:self.animations_enabled)
        cv.addWidget(self.pages, 1)
        shell.addWidget(content, 1)

        self.dashboard_page = self._dashboard_page()
        self.scan_page = self._scan_page()
        self.quarantine_page = self._quarantine_page()
        self.history_page = self._history_page()
        self.activity_page = self._activity_page()
        self.protection_page = self._protection_page()
        self.settings_page = self._settings_page()
        for p in (
            self.dashboard_page,
            self.scan_page,
            self.quarantine_page,
            self.history_page,
            self.activity_page,
            self.protection_page,
            self.settings_page,
        ):
            self.pages.addWidget(p)

        self._force_quit=False
        self._tray_notice_shown=False
        self._setup_tray()
        self.notifier=WindowsNotifier(self._tray_fallback_message)

        self.telemetry_poller = TelemetryServicePoller(
            self.telemetry_client, self.db.path, self
        )
        self.telemetry_poller.status_ready.connect(
            self._telemetry_status_changed
        )
        self.telemetry_poller.events_ready.connect(
            self._consume_telemetry_events
        )
        self.telemetry_poller.start()

        self.nav_to(0)
        self.refresh_all()

    # ---------- persistence ----------
    def _load_settings(self):
        s = Settings.defaults()
        def b(key, default):
            raw = self.db.get_setting(key, "1" if default else "0")
            return raw == "1"
        s.realtime_enabled = b("realtime_enabled", s.realtime_enabled)
        s.ransomware_enabled = b("ransomware_enabled", s.ransomware_enabled)
        s.behavior_enabled = b("behavior_enabled", s.behavior_enabled)
        s.etw_enabled = b("etw_enabled", s.etw_enabled)
        s.notifications_enabled = b("notifications_enabled", s.notifications_enabled)
        s.close_to_tray = b("close_to_tray", s.close_to_tray)
        s.animations_enabled = b("animations_enabled", s.animations_enabled)
        s.persistence_enabled = b("persistence_enabled", s.persistence_enabled)
        s.network_enabled = b("network_enabled", s.network_enabled)
        s.reputation_enabled = b("reputation_enabled", s.reputation_enabled)
        raw_dirs = self.db.get_setting("monitored_dirs")
        if raw_dirs:
            try:
                vals = json.loads(raw_dirs)
                if isinstance(vals, list):
                    s.monitored_dirs = [str(x) for x in vals if str(x)]
            except Exception:
                pass
        return s

    def _save_bool(self, key, value):
        self.db.set_setting(key, "1" if value else "0")

    def _sync_protection_service_config(self, changes):
        if self.telemetry_service_status is None:
            return None
        ok=self.telemetry_client.set_protection_config(dict(changes))
        if not ok:
            QMessageBox.warning(
                self,
                "Protection Service",
                self.telemetry_client.last_error
                or "La modifica richiede autorizzazione amministrativa del Protection Service.",
            )
            return False
        return True

    def _apply_native_windows_icon(self):
        """Force the BC Sentinel icon on the real Windows top-level HWND."""
        if os.name != "nt":
            return

        icon_path = APP_ROOT / "app" / "assets" / "bc_sentinel.ico"
        if not icon_path.exists():
            return

        try:
            import ctypes
            from ctypes import wintypes

            IMAGE_ICON = 1
            LR_LOADFROMFILE = 0x0010
            LR_DEFAULTSIZE = 0x0040

            WM_SETICON = 0x0080
            ICON_SMALL = 0
            ICON_BIG = 1

            # Window-class icon slots. These are important because Explorer can
            # use the class icon for the taskbar button even after WM_SETICON.
            GCLP_HICON = -14
            GCLP_HICONSM = -34

            user32 = ctypes.WinDLL("user32", use_last_error=True)

            HANDLE = ctypes.c_void_p
            LONG_PTR = ctypes.c_ssize_t
            WPARAM_T = ctypes.c_size_t
            LPARAM_T = ctypes.c_ssize_t
            LRESULT_T = ctypes.c_ssize_t

            user32.LoadImageW.argtypes = [
                wintypes.HINSTANCE,
                wintypes.LPCWSTR,
                wintypes.UINT,
                ctypes.c_int,
                ctypes.c_int,
                wintypes.UINT,
            ]
            user32.LoadImageW.restype = HANDLE

            user32.SendMessageW.argtypes = [
                wintypes.HWND,
                wintypes.UINT,
                WPARAM_T,
                LPARAM_T,
            ]
            user32.SendMessageW.restype = LRESULT_T

            # 64-bit-safe SetClassLongPtrW. On 32-bit Windows the function is
            # exported as SetClassLongW.
            if ctypes.sizeof(ctypes.c_void_p) == 8:
                set_class_long = user32.SetClassLongPtrW
            else:
                set_class_long = user32.SetClassLongW

            set_class_long.argtypes = [
                wintypes.HWND,
                ctypes.c_int,
                LONG_PTR,
            ]
            set_class_long.restype = LONG_PTR

            hwnd = wintypes.HWND(int(self.winId()))

            flags = LR_LOADFROMFILE | LR_DEFAULTSIZE
            big = user32.LoadImageW(
                None,
                str(icon_path),
                IMAGE_ICON,
                32,
                32,
                flags,
            )
            small = user32.LoadImageW(
                None,
                str(icon_path),
                IMAGE_ICON,
                16,
                16,
                flags,
            )

            if big:
                big_value = int(ctypes.cast(big, ctypes.c_void_p).value or 0)
                user32.SendMessageW(
                    hwnd,
                    WM_SETICON,
                    ICON_BIG,
                    big_value,
                )
                set_class_long(hwnd, GCLP_HICON, big_value)

            if small:
                small_value = int(ctypes.cast(small, ctypes.c_void_p).value or 0)
                user32.SendMessageW(
                    hwnd,
                    WM_SETICON,
                    ICON_SMALL,
                    small_value,
                )
                set_class_long(hwnd, GCLP_HICONSM, small_value)

            # Keep handles alive for the whole window lifetime. Windows uses
            # them after this function returns.
            self._native_window_icons = (big, small)

        except Exception:
            event_log(
                "Native Windows taskbar icon assignment failed",
                event="taskbar_icon_failed",
                source="windows_ui",
            )

    def showEvent(self,event):
        super().showEvent(event)

        # Qt/Explorer may rewrite the window icon during first show. Apply the
        # native icon more than once after HWND creation, without visible UI
        # changes or blocking the event loop.
        QTimer.singleShot(0, self._apply_native_windows_icon)
        QTimer.singleShot(150, self._apply_native_windows_icon)
        QTimer.singleShot(700, self._apply_native_windows_icon)

    def closeEvent(self,event):
        if (
            not self._force_quit
            and self.settings.close_to_tray
            and QSystemTrayIcon.isSystemTrayAvailable()
        ):
            event.ignore()
            self.hide()
            if not self._tray_notice_shown:
                self._tray_notice_shown=True
                self._notify(
                    "BC Sentinel resta attivo",
                    "La finestra è stata chiusa, ma la protezione continua nella tray.",
                    "info",
                )
            return
        self._shutdown_services()
        event.accept()

    def _shutdown_services(self):
        if hasattr(self, "telemetry_poller"):
            self.telemetry_poller.stop()
            self.telemetry_poller.wait(1500)
        self.realtime.stop()
        self.procmon.stop()
        self.etw.stop()
        self.persistence.stop()
        self.network_monitor.stop()
        self.network_running=False
        if hasattr(self, "process_identity"):
            self.process_identity.shutdown(wait=False)

    def exit_application(self):
        self._force_quit=True
        self._shutdown_services()
        if hasattr(self,"tray"):self.tray.hide()
        QApplication.instance().quit()

    def _setup_tray(self):
        asset=APP_ROOT/"app"/"assets"/"bc_sentinel_icon.png"
        icon=QIcon(str(asset)) if asset.exists() else self.windowIcon()
        self.tray=QSystemTrayIcon(icon,self)
        self.tray.setToolTip(f"BC Sentinel {APP_VERSION}")
        menu=QMenu(self)
        open_action=QAction("Apri BC Sentinel",self); open_action.triggered.connect(self.show_from_tray)
        quick_action=QAction("Scansione rapida",self); quick_action.triggered.connect(self.quick_scan)
        protection_action=QAction("Protezione",self); protection_action.triggered.connect(lambda:self.show_page_from_tray(5))
        exit_action=QAction("Esci completamente",self); exit_action.triggered.connect(self.exit_application)
        menu.addAction(open_action); menu.addAction(quick_action); menu.addAction(protection_action)
        menu.addSeparator(); menu.addAction(exit_action)
        self.tray.setContextMenu(menu); self.tray.activated.connect(self._tray_activated); self.tray.show()

    def _tray_activated(self,reason):
        if reason in (QSystemTrayIcon.Trigger,QSystemTrayIcon.DoubleClick):
            self.show_from_tray()

    def show_from_tray(self):
        self.show(); self.showNormal(); self.raise_(); self.activateWindow()

    def show_page_from_tray(self,idx):
        self.show_from_tray(); self.nav_to(idx)

    def _tray_fallback_message(self,title,message,level):
        icon=QSystemTrayIcon.Information
        if level in {"warning","high"}:icon=QSystemTrayIcon.Warning
        elif level in {"critical","danger"}:icon=QSystemTrayIcon.Critical
        self.tray.showMessage(title,message,icon,6000)

    def _notify(self,title,message,level="info"):
        if self.settings.notifications_enabled and hasattr(self,"notifier"):
            self.notifier.notify(title,message,level=level)


    def resizeEvent(self, event):
        super().resizeEvent(event)

        # Keep tables readable at laptop resolutions and Windows DPI scaling.
        width = self.width()
        compact = width < 1120
        # Below ~980px, collapse navigation to protect the content canvas from
        # clipping at 125–150% Windows scaling while preserving every route.
        compact_nav = width < 980

        if hasattr(self, "sidebar") and hasattr(self, "nav_buttons"):
            self.sidebar.setFixedWidth(76 if compact_nav else 212)
            for i, button in enumerate(self.nav_buttons):
                label, icon = self.NAV[i]
                button.setText(icon if compact_nav else f"{icon}   {label}")
                button.setToolTip(label if compact_nav else "")
                button.setStyleSheet(
                    "font-size:18px;" if compact_nav else "font-size:13px;"
                )

        if hasattr(self, "footer_version"):
            self.footer_version.setVisible(self.height() >= 570 and not compact_nav)

        if hasattr(self, "qtable"):
            # Keep the short file name visible; the long full path is the first
            # column sacrificed on constrained canvases and remains available
            # through Dettagli.
            self.qtable.setColumnHidden(1, compact)
        if hasattr(self, "htable"):
            self.htable.setColumnHidden(0, width < 980)
        if hasattr(self, "activity_table"):
            self.activity_table.setColumnHidden(2, compact)
            self.activity_table.setColumnHidden(3, width < 980)


    # ---------- shared widgets ----------
    def card(self, name="card"):
        f = QFrame(); f.setObjectName(name); return f

    def muted(self, text):
        l = QLabel(text)
        l.setProperty("role", "bodyMuted")
        l.setWordWrap(True)
        return l

    def _set_role(self, label, role):
        label.setProperty("role", role)
        return label

    def _set_badge_tone(self, badge, tone):
        previous=badge.property("tone")
        badge.setObjectName("statusBadge")
        badge.setProperty("tone", tone)
        badge.style().unpolish(badge)
        badge.style().polish(badge)
        badge.update()
        if previous is not None and previous != tone:
            self._micro_fade(badge, MOTION["fast"], 0.55)

    def _set_scan_state(self, state):
        if not hasattr(self, "scan_panel"):
            return
        self.scan_panel.setProperty("state", state)
        self.scan_panel.style().unpolish(self.scan_panel)
        self.scan_panel.style().polish(self.scan_panel)
        self.scan_panel.update()

    def _set_inline_tone(self, label, tone):
        label.setObjectName("inlineStatus")
        label.setProperty("tone", tone)
        label.style().unpolish(label)
        label.style().polish(label)
        label.update()

    def _apply_elevation(self, widget):
        # One restrained hero shadow only: avoids expensive effect stacking on
        # scrolling cards/tables while still separating the primary status plane.
        effect=QGraphicsDropShadowEffect(widget)
        effect.setBlurRadius(ELEVATION["hero_blur"])
        effect.setOffset(0, ELEVATION["hero_y"])
        shadow=QColor(C["shadow"]); shadow.setAlpha(ELEVATION["hero_alpha"])
        effect.setColor(shadow)
        widget.setGraphicsEffect(effect)
        return effect

    def _sidebar(self):
        bar = QFrame()
        bar.setObjectName("sidebar")
        bar.setFixedWidth(212)

        v = QVBoxLayout(bar)
        v.setContentsMargins(14, 18, 14, SPACING["md"])
        v.setSpacing(SPACING["sm"] - 2)

        brand = QHBoxLayout()
        asset = APP_ROOT / "app" / "assets" / "bc_sentinel_icon.png"
        logo = QLabel()
        logo.setFixedSize(ICON_SIZE["brand"], ICON_SIZE["brand"])
        if asset.exists():
            pm = QPixmap(str(asset)).scaled(
                38,38,Qt.KeepAspectRatio,Qt.SmoothTransformation
            )
            logo.setPixmap(pm)

        name = QLabel("BC Sentinel")
        name.setStyleSheet(
            f"font-size:18px;font-weight:750;color:{C['primary']};"
        )
        brand.addWidget(logo)
        brand.addWidget(name)
        brand.addStretch()
        v.addLayout(brand)
        v.addSpacing(16)

        self.nav_buttons=[]
        # Tutte le voci, inclusa Impostazioni, usano lo stesso componente nav.
        for i,(label,icon) in enumerate(self.NAV):
            b = QPushButton(f"{icon}   {label}")
            b.setObjectName("nav")
            b.setCursor(Qt.PointingHandCursor)
            b.setMinimumHeight(42)
            b.setStyleSheet("font-size:13px;")
            b.clicked.connect(lambda checked=False, idx=i: self.nav_to(idx))
            self.nav_buttons.append(b)
            v.addWidget(b)

        v.addStretch()

        self.footer_version = QLabel(f"v{APP_VERSION}  ·  MVP")
        self.footer_version.setObjectName("footerLabel")
        self.footer_version.setMinimumHeight(24)
        self.footer_version.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        v.addWidget(self.footer_version)
        return bar

    def nav_to(self, idx):
        titles = [
            ("Dashboard","Stato e attività principali di BC Sentinel"),
            ("Scansione","Analizza file e cartelle con il motore locale"),
            ("Quarantena","Gestisci in sicurezza gli elementi isolati"),
            ("Cronologia","Stato corrente dei rilevamenti"),
            ("Attività","Timeline processo → file → comportamento"),
            ("Protezione","Moduli user-space e telemetria avanzata"),
            ("Impostazioni","Configura protezione, telemetria ed esclusioni"),
        ]
        self.pages.fade_to(idx)
        self.page_title.setText(titles[idx][0])
        self.page_subtitle.setText(titles[idx][1])
        self._micro_fade(self.page_title,170,0.35)
        self._micro_fade(self.page_subtitle,210,0.28)

        for i,b in enumerate(self.nav_buttons):
            b.setObjectName("navActive" if i==idx else "nav")
            b.style().unpolish(b)
            b.style().polish(b)

        self._stagger_page_cards(self.pages.widget(idx))

        if idx==0:
            self.refresh_dashboard()
        elif idx==2:
            self.refresh_quarantine()
        elif idx==3:
            self.refresh_history()
        elif idx==4:
            self.refresh_activity()
        elif idx==5:
            self.refresh_protection()
        elif idx==6:
            self.refresh_settings_lists()

    def _micro_fade(self,widget,duration=190,start=0.35):
        if not self.animations_enabled or widget is None:
            return
        effect=QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        effect.setOpacity(float(start))
        anim=QPropertyAnimation(effect,b"opacity",self)
        anim.setDuration(int(duration))
        anim.setStartValue(float(start))
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.finished.connect(lambda w=widget:w.setGraphicsEffect(None))
        if not hasattr(self,"_micro_animations"):
            self._micro_animations=[]
        self._micro_animations.append(anim)
        anim.finished.connect(lambda a=anim:self._micro_animations.remove(a) if a in self._micro_animations else None)
        anim.start()

    def _stagger_page_cards(self, page):
        if not self.animations_enabled or page is None:
            return
        cards=[
            frame for frame in page.findChildren(QFrame)
            if frame.objectName() in {"hero", "card", "scanPanel"}
        ][:4]
        for i, card in enumerate(cards):
            QTimer.singleShot(
                90 + i * 34,
                lambda c=card: self._micro_fade(c, MOTION["base"], 0.68)
                if c.isVisible() else None,
            )

    def metric_card(self, title, value="—", hint=""):
        f=self.card(); v=QVBoxLayout(f); v.setContentsMargins(17,15,17,15); v.setSpacing(4)
        t=self._set_role(QLabel(title.upper()), "eyebrow")
        val=self._set_role(MetricValueLabel(value), "metricValue")
        h=self._set_role(QLabel(hint), "caption")
        v.addWidget(t); v.addWidget(val); v.addWidget(h)
        return f,val

    def status_badge(self, text, active=True):
        l=QLabel(text); l.setAlignment(Qt.AlignCenter); l.setMinimumWidth(76)
        self._set_badge_tone(l, "safe" if active else "inactive")
        return l

    # ---------- dashboard ----------
    def _dashboard_page(self):
        scroll=QScrollArea(); scroll.setWidgetResizable(True)
        body=QWidget(); v=QVBoxLayout(body); v.setContentsMargins(0,0,0,8); v.setSpacing(15)

        hero=self.card("hero"); self._dashboard_hero_shadow=self._apply_elevation(hero)
        hv=QHBoxLayout(hero); hv.setContentsMargins(22,20,22,20); hv.setSpacing(18)
        asset=APP_ROOT/"app/assets/bc_sentinel_icon.png"; icon=QLabel(); icon.setFixedSize(ICON_SIZE["hero"], ICON_SIZE["hero"])
        if asset.exists(): icon.setPixmap(QPixmap(str(asset)).scaled(68,68,Qt.KeepAspectRatio,Qt.SmoothTransformation))
        txt=QVBoxLayout(); title=self._set_role(QLabel("BC Sentinel è attivo"), "heroTitle")
        live_row=QHBoxLayout(); self.status_pulse=PulseDot()
        live=QLabel("Monitoraggio del sistema in corso"); live.setStyleSheet(f"color:{C['safe']};font-size:14px;font-weight:650;")
        live_row.addWidget(self.status_pulse); live_row.addWidget(live); live_row.addStretch()
        desc=self._set_role(QLabel("Protezione user-space attiva"), "bodyMuted")
        self.telemetry_badge_dashboard=QLabel("")
        self.telemetry_badge_dashboard.setMaximumWidth(250)
        txt.addWidget(title)
        txt.addLayout(live_row)
        txt.addWidget(desc)
        txt.addWidget(self.telemetry_badge_dashboard,0,Qt.AlignLeft)
        actions=QVBoxLayout()
        self.dashboard_quick_scan_btn=QPushButton("Scansione rapida")
        self.dashboard_quick_scan_btn.setObjectName("primary")
        self.dashboard_quick_scan_btn.clicked.connect(self.quick_scan)
        self.dashboard_full_scan_btn=QPushButton("Scansione completa")
        self.dashboard_full_scan_btn.clicked.connect(self.full_scan)
        self.scan_action_buttons=[
            self.dashboard_quick_scan_btn,
            self.dashboard_full_scan_btn,
        ]
        actions.addWidget(self.dashboard_quick_scan_btn)
        actions.addWidget(self.dashboard_full_scan_btn)
        hv.addWidget(icon); hv.addLayout(txt); hv.addStretch(); hv.addLayout(actions)
        v.addWidget(hero)

        stats=QHBoxLayout(); a,self.stat_last=self.metric_card("Ultima scansione","Mai","persistente"); b,self.stat_detect=self.metric_card("Rilevamenti attivi","0","score ≥ 50"); c,self.stat_quarantine=self.metric_card("File in quarantena","0","isolati localmente")
        stats.addWidget(a); stats.addWidget(b); stats.addWidget(c); v.addLayout(stats)

        protection=self.card(); pv=QVBoxLayout(protection); pv.setContentsMargins(18,16,18,16); pv.setSpacing(10)
        head=QHBoxLayout(); h=self._set_role(QLabel("Moduli protezione"), "sectionTitle"); head.addWidget(h); head.addStretch(); manage=QPushButton("Gestisci"); manage.clicked.connect(lambda:self.nav_to(5)); head.addWidget(manage); pv.addLayout(head)
        self.dashboard_module_states={}
        modules=[
            ("Protezione real-time","Monitora nuovi file e script nelle cartelle protette.","realtime"),
            ("Ransomware Shield","Rileva pattern di modifica massiva e attività anomale sui file.","ransomware"),
            ("Behavior Shield","Analizza processi e sequenze di comportamento sospette.","behavior"),
            ("AI Security Analyst (Beta)","Spiega localmente i rilevamenti in linguaggio semplice.","ai"),
        ]
        grid=QHBoxLayout(); left=QVBoxLayout(); right=QVBoxLayout()
        for i,(name,desc,key) in enumerate(modules):
            f=self.card("softCard"); r=QHBoxLayout(f); r.setContentsMargins(14,12,14,12)
            texts=QVBoxLayout(); n=self._set_role(QLabel(name), "subsectionTitle"); d=self._set_role(QLabel(desc), "caption"); d.setWordWrap(True); texts.addWidget(n); texts.addWidget(d)
            badge=self.status_badge("Attivo" if key!="ai" else "Beta", key!="ai"); self.dashboard_module_states[key]=badge
            r.addLayout(texts,1); r.addWidget(badge)
            (left if i%2==0 else right).addWidget(f)
        grid.addLayout(left,1); grid.addLayout(right,1); pv.addLayout(grid); v.addWidget(protection)
        v.addStretch(); scroll.setWidget(body); return scroll

    # ---------- scan ----------
    def _scan_page(self):
        body=QWidget()
        v=QVBoxLayout(body)
        v.setContentsMargins(0,0,0,0)
        v.setSpacing(15)

        choices=QHBoxLayout()
        self.scan_quick_btn=QPushButton("Scansione rapida")
        self.scan_quick_btn.setObjectName("primary")
        self.scan_quick_btn.clicked.connect(self.quick_scan)
        self.scan_full_btn=QPushButton("Scegli cartella…")
        self.scan_full_btn.clicked.connect(self.full_scan)
        choices.addWidget(self.scan_quick_btn)
        choices.addWidget(self.scan_full_btn)
        choices.addStretch()
        v.addLayout(choices)
        self.scan_action_buttons.extend([self.scan_quick_btn,self.scan_full_btn])

        self.scan_panel=self.card("scanPanel")
        self.scan_panel.setProperty("state", "idle")
        panel=self.scan_panel
        pv=QVBoxLayout(panel)
        pv.setContentsMargins(24,22,24,22)
        pv.setSpacing(11)

        scan_head=QHBoxLayout()
        self.scan_indicator=ScanActivityIndicator()
        self.scan_status=QLabel("Pronto per la scansione")
        self.scan_status.setProperty("role", "scanStatus")
        scan_head.addWidget(self.scan_indicator,0,Qt.AlignVCenter)
        scan_head.addWidget(self.scan_status,1)

        self.scan_desc=QLabel("Analizza i file nelle aree principali del sistema.")
        self.scan_desc.setProperty("role", "bodyMuted")
        self.scan_progress=QProgressBar()
        self.scan_progress.setRange(0,100)
        self.scan_progress.setValue(0)
        self.scan_progress.setFormat("0%")

        row=QHBoxLayout()
        self.scan_count=QLabel("0 / 0 file")
        self.scan_count.setStyleSheet("font-weight:600;")
        self.scan_hits=QLabel("0 elementi rilevati")
        self.scan_hits.setProperty("role", "bodyMuted")
        row.addWidget(self.scan_count)
        row.addStretch()
        row.addWidget(self.scan_hits)

        self.scan_current=QLabel("—")
        self.scan_current.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.scan_current.setStyleSheet(f"background:{C['surface_low']};border:1px solid {C['border_soft']};border-radius:8px;padding:10px;color:{C['muted']};")

        bottom=QHBoxLayout()
        self.scan_elapsed=QLabel("Tempo trascorso: 00:00.0")
        self.scan_elapsed.setProperty("role", "caption")
        self.cancel_scan_btn=QPushButton("Annulla scansione")
        self.cancel_scan_btn.setObjectName("danger")
        self.cancel_scan_btn.clicked.connect(self.cancel_scan)
        self.cancel_scan_btn.hide()
        bottom.addWidget(self.scan_elapsed)
        bottom.addStretch()
        bottom.addWidget(self.cancel_scan_btn)

        pv.addLayout(scan_head)
        pv.addWidget(self.scan_desc)
        pv.addWidget(self.scan_progress)
        pv.addLayout(row)
        pv.addWidget(self.scan_current)
        pv.addLayout(bottom)
        v.addWidget(panel)
        v.addStretch()

        self.scan_ui_timer=QTimer(self)
        self.scan_ui_timer.setInterval(100)
        self.scan_ui_timer.timeout.connect(self._tick_scan_clock)
        self._scan_progress_animation=None
        self._scan_prepare_phase=0
        self._scan_has_progress=False
        return body

    def _apply_network_intelligence(self,event):
        if event.category != "network" or not self.settings.network_enabled:
            return event
        data=dict(event.data or {})
        if data.get("endpoint_indicator"):
            return event
        try:
            result=self.network_intelligence.assess_event(event)
            event.score=min(100,int(event.score or 0)+int(result.score_delta or 0))
            event.reasons=list(dict.fromkeys((event.reasons or [])+(result.reasons or [])))
            data.update({
                "endpoint_indicator":result.indicator,
                "endpoint_kind":result.kind,
                "endpoint_class":result.address_class,
                "endpoint_status":result.status,
                "endpoint_source":result.source,
                "endpoint_confidence":result.confidence,
                "endpoint_first_seen":result.first_seen,
                "endpoint_connection_count":result.connection_count,
                "endpoint_process_count":result.process_count,
            })
            event.data=data
        except Exception:
            pass
        return event

    def _apply_incident_correlation(self,event,correlation=None,ancestry=None):
        try:
            incident=self.incident_engine.ingest(
                event,
                correlation=correlation,
                ancestry=ancestry or [],
            )
        except Exception:
            incident=None
        if incident is None:
            return None
        event.data=dict(event.data or {})
        event.data.update({
            "incident_id":incident.incident_id,
            "incident_score":incident.score,
            "incident_level":incident.level,
            "incident_confidence":incident.confidence,
            "incident_status":incident.status,
            "incident_suppressed":incident.suppressed,
            "incident_categories":list(incident.categories),
            "incident_reasons":list(incident.reasons),
            "incident_recommended_actions":list(incident.recommended_actions),
        })
        return incident

    def on_security_event(self,event):
        try:
            if event.category=="network" and not self.settings.network_enabled:
                return
            self._apply_network_intelligence(event)
            if not self.event_deduplicator.allow(event):
                return

            ancestry=[]
            if event.pid:
                ancestry=self.process_tree.ancestry(
                    int(event.pid),
                    max_depth=8,
                )

            correlation=self.correlation_engine.assess(
                event,
                ancestry=ancestry,
            )

            if correlation.reasons:
                event.data=dict(event.data or {})
                event.data.update({
                    "correlation_score_delta":correlation.score_delta,
                    "correlation_confidence":correlation.confidence,
                    "correlation_severity":correlation.severity,
                    "correlation_stages":correlation.stages,
                    "correlation_evidence_families":correlation.evidence_families,
                    "correlation_sequence":correlation.sequence,
                    "correlation_incident_id":correlation.incident_id,
                    "correlation_total_score":correlation.total_score,
                })
                if correlation.chain:
                    event.data["chain"]=correlation.chain

                self.db.record_correlation_event(
                    category="behavioral_correlation_v2",
                    source_event_category=event.category,
                    source_event_action=event.action,
                    pid=event.pid,
                    process_name=event.process_name,
                    score_delta=correlation.score_delta,
                    confidence=correlation.confidence,
                    chain=correlation.chain,
                    reasons=correlation.reasons,
                    data={
                        "path":event.path,
                        "severity":correlation.severity,
                        "stages":correlation.stages,
                        "evidence_families":correlation.evidence_families,
                        "sequence":correlation.sequence,
                        "incident_id":correlation.incident_id,
                        "total_score":correlation.total_score,
                    },
                )

            # Service-processed events carry the canonical incident id. Keep
            # the local presentation database in sync without inventing a
            # second incident identity.
            if (event.data or {}).get("service_processed") and (event.data or {}).get("incident_id"):
                correlation.incident_id = str(event.data.get("incident_id"))

            self._apply_incident_correlation(
                event,
                correlation=correlation,
                ancestry=ancestry,
            )

            if event.category=="network":
                self.db.record_network_event(event)

            self.db.record_security_event(event)
            event_log(
                f"{event.category}:{event.action}",
                event="security_event",
                category=event.category,
                path=event.path,
                pid=event.pid,
                score=event.score,
                source=event.source,
            )
        except Exception:
            pass

    def on_persistence_event(self,event):
        # Route local persistence telemetry through the same v2 correlation
        # pipeline used by process/file/network events. The old path persisted
        # it directly, which meant local fallback mode could miss multi-stage
        # persistence convergence.
        self.on_security_event(event)
        self.persistence_report.emit(event)

    def _handle_persistence_event(self,event):
        if event.score>=25:
            self._notify("Modifica avvio automatico rilevata",event.reasons[0] if event.reasons else event.path,"warning")

    # ---------- privileged telemetry service ----------
    def _service_owns_protection(self, status=None):
        status = self.telemetry_service_status if status is None else status
        return bool(
            status
            and status.get("health") in {"HEALTHY", "DEGRADED"}
            and status.get("protection_enabled", True)
        )

    def _telemetry_status_changed(self,status):
        self.telemetry_service_status=status
        service_owns=self._service_owns_protection(status)

        if service_owns:
            # The service is canonical. Tear down any GUI fallback engines that
            # may have started while the service was unavailable.
            try:self.realtime.stop()
            except Exception:pass
            try:self.procmon.stop()
            except Exception:pass
            try:self.persistence.stop()
            except Exception:pass
            try:self.network_monitor.stop()
            except Exception:pass

            self.realtime_running=bool(status.get("realtime"))
            self.telemetry_advanced_active=bool(
                self.settings.etw_enabled and status.get("etw",{}).get("running")
            )
            self.etw_running=self.telemetry_advanced_active
            self.persistence_running=bool(status.get("persistence"))
            self.network_running=bool(status.get("network"))
        else:
            # Fail visibly but keep deterministic local user-space fallback
            # when the privileged service is unavailable.
            self.telemetry_advanced_active=False
            self.etw_running=False
            if self.settings.realtime_enabled and not self.realtime_running:
                self.realtime_running=bool(self.realtime.start())
            if self.settings.behavior_enabled:
                self.procmon.start()
            else:
                self.procmon.stop()
            if self.settings.persistence_enabled:
                if not (self.persistence._thread and self.persistence._thread.is_alive()):
                    self.persistence_running=bool(self.persistence.start())
            else:
                self.persistence.stop(); self.persistence_running=False
            if self.settings.network_enabled:
                self.network_running=bool(self.network_monitor.start())
            else:
                self.network_monitor.stop(); self.network_running=False

        self._refresh_telemetry_visual_state()
        self.refresh_protection()
        if hasattr(self,"activity_table") and self.pages.currentIndex()==4:
            self.refresh_activity()

    def _refresh_telemetry_visual_state(self):
        advanced=self.telemetry_advanced_active
        hardening = (self.telemetry_service_status or {}).get("hardening") or {}
        hardening_bad = bool(hardening) and not bool(hardening.get("ok", True))

        if hasattr(self,"telemetry_badge_dashboard"):
            if advanced and hardening_bad:
                self.telemetry_badge_dashboard.setText(
                    "  Protection Service degradato · verifica integrità  "
                )
                self._set_badge_tone(self.telemetry_badge_dashboard, "warning")
            elif advanced:
                self.telemetry_badge_dashboard.setText(
                    "  Telemetria avanzata attiva  "
                )
                self._set_badge_tone(self.telemetry_badge_dashboard, "safe")
            else:
                self.telemetry_badge_dashboard.setText(
                    "  Fallback locale attivo  "
                )
                self._set_badge_tone(self.telemetry_badge_dashboard, "warning")

        if hasattr(self,"etw_status"):
            if advanced and hardening_bad:
                issues = hardening.get("issues") or []
                detail = str(issues[0]) if issues else "integrità/ACL/SCM da verificare"
                self.etw_status.setText(
                    "Protection Service attivo ma degradato · " + detail
                )
                self._set_inline_tone(self.etw_status, "warning")
            elif advanced:
                self.etw_status.setText(
                    "Telemetria avanzata attiva · ETW privilegiato "
                    "tramite BC Sentinel Protection Service."
                )
                self._set_inline_tone(self.etw_status, "safe")
            else:
                installed=self.telemetry_client.service_installed()
                text=(
                    "Fallback locale attivo · il servizio è installato "
                    "ma non ancora raggiungibile."
                    if installed else
                    "Fallback locale attivo · installa una volta il "
                    "Protection Service per usare ETW senza avviare "
                    "la UI come amministratore."
                )
                self.etw_status.setText(text)
                self._set_inline_tone(self.etw_status, "warning")

        if hasattr(self,"telemetry_install_btn"):
            self.telemetry_install_btn.setText(
                "Ripara Protection Service"
                if self.telemetry_client.service_installed()
                else "Installa Protection Service"
            )

    def install_telemetry_service(self):
        if not self.telemetry_client.launch_installer(False):
            QMessageBox.warning(
                self,
                "Protection Service",
                self.telemetry_client.last_error
                or "Impossibile avviare l'installazione elevata.",
            )
            return

        QMessageBox.information(
            self,
            "Protection Service",
            "Windows mostrerà una richiesta UAC per l'installazione "
            "una tantum. La UI resterà poi a privilegi normali.",
        )

    def _consume_telemetry_events(self,events):
        changed=False
        security_batch=[]
        correlation_batch=[]
        for raw in events:
            try:
                category=str(raw.get("category") or "unknown")
                action=str(raw.get("action") or "event")
                pid=raw.get("pid")
                ppid=raw.get("ppid")
                process_name=str(raw.get("process_name") or "")
                process_path=str(raw.get("process_path") or "")
                path=str(raw.get("path") or "")
                reasons=list(raw.get("reasons") or [])
                data=dict(raw.get("data") or {})

                if category=="process" and action=="start" and pid:
                    self.process_tree.observe(
                        int(pid),
                        int(ppid or 0),
                        process_name,
                        process_path,
                        cmdline=str(data.get("cmdline") or ""),
                        risk_score=int(raw.get("score") or 0),
                        reasons=reasons,
                    )
                elif category=="file" and path:
                    self.correlator.record(
                        path,
                        int(pid) if pid else None,
                        process_name,
                        process_path,
                        action,
                        float(raw.get("ts") or time.time()),
                    )

                event=SecurityEvent(
                    category=category,
                    action=action,
                    source="telemetry_service",
                    score=int(raw.get("score") or 0),
                    path=path,
                    pid=int(pid) if pid else None,
                    ppid=int(ppid) if ppid else None,
                    process_name=process_name,
                    process_path=process_path,
                    reasons=reasons,
                    data=data,
                    ts=float(raw.get("ts") or time.time()),
                )

                if category=="network" and not self.settings.network_enabled:
                    continue
                self._apply_network_intelligence(event)

                if not self.event_deduplicator.allow(event):
                    continue

                if category == "firewall" and action in {"rule_drift_detected", "policy_conflict_detected"}:
                    self._notify(
                        "Protezione firewall modificata",
                        reasons[0] if reasons else "BC Sentinel richiede una verifica del firewall.",
                        "warning",
                    )
                    dialog = FirewallAlertDialog(event, self)
                    if dialog.exec() == QDialog.Accepted:
                        self.nav_to(5)
                if category == "web" and int(event.score or 0) >= 70:
                    self._notify(
                        "Web Protection · dominio ad alto rischio",
                        reasons[0] if reasons else (path or "Dominio IOC rilevato"),
                        "warning",
                    )

                ancestry=[]
                if event.pid:
                    ancestry=self.process_tree.ancestry(
                        int(event.pid),
                        max_depth=8,
                    )

                correlation=self.correlation_engine.assess(
                    event,
                    ancestry=ancestry,
                )

                if correlation.reasons:
                    event.data.update({
                        "correlation_score_delta":correlation.score_delta,
                        "correlation_confidence":correlation.confidence,
                        "correlation_severity":correlation.severity,
                        "correlation_stages":correlation.stages,
                        "correlation_evidence_families":correlation.evidence_families,
                        "correlation_sequence":correlation.sequence,
                        "correlation_incident_id":correlation.incident_id,
                        "correlation_total_score":correlation.total_score,
                    })
                    if correlation.chain:
                        event.data["chain"]=correlation.chain

                    correlation_batch.append({
                        "category":"behavioral_correlation_v2",
                        "source_event_category":event.category,
                        "source_event_action":event.action,
                        "pid":event.pid,
                        "process_name":event.process_name,
                        "score_delta":correlation.score_delta,
                        "confidence":correlation.confidence,
                        "chain":correlation.chain,
                        "reasons":correlation.reasons,
                        "data":{
                            "path":event.path,
                            "severity":correlation.severity,
                            "stages":correlation.stages,
                            "evidence_families":correlation.evidence_families,
                            "sequence":correlation.sequence,
                            "incident_id":correlation.incident_id,
                            "total_score":correlation.total_score,
                        },
                    })

                self._apply_incident_correlation(
                    event,
                    correlation=correlation,
                    ancestry=ancestry,
                )

                security_batch.append(event)
                changed=True

                if (
                    category=="persistence"
                    and max(event.score,correlation.score_delta)>=30
                ):
                    message=(
                        correlation.reasons[0]
                        if correlation.reasons
                        else (reasons[0] if reasons else path)
                    )
                    self._notify(
                        "Modifica avvio automatico rilevata",
                        message,
                        "warning",
                    )
            except Exception:
                continue

        if security_batch or correlation_batch:
            try:
                self.db.record_telemetry_batch(security_batch,correlation_batch)
            except Exception:
                # Preserve telemetry continuity if one batch write fails; the
                # in-memory service buffer remains authoritative for the next poll.
                pass

        if changed and hasattr(self,"activity_table"):
            if self.pages.currentIndex()==4:
                self.refresh_activity()
                self._animate_activity_update()

    def _attribution_for_path(self,path):
        if self.telemetry_advanced_active:
            raw=self.telemetry_client.attribute(path)
            if raw:
                return ProcessAttribution(
                    pid=raw.get("pid"),
                    ppid=raw.get("ppid"),
                    name=raw.get("name") or "",
                    path=raw.get("path") or "",
                    cmdline=raw.get("cmdline") or "",
                    sha256=raw.get("sha256") or "",
                    signature_status=raw.get("signature_status") or "",
                    signer=raw.get("signer") or "",
                    create_time=float(raw.get("create_time") or 0.0),
                    source=raw.get("source") or "telemetry_service",
                    confidence=float(raw.get("confidence") or 0.0),
                    observed_ts=float(raw.get("observed_ts") or 0.0),
                )
        return self.correlator.attribute(path,max_age=5.0)

    # ---------- quarantine ----------
    def _quarantine_page(self):
        body=QWidget(); v=QVBoxLayout(body); v.setContentsMargins(0,0,0,0); v.setSpacing(12)
        info=self.muted("I file in quarantena sono cifrati e isolati. Il ripristino richiede una conferma esplicita."); v.addWidget(info)
        self.qtabs=QTabWidget(); active=QWidget(); av=QVBoxLayout(active); restored=QWidget(); rv=QVBoxLayout(restored)
        self.q_empty=self._set_role(QLabel("Nessun elemento in quarantena."), "empty"); av.addWidget(self.q_empty)
        self.qtable=QTableWidget(0,5); self._setup_table(self.qtable,["File","Percorso","Rischio","Motivo","Stato"],[0,1,3]); av.addWidget(self.qtable)
        ar=QHBoxLayout(); restore=QPushButton("Ripristina"); restore.clicked.connect(self.restore_selected); detail=QPushButton("Dettagli"); detail.clicked.connect(self.quarantine_details); delete=QPushButton("Elimina definitivamente"); delete.setObjectName("danger"); delete.clicked.connect(self.delete_selected); ar.addWidget(restore); ar.addWidget(detail); ar.addStretch(); ar.addWidget(delete); av.addLayout(ar)
        self.r_empty=self._set_role(QLabel("Nessun elemento ripristinato."), "empty"); rv.addWidget(self.r_empty)
        self.rtable=QTableWidget(0,4); self._setup_table(self.rtable,["Data","File originale","Rischio","Motivo"],[1,3]); rv.addWidget(self.rtable)
        self.qtabs.addTab(active,"In quarantena"); self.qtabs.addTab(restored,"Ripristinati"); v.addWidget(self.qtabs,1); return body

    # ---------- history ----------
    def _history_page(self):
        body=QWidget(); v=QVBoxLayout(body); v.setContentsMargins(0,0,0,0); v.setSpacing(12)

        inbox=self.card()
        iv=QVBoxLayout(inbox); iv.setContentsMargins(16,14,16,14); iv.setSpacing(9)
        ih=QHBoxLayout()
        it=QVBoxLayout()
        inbox_title=QLabel("Security Center Inbox"); inbox_title.setProperty("role", "sectionTitle")
        self.security_inbox_summary=QLabel("Nessuna minaccia in attesa di decisione."); self.security_inbox_summary.setProperty("role", "bodyMuted")
        it.addWidget(inbox_title); it.addWidget(self.security_inbox_summary)
        self.security_inbox_badge=self.status_badge("0 da decidere", True)
        ih.addLayout(it,1); ih.addWidget(self.security_inbox_badge)
        iv.addLayout(ih)
        self.security_inbox_empty=self._set_role(QLabel("Le minacce HIGH/CRITICAL chiuse senza scelta resteranno qui."), "empty")
        iv.addWidget(self.security_inbox_empty)
        self.security_inbox_table=QTableWidget(0,4)
        self._setup_table(self.security_inbox_table,["File","Score","Livello","Origine"],[0])
        self.security_inbox_table.setMaximumHeight(210)
        self.security_inbox_table.itemSelectionChanged.connect(self._security_inbox_selection_changed)
        self.security_inbox_table.itemDoubleClicked.connect(lambda *_: self._review_pending_threat())
        iv.addWidget(self.security_inbox_table)
        inbox_actions=QHBoxLayout(); inbox_actions.addStretch()
        self.security_inbox_review=QPushButton("Gestisci minaccia")
        self.security_inbox_review.setObjectName("primary")
        self.security_inbox_review.setEnabled(False)
        self.security_inbox_review.clicked.connect(self._review_pending_threat)
        inbox_actions.addWidget(self.security_inbox_review)
        iv.addLayout(inbox_actions)
        v.addWidget(inbox)

        web=self.card()
        wv=QVBoxLayout(web); wv.setContentsMargins(16,14,16,14); wv.setSpacing(9)
        wh=QHBoxLayout(); wt=QVBoxLayout()
        web_title=QLabel("Web Protection Center"); web_title.setProperty("role", "sectionTitle")
        self.web_center_summary=QLabel("DNS per-processo, anti-phishing e containment web reversibile."); self.web_center_summary.setProperty("role", "bodyMuted")
        wt.addWidget(web_title); wt.addWidget(self.web_center_summary)
        self.web_center_badge=self.status_badge("Active reversible", True)
        wh.addLayout(wt,1); wh.addWidget(self.web_center_badge); wv.addLayout(wh)
        url_row=QHBoxLayout()
        self.web_url_input=QLineEdit(); self.web_url_input.setPlaceholderText("Analizza dominio o URL, es. example.com")
        self.web_url_check=QPushButton("Analizza URL"); self.web_url_check.clicked.connect(self._analyze_web_url)
        url_row.addWidget(self.web_url_input,1); url_row.addWidget(self.web_url_check); wv.addLayout(url_row)
        self.web_findings_empty=self._set_role(QLabel("Nessun evento web rilevante registrato."), "empty"); wv.addWidget(self.web_findings_empty)
        self.web_findings_table=QTableWidget(0,5)
        self._setup_table(self.web_findings_table,["Dominio","Score","Verdetto","Processo","Stato"],[0,3])
        self.web_findings_table.setMaximumHeight(210)
        self.web_findings_table.itemSelectionChanged.connect(self._web_finding_selection_changed)
        self.web_findings_table.itemDoubleClicked.connect(lambda *_: self._block_selected_web_finding())
        wv.addWidget(self.web_findings_table)
        web_actions=QHBoxLayout(); web_actions.addStretch()
        self.web_details=QPushButton("Dettagli dominio"); self.web_details.setEnabled(False); self.web_details.clicked.connect(self._show_selected_web_domain_details)
        self.web_ignore_once=QPushButton("Ignora una volta"); self.web_ignore_once.setEnabled(False); self.web_ignore_once.clicked.connect(self._ignore_selected_web_finding)
        self.web_trust_domain=QPushButton("Consenti dominio"); self.web_trust_domain.setEnabled(False); self.web_trust_domain.clicked.connect(self._trust_selected_web_domain)
        self.web_block_15m=QPushButton("Blocca 15 min"); self.web_block_15m.setObjectName("primary"); self.web_block_15m.setEnabled(False); self.web_block_15m.clicked.connect(self._block_selected_web_finding)
        web_actions.addWidget(self.web_details); web_actions.addWidget(self.web_ignore_once); web_actions.addWidget(self.web_trust_domain); web_actions.addWidget(self.web_block_15m); wv.addLayout(web_actions)

        trust_title=QLabel("Domini consentiti"); trust_title.setProperty("role","sectionTitle"); wv.addWidget(trust_title)
        self.web_trust_empty=self._set_role(QLabel("Nessuna fiducia persistente configurata."),"empty"); wv.addWidget(self.web_trust_empty)
        self.web_trust_table=QTableWidget(0,3)
        self._setup_table(self.web_trust_table,["Dominio","Stato","Motivo"],[0,2])
        self.web_trust_table.setMaximumHeight(145)
        self.web_trust_table.itemSelectionChanged.connect(self._web_trust_selection_changed)
        wv.addWidget(self.web_trust_table)
        trust_actions=QHBoxLayout(); trust_actions.addStretch()
        self.web_revoke_trust=QPushButton("Revoca fiducia"); self.web_revoke_trust.setEnabled(False); self.web_revoke_trust.clicked.connect(self._revoke_selected_web_domain_trust)
        trust_actions.addWidget(self.web_revoke_trust); wv.addLayout(trust_actions)

        downloads_title=QLabel("Download Protection · Download tracciati"); downloads_title.setProperty("role","sectionTitle"); wv.addWidget(downloads_title)
        self.web_downloads_empty=self._set_role(QLabel("Nessun download browser tracciato."),"empty"); wv.addWidget(self.web_downloads_empty)
        self.web_downloads_table=QTableWidget(0,5)
        self._setup_table(self.web_downloads_table,["File","Dominio","Browser","Verdetto file","Stato"],[0,1])
        self.web_downloads_table.setMaximumHeight(185)
        self.web_downloads_table.itemSelectionChanged.connect(self._web_download_selection_changed)
        self.web_downloads_table.itemDoubleClicked.connect(lambda *_: self._show_selected_web_download_details())
        wv.addWidget(self.web_downloads_table)
        download_actions=QHBoxLayout(); download_actions.addStretch()
        self.web_download_details=QPushButton("Dettagli download"); self.web_download_details.setEnabled(False); self.web_download_details.clicked.connect(self._show_selected_web_download_details)
        download_actions.addWidget(self.web_download_details); wv.addLayout(download_actions)
        v.addWidget(web)

        controls=QHBoxLayout(); self.history_filter="all"; self.history_filter_buttons=[]
        for label,key in [("Tutti","all"),("Critical","CRITICAL"),("High","HIGH"),("Suspicious","SUSPICIOUS")]:
            b=QPushButton(label); b.clicked.connect(lambda checked=False,k=key:self.set_history_filter(k)); self.history_filter_buttons.append((b,key)); controls.addWidget(b)
        controls.addStretch(); clean=QPushButton("Pulisci cronologia precedente"); clean.clicked.connect(self.cleanup_history); controls.addWidget(clean); v.addLayout(controls)
        self.h_empty=self._set_role(QLabel("Nessun rilevamento corrisponde al filtro selezionato."), "empty"); v.addWidget(self.h_empty)
        self.htable=QTableWidget(0,5); self._setup_table(self.htable,["Data","File","Score","Livello","Stato"],[1]); v.addWidget(self.htable,1); return body

    # ---------- activity ----------
    def _activity_page(self):
        body=QWidget()
        v=QVBoxLayout(body)
        v.setContentsMargins(0,0,0,0)
        v.setSpacing(12)

        status=self.card()
        sr=QHBoxLayout(status)
        sr.setContentsMargins(16,13,16,13)

        texts=QVBoxLayout()
        title=QLabel("Telemetria e correlazioni")
        title.setProperty("role", "sectionTitle")
        self.activity_summary=QLabel(
            "Visualizza processo → file → comportamento."
        )
        self.activity_summary.setProperty("role", "bodyMuted")
        texts.addWidget(title)
        texts.addWidget(self.activity_summary)

        self.activity_status_badge=self.status_badge("Verifica…",False)
        sr.addLayout(texts,1)
        sr.addWidget(self.activity_status_badge)
        v.addWidget(status)

        self.activity_empty=self._set_role(QLabel("Nessun evento di telemetria disponibile."), "empty")
        v.addWidget(self.activity_empty)
        self.activity_table=QTableWidget(0,7)
        self._setup_table(
            self.activity_table,
            ["Ora","Processo","PID","Tipo","Azione","Risorsa","Score"],
            [1,5],
        )
        self.activity_table.itemSelectionChanged.connect(
            self._activity_selection_changed
        )
        v.addWidget(self.activity_table,1)

        detail=self.card()
        dv=QVBoxLayout(detail)
        dv.setContentsMargins(16,13,16,13)
        dh=QLabel("Process tree / correlazione")
        dh.setProperty("role", "subsectionTitle")
        self.activity_chain=QLabel(
            "Seleziona un evento per vedere PID, percorso e catena parent."
        )
        self.activity_chain.setWordWrap(True)
        self.activity_chain.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.activity_chain.setProperty("role", "bodyMuted")
        dv.addWidget(dh)
        dv.addWidget(self.activity_chain)
        response_row=QHBoxLayout()
        self.incident_terminate_button=QPushButton("Termina processo")
        self.incident_quarantine_button=QPushButton("Quarantena file")
        self.incident_terminate_button.setEnabled(False)
        self.incident_quarantine_button.setEnabled(False)
        self.incident_terminate_button.clicked.connect(self._manual_terminate_selected_incident)
        self.incident_quarantine_button.clicked.connect(self._manual_quarantine_selected_incident)
        response_row.addWidget(self.incident_terminate_button)
        response_row.addWidget(self.incident_quarantine_button)
        response_row.addStretch()
        dv.addLayout(response_row)
        self._selected_incident_id=""
        v.addWidget(detail)
        return body

    def _animate_activity_update(self):
        if not self.animations_enabled or not hasattr(self,"activity_table"):
            return
        effect=QGraphicsOpacityEffect(self.activity_table)
        self.activity_table.setGraphicsEffect(effect)
        effect.setOpacity(0.72)
        anim=QPropertyAnimation(effect,b"opacity",self)
        anim.setDuration(230)
        anim.setStartValue(0.72)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.finished.connect(
            lambda:self.activity_table.setGraphicsEffect(None)
        )
        self._activity_animation=anim
        anim.start()

    def refresh_activity(self):
        if not hasattr(self,"activity_table"):
            return

        rows=self.db.recent_security_events(350)
        if hasattr(self, "activity_empty"): self.activity_empty.setVisible(not rows)
        self.activity_table.setRowCount(len(rows))

        for r,row in enumerate(rows):
            process=row["process_name"] or (
                Path(row["process_path"]).name
                if row["process_path"] else "—"
            )

            try:
                data=json.loads(row["data_json"] or "{}")
            except Exception:
                data={}

            correlation_delta=int(
                data.get("correlation_score_delta") or 0
            )
            incident_score=int(data.get("incident_score") or 0)
            display_score=max(
                int(row["score"] or 0)+correlation_delta,
                incident_score,
            )

            vals=[
                str(row["ts"] or "")[-8:],
                process,
                str(row["pid"] or "—"),
                row["category"],
                row["action"],
                row["path"] or "—",
                str(min(100,display_score)),
            ]

            for c,val in enumerate(vals):
                item=QTableWidgetItem(str(val))
                self.activity_table.setItem(r,c,item)

            self.activity_table.item(r,0).setData(
                Qt.UserRole,
                {
                    "pid":row["pid"],
                    "process_name":row["process_name"],
                    "process_path":row["process_path"],
                    "path":row["path"],
                    "correlation_score_delta":correlation_delta,
                    "correlation_confidence":data.get(
                        "correlation_confidence",0
                    ),
                    "correlation_severity":data.get("correlation_severity",""),
                    "correlation_stages":data.get("correlation_stages",[]),
                    "correlation_sequence":data.get("correlation_sequence",[]),
                    "correlation_incident_id":data.get("correlation_incident_id",""),
                    "correlation_total_score":data.get("correlation_total_score",0),
                    "chain":data.get("chain",""),
                    "incident":{
                        "incident_id":data.get("incident_id","") or data.get("correlation_incident_id",""),
                        "score":data.get("incident_score",0) or data.get("correlation_total_score",0),
                        "level":data.get("incident_level","") or data.get("correlation_severity",""),
                        "confidence":data.get("incident_confidence",0) or data.get("correlation_confidence",0),
                        "status":data.get("incident_status",""),
                        "suppressed":data.get("incident_suppressed",False),
                        "categories":data.get("incident_categories",[]),
                        "reasons":data.get("incident_reasons",[]),
                        "recommended_actions":data.get("incident_recommended_actions",[]),
                    },
                    "network":{
                        "remote_addr":data.get("remote_addr",""),
                        "remote_domain":data.get("remote_domain",""),
                        "remote_port":data.get("remote_port",0),
                        "protocol":data.get("protocol",""),
                        "endpoint_class":data.get("endpoint_class",""),
                        "endpoint_status":data.get("endpoint_status",""),
                        "endpoint_confidence":data.get("endpoint_confidence",0),
                        "endpoint_first_seen":data.get("endpoint_first_seen",""),
                        "endpoint_connection_count":data.get("endpoint_connection_count",0),
                        "endpoint_process_count":data.get("endpoint_process_count",0),
                        "process_sha256":data.get("process_sha256",""),
                        "signature_status":data.get("signature_status",""),
                        "signer":data.get("signer",""),
                    },
                },
            )

        if self.telemetry_advanced_active:
            self.activity_status_badge.setText(
                "Telemetria avanzata attiva"
            )
            self._set_badge_tone(self.activity_status_badge, "safe")
            self.activity_summary.setText(
                "ETW privilegiato + incident correlation + rete locale."
            )
        else:
            self.activity_status_badge.setText(
                "Fallback locale attivo"
            )
            self._set_badge_tone(self.activity_status_badge, "warning")
            self.activity_summary.setText(
                "psutil/watchdog + incident correlation + rete locale."
            )

    def _activity_selection_changed(self):
        r=self.activity_table.currentRow()
        if r<0:
            return

        item=self.activity_table.item(r,0)
        payload=item.data(Qt.UserRole) if item else None
        if not payload:
            return

        pid=payload.get("pid")
        process=payload.get("process_name") or "Processo non attribuito"
        process_path=payload.get("process_path") or ""
        resource=payload.get("path") or ""
        delta=int(payload.get("correlation_score_delta") or 0)
        confidence=float(payload.get("correlation_confidence") or 0.0)
        correlation_severity=str(payload.get("correlation_severity") or "")
        correlation_stages=list(payload.get("correlation_stages") or [])
        correlation_sequence=list(payload.get("correlation_sequence") or [])
        correlation_incident_id=str(payload.get("correlation_incident_id") or "")
        correlation_total_score=int(payload.get("correlation_total_score") or 0)
        saved_chain=payload.get("chain") or ""
        network=payload.get("network") or {}
        incident=payload.get("incident") or {}
        self._selected_incident_id=str(incident.get("incident_id") or "")
        persisted_incident=self._selected_incident_payload() if self._selected_incident_id else None
        response_incident=persisted_incident or incident
        incident_score=int(response_incident.get("score") or 0)
        incident_confidence=float(response_incident.get("confidence") or 0.0)
        incident_suppressed=bool(response_incident.get("suppressed"))
        incident_data=response_incident.get("data") or {}
        response_pid=response_incident.get("pid") or pid
        process_create_time=float(incident_data.get("process_create_time") or 0.0)
        quarantine_path=str(incident_data.get("file_candidate_path") or response_incident.get("process_path") or process_path or "")
        can_respond=bool(
            persisted_incident
            and not incident_suppressed
            and incident_score>=70
            and incident_confidence>=0.60
        )
        if hasattr(self,"incident_terminate_button"):
            self.incident_terminate_button.setEnabled(
                can_respond and bool(response_pid) and process_create_time>0
            )
        if hasattr(self,"incident_quarantine_button"):
            self.incident_quarantine_button.setEnabled(can_respond and bool(quarantine_path))

        chain=[]
        if pid and self.telemetry_advanced_active:
            chain=self.telemetry_client.process_chain(int(pid))
        if not chain and pid:
            chain=[
                {"pid":n.pid,"name":n.name,"path":n.path}
                for n in self.process_tree.ancestry(int(pid))
            ]

        if chain:
            chain_text=" → ".join(
                f"{x.get('name') or 'processo'} [{x.get('pid')}]"
                for x in reversed(chain)
            )
        elif saved_chain:
            chain_text=saved_chain
        else:
            chain_text="Catena parent non disponibile per questo evento."

        correlation_text=""
        if delta:
            severity_label=correlation_severity.upper() if correlation_severity else "CONTEXT"
            correlation_text=(
                f"\n\nCorrelazione comportamentale 2.0: +{delta} rischio"
                f" · totale {correlation_total_score or min(100,delta)}"
                f" · {severity_label}"
                f" · confidenza {int(confidence*100)}%"
            )
            if correlation_incident_id:
                correlation_text += f"\nIncident: {correlation_incident_id}"
            if correlation_stages:
                correlation_text += "\nFasi: " + " → ".join(correlation_stages)
            if correlation_sequence:
                correlation_text += "\nSequenza: " + " → ".join(correlation_sequence[-6:])

        incident_text=""
        if incident.get("incident_id"):
            actions=list(incident.get("recommended_actions") or [])
            reasons=list(incident.get("reasons") or [])
            level=str(incident.get("level") or "SAFE").upper()
            incident_text=(
                f"\n\nIncident response: {str(incident.get('incident_id'))[:16]}"
                f" · {level} {int(incident.get('score') or 0)}/100"
                f" · confidenza {int(float(incident.get('confidence') or 0.0)*100)}%"
                + (" · SUPPRESSED" if incident.get("suppressed") else "")
            )
            if reasons:
                incident_text += "\nEvidenze: " + "; ".join(str(x) for x in reasons[:3])
            if actions:
                incident_text += "\nAzioni consigliate: " + ", ".join(str(x) for x in actions[:4])

        self.activity_chain.setText(
            f"{process}"
            + (f" · PID {pid}" if pid else "")
            + (f"\n{process_path}" if process_path else "")
            + f"\n\n{chain_text}"
            + correlation_text
            + incident_text
            + (
                f"\n\nRete: {network.get('protocol') or 'IP'} → "
                f"{network.get('remote_domain') or network.get('remote_addr') or resource}:"
                f"{network.get('remote_port') or ''}"
                + (f" · {network.get('endpoint_class')}" if network.get('endpoint_class') else "")
                + (f" · reputation {network.get('endpoint_status')}" if network.get('endpoint_status') and network.get('endpoint_status') != 'unknown' else "")
                + (f"\nPrima osservazione locale: {network.get('endpoint_first_seen')}" if network.get('endpoint_first_seen') else "")
                + (f" · {network.get('endpoint_connection_count')} connessioni / {network.get('endpoint_process_count')} processi" if network.get('endpoint_connection_count') else "")
                + (f"\nFirma processo: {network.get('signature_status')} · {network.get('signer')}" if network.get('signature_status') or network.get('signer') else "")
                if network.get("remote_addr") or network.get("remote_domain") else ""
            )
            + (f"\n\nRisorsa: {resource}" if resource and not network.get("remote_addr") else "")
        )

        if self.animations_enabled:
            effect=QGraphicsOpacityEffect(self.activity_chain)
            self.activity_chain.setGraphicsEffect(effect)
            effect.setOpacity(0.55)
            anim=QPropertyAnimation(effect,b"opacity",self)
            anim.setDuration(190)
            anim.setStartValue(0.55)
            anim.setEndValue(1.0)
            anim.setEasingCurve(QEasingCurve.OutCubic)
            anim.finished.connect(
                lambda:self.activity_chain.setGraphicsEffect(None)
            )
            self._chain_animation=anim
            anim.start()

    def _selected_incident_payload(self):
        incident_id=str(getattr(self,"_selected_incident_id","") or "")
        if not incident_id:
            return None
        row=self.db.get_incident(incident_id)
        if row is None:
            return None
        try:
            reasons=json.loads(row["reasons_json"] or "[]")
        except Exception:
            reasons=[]
        try:
            data=json.loads(row["data_json"] or "{}")
        except Exception:
            data={}
        try:
            actions=json.loads(row["recommended_actions_json"] or "[]")
        except Exception:
            actions=[]
        return {
            "incident_id":row["incident_id"],
            "pid":row["pid"],
            "ppid":row["ppid"],
            "process_name":row["process_name"] or "",
            "process_path":row["process_path"] or "",
            "process_sha256":row["process_sha256"] or "",
            "signature_status":row["signature_status"] or "",
            "signer":row["signer"] or "",
            "score":int(row["score"] or 0),
            "level":row["level"] or "SAFE",
            "confidence":float(row["confidence"] or 0.0),
            "reasons":reasons,
            "data":data,
            "recommended_actions":actions,
            "status":row["status"] or "open",
            "suppressed":bool(row["suppressed"]),
        }

    def _manual_terminate_selected_incident(self):
        incident=self._selected_incident_payload()
        if not incident:
            QMessageBox.information(self,"Incident response","Incident non più disponibile.")
            return
        name=incident.get("process_name") or incident.get("process_path") or "processo"
        if QMessageBox.question(
            self,
            "Termina processo",
            f"Terminare manualmente {name}?\n\nBC Sentinel verificherà PID, generazione e percorso prima di agire.",
            QMessageBox.Yes|QMessageBox.No,
        )!=QMessageBox.Yes:
            return
        if self.telemetry_service_status is not None:
            response=self.telemetry_client.terminate_process(incident.get("incident_id",""),approved=True)
            if response.get("ok"):
                payload=response.get("result") or {}
                detail=str(payload.get("detail") or "Azione completata dal Protection Service.")
                if payload.get("status")=="success":
                    self._notify("Incident response",detail,"warning")
                else:
                    QMessageBox.warning(self,"Incident response",detail)
            else:
                QMessageBox.warning(
                    self,"Incident response",
                    self.telemetry_client.last_error or "Il Protection Service ha rifiutato l'azione. Avvia l'azione con privilegi amministrativi."
                )
        else:
            result=self.response_engine.terminate_process(incident,approved=True)
            if result.succeeded:
                self._notify("Incident response",result.detail,"warning")
            else:
                QMessageBox.warning(self,"Incident response",result.detail)
        self.refresh_activity()

    def _manual_quarantine_selected_incident(self):
        incident=self._selected_incident_payload()
        if not incident:
            QMessageBox.information(self,"Incident response","Incident non più disponibile.")
            return
        incident_data=incident.get("data") or {}
        path=incident_data.get("file_candidate_path") or incident.get("process_path") or ""
        if QMessageBox.question(
            self,
            "Quarantena file",
            f"Spostare in quarantena il file associato?\n\n{path}\n\nL'azione richiede un incidente >=70 e fallisce in modo sicuro su allowlist, reparse point o percorsi Windows protetti.",
            QMessageBox.Yes|QMessageBox.No,
        )!=QMessageBox.Yes:
            return
        if self.telemetry_service_status is not None:
            response=self.telemetry_client.quarantine_file(
                incident.get("incident_id",""),approved=True,candidate_path=path
            )
            if response.get("ok"):
                payload=response.get("result") or {}
                detail=str(payload.get("detail") or "Azione completata dal Protection Service.")
                if payload.get("status")=="success":
                    self._notify("File in quarantena",detail,"warning")
                    self.refresh_quarantine()
                else:
                    QMessageBox.warning(self,"Incident response",detail)
            else:
                QMessageBox.warning(
                    self,"Incident response",
                    self.telemetry_client.last_error or "Il Protection Service ha rifiutato l'azione. Avvia l'azione con privilegi amministrativi."
                )
        else:
            result=self.response_engine.quarantine_file(incident,candidate_path=path,approved=True)
            if result.succeeded:
                self._notify("File in quarantena",result.detail,"warning")
                self.refresh_quarantine()
            else:
                QMessageBox.warning(self,"Incident response",result.detail)
        self.refresh_activity()

    # ---------- protection ----------
    def _protection_page(self):
        scroll=QScrollArea(); scroll.setWidgetResizable(True); body=QWidget(); v=QVBoxLayout(body); v.setContentsMargins(0,0,0,8); v.setSpacing(12)
        self.protection_cards={}
        data=[
            ("Protezione real-time","Monitora la creazione e modifica di file eseguibili e script nelle cartelle configurate.","realtime"),
            ("Ransomware Shield","Correla burst di attività file e richiede un segnale forte prima di mostrare un alert. Registra l'evento senza terminare processi.","ransomware"),
            ("Behavior Shield","Osserva nuovi processi, parent process e command line per correlare sequenze sospette.","behavior"),
            ("AI Security Analyst (Beta)","Ollama locale può spiegare eventi già classificati. Non decide blocchi, score o cancellazioni.","ai"),
            ("ETW Telemetry (Beta)","Correla eventi processo/file ETW quando Windows e i privilegi lo consentono. Fallback psutil/watchdog sempre disponibile.","etw"),
            ("Persistence Monitor","Osserva Run/RunOnce, cartelle Startup e Scheduled Tasks senza rimuoverli automaticamente.","persistence"),
            ("Antispyware & Persistence Intelligence","Analizza persistenza, servizi, WMI, policy browser, proxy/DNS e target firmati/non firmati. Correlazione multi-segnale, nessuna rimozione automatica nella v0.9 Beta1.","antispyware"),
            ("Network Intelligence","Correla processo → connessione → endpoint con reputazione locale e scoring spiegabile. Non blocca il traffico.","network"),
            ("Web Protection / Anti-Phishing","Correla DNS → dominio → IP → browser → download → file → processo, persiste finding/download e consente containment temporaneo solo dopo verifica IOC/DNS/shared-IP. Nessun MITM HTTPS e nessun auto-blocco.","web"),
            ("File Reputation","Arricchisce file/processi con Authenticode, certificato, first-seen e prevalenza locale senza upload cloud.","reputation"),
        ]
        for title,desc,key in data:
            f=self.card(); r=QHBoxLayout(f); r.setContentsMargins(18,16,18,16); texts=QVBoxLayout(); t=self._set_role(QLabel(title), "sectionTitle"); d=self._set_role(QLabel(desc), "bodyMuted"); d.setWordWrap(True); texts.addWidget(t); texts.addWidget(d); badge=self.status_badge("Attivo",True); r.addLayout(texts,1); r.addWidget(badge); v.addWidget(f); self.protection_cards[key]=badge
        manage=QPushButton("Apri Impostazioni"); manage.clicked.connect(lambda:self.nav_to(6)); v.addWidget(manage,0,Qt.AlignLeft); v.addStretch(); scroll.setWidget(body); return scroll

    # ---------- settings ----------
    def _settings_page(self):
        scroll=QScrollArea(); scroll.setWidgetResizable(True); body=QWidget(); v=QVBoxLayout(body); v.setContentsMargins(0,0,8,8); v.setSpacing(14)
        general=self.card(); gv=QVBoxLayout(general); gv.setContentsMargins(18,16,18,16); h=self._set_role(QLabel("Generale"), "sectionTitle"); gv.addWidget(h)
        self.auto_switch=ToggleSwitch(self.is_autostart_enabled()); gv.addLayout(self._setting_row("Avvia BC Sentinel con Windows","Apre BC Sentinel automaticamente all'accesso a Windows.",self.auto_switch)); self.auto_switch.toggled.connect(self.toggle_autostart); v.addWidget(general)
        protection=self.card(); pv=QVBoxLayout(protection); pv.setContentsMargins(18,16,18,16); hh=self._set_role(QLabel("Protezione"), "sectionTitle"); pv.addWidget(hh)
        self.rt_switch=ToggleSwitch(self.settings.realtime_enabled); self.rs_switch=ToggleSwitch(self.settings.ransomware_enabled); self.bh_switch=ToggleSwitch(self.settings.behavior_enabled); self.ai_switch=ToggleSwitch(self.db.get_setting("ai_enabled","0")=="1")
        pv.addLayout(self._setting_row("Protezione real-time","Monitora file e script nelle cartelle configurate.",self.rt_switch)); pv.addLayout(self._setting_row("Ransomware Shield","Abilita la correlazione conservativa di attività anomala nelle cartelle utente protette.",self.rs_switch)); pv.addLayout(self._setting_row("Behavior Shield","Abilita il monitoraggio user-space dei nuovi processi.",self.bh_switch)); pv.addLayout(self._setting_row("AI Security Analyst (Beta)","Abilita le spiegazioni locali via Ollama quando disponibile.",self.ai_switch));
        self.rt_switch.toggled.connect(self.toggle_realtime); self.rs_switch.toggled.connect(self.toggle_ransomware); self.bh_switch.toggled.connect(self.toggle_behavior); self.ai_switch.toggled.connect(self.toggle_ai); v.addWidget(protection)

        telemetry=self.card(); tv=QVBoxLayout(telemetry); tv.setContentsMargins(18,16,18,16)
        th=self._set_role(QLabel("Telemetria Windows"), "sectionTitle"); tv.addWidget(th)
        self.etw_switch=ToggleSwitch(self.settings.etw_enabled); self.persistence_switch=ToggleSwitch(self.settings.persistence_enabled)
        tv.addLayout(self._setting_row("ETW Telemetry (Beta)","Correla processi e operazioni file tramite Event Tracing for Windows quando disponibile.",self.etw_switch))
        self.etw_status=QLabel("")
        self.etw_status.setWordWrap(True)
        tv.addWidget(self.etw_status)

        install_row=QHBoxLayout()
        install_row.addStretch()
        self.telemetry_install_btn=QPushButton(
            "Installa Protection Service"
        )
        self.telemetry_install_btn.clicked.connect(
            self.install_telemetry_service
        )
        install_row.addWidget(self.telemetry_install_btn)
        tv.addLayout(install_row)

        tv.addLayout(self._setting_row(
            "Persistence Monitor",
            "Run/RunOnce, Startup folders e Scheduled Tasks. "
            "Usa il servizio privilegiato quando disponibile.",
            self.persistence_switch,
        ))
        self.etw_switch.toggled.connect(self.toggle_etw); self.persistence_switch.toggled.connect(self.toggle_persistence); v.addWidget(telemetry)

        intelligence=self.card()
        iv=QVBoxLayout(intelligence)
        iv.setContentsMargins(18,16,18,16)
        ih=QLabel("Reputation & Network")
        ih.setProperty("role", "sectionTitle")
        iv.addWidget(ih)
        self.network_switch=ToggleSwitch(self.settings.network_enabled)
        self.reputation_switch=ToggleSwitch(self.settings.reputation_enabled)
        iv.addLayout(self._setting_row(
            "Telemetria di rete",
            "Correla processo → IP/porta → reputazione locale. Il servizio privilegiato è usato quando disponibile; nessun blocco traffico.",
            self.network_switch,
        ))
        iv.addLayout(self._setting_row(
            "Reputazione locale / Authenticode",
            "Usa Authenticode, certificato, first-seen/prevalenza, cache e allowlist locali. Nessun hash viene caricato online.",
            self.reputation_switch,
        ))
        self.network_switch.toggled.connect(self.toggle_network)
        self.reputation_switch.toggled.connect(self.toggle_reputation)
        v.addWidget(intelligence)

        threat_intel=self.card()
        tiv=QVBoxLayout(threat_intel)
        tiv.setContentsMargins(18,16,18,16)
        tih=QHBoxLayout()
        til=self._set_role(QLabel("Threat Intelligence firmata"), "sectionTitle")
        self.ioc_status_label=QLabel("Feed non verificato")
        self._set_inline_tone(self.ioc_status_label, "info")
        self.ioc_import_btn=QPushButton("Importa IOC firmati…")
        self.ioc_import_btn.clicked.connect(self.import_signed_ioc_bundle)
        tih.addWidget(til); tih.addStretch(); tih.addWidget(self.ioc_status_label); tih.addWidget(self.ioc_import_btn)
        tiv.addLayout(tih)
        ioc_desc=self._set_role(QLabel(
            "Importa solo bundle IOC BC Sentinel con firma Ed25519 valida. La chiave privata non è inclusa nel prodotto; "
            "sequenze precedenti vengono rifiutate e l'import non modifica automaticamente il firewall."
        ), "caption")
        ioc_desc.setWordWrap(True); tiv.addWidget(ioc_desc)
        self.ioc_detail_label=self._set_role(QLabel("Nessun feed IOC attivo."), "bodyMuted")
        self.ioc_detail_label.setWordWrap(True); tiv.addWidget(self.ioc_detail_label)
        package_row=QHBoxLayout()
        package_title=self._set_role(QLabel("Pacchetti sicurezza v0.8"), "subsectionTitle")
        self.threat_package_status_label=QLabel("Nessun pacchetto attivo")
        self._set_inline_tone(self.threat_package_status_label, "inactive")
        self.threat_package_import_btn=QPushButton("Installa pacchetto firmato…")
        self.threat_package_import_btn.clicked.connect(self.import_signed_threat_package)
        package_row.addWidget(package_title); package_row.addStretch(); package_row.addWidget(self.threat_package_status_label); package_row.addWidget(self.threat_package_import_btn)
        tiv.addLayout(package_row)
        package_desc=self._set_role(QLabel(
            "Canale firmato Ed25519 per IOC, YARA e profili comportamentali advisory. Il servizio verifica firma/hash, compila YARA in staging e attiva atomicamente; rollback consentito solo al last-known-good. Nessun codice arbitrario viene eseguito dal pacchetto."
        ), "caption")
        package_desc.setWordWrap(True); tiv.addWidget(package_desc)
        self.threat_package_detail_label=self._set_role(QLabel("Canale v0.8 non verificato."), "bodyMuted")
        self.threat_package_detail_label.setWordWrap(True); tiv.addWidget(self.threat_package_detail_label)
        v.addWidget(threat_intel)

        ai_card=self.card(); aiv=QVBoxLayout(ai_card); aiv.setContentsMargins(18,16,18,16)
        aih=QHBoxLayout(); ail=self._set_role(QLabel("AI Security Analyst"), "sectionTitle")
        self.ai_status=QLabel("Non verificato"); self._set_inline_tone(self.ai_status, "info")
        test_ai=QPushButton("Verifica Ollama"); test_ai.clicked.connect(self.test_ollama)
        aih.addWidget(ail); aih.addStretch(); aih.addWidget(self.ai_status); aih.addWidget(test_ai); aiv.addLayout(aih)
        model_row=QHBoxLayout(); model_row.addWidget(QLabel("Modello"))
        self.ai_model_input=QLineEdit(self.db.get_setting("ai_model","qwen3:4b") or "qwen3:4b"); self.ai_model_input.setPlaceholderText("es. qwen3:4b"); self.ai_model_input.editingFinished.connect(self.save_ai_model)
        model_row.addWidget(self.ai_model_input,1); aiv.addLayout(model_row); v.addWidget(ai_card)

        experience=self.card(); ev=QVBoxLayout(experience); ev.setContentsMargins(18,16,18,16)
        eh=self._set_role(QLabel("Esperienza"), "sectionTitle"); ev.addWidget(eh)
        self.notify_switch=ToggleSwitch(self.settings.notifications_enabled); self.tray_switch=ToggleSwitch(self.settings.close_to_tray); self.animation_switch=ToggleSwitch(self.settings.animations_enabled)
        ev.addLayout(self._setting_row("Notifiche Windows","Mostra notifiche native per eventi ad alta priorità.",self.notify_switch))
        ev.addLayout(self._setting_row("Chiudi nella tray","La X nasconde la finestra senza spegnere la protezione.",self.tray_switch))
        ev.addLayout(self._setting_row("Animazioni","Transizioni e micro-animazioni sobrie. Disattivabile per accessibilità.",self.animation_switch))
        self.notify_switch.toggled.connect(self.toggle_notifications); self.tray_switch.toggled.connect(self.toggle_close_to_tray); self.animation_switch.toggled.connect(self.toggle_animations)
        lr=QHBoxLayout(); lr.addStretch(); open_logs=QPushButton("Apri cartella log"); open_logs.clicked.connect(self.open_logs); lr.addWidget(open_logs); ev.addLayout(lr); v.addWidget(experience)
        dirs=self.card(); dv=QVBoxLayout(dirs); dv.setContentsMargins(18,16,18,16); dh=QHBoxLayout(); lab=self._set_role(QLabel("Cartelle monitorate"), "sectionTitle"); add=QPushButton("Aggiungi cartella"); add.clicked.connect(self.add_monitored_dir); rem=QPushButton("Rimuovi"); rem.clicked.connect(self.remove_monitored_dir); dh.addWidget(lab); dh.addStretch(); dh.addWidget(add); dh.addWidget(rem); dv.addLayout(dh); self.dirs_list=QListWidget(); self.dirs_list.setMaximumHeight(180); dv.addWidget(self.dirs_list); v.addWidget(dirs)
        allow=self.card(); av=QVBoxLayout(allow); av.setContentsMargins(18,16,18,16); ah=QHBoxLayout(); al=self._set_role(QLabel("Esclusioni / Allowlist"), "sectionTitle"); addf=QPushButton("Aggiungi file"); addf.clicked.connect(self.add_allow_file); addd=QPushButton("Aggiungi cartella"); addd.clicked.connect(self.add_allow_dir); delb=QPushButton("Rimuovi"); delb.clicked.connect(self.remove_allow); ah.addWidget(al); ah.addStretch(); ah.addWidget(addf); ah.addWidget(addd); ah.addWidget(delb); av.addLayout(ah); self.allow_list=QListWidget(); self.allow_list.setMaximumHeight(190); av.addWidget(self.allow_list); v.addWidget(allow); v.addStretch(); scroll.setWidget(body); return scroll

    def _setting_row(self,title,desc,switch):
        r=QHBoxLayout(); r.setSpacing(16)
        texts=QVBoxLayout(); texts.setSpacing(3)
        t=self._set_role(QLabel(title), "subsectionTitle")
        d=self._set_role(QLabel(desc), "caption"); d.setWordWrap(True)
        texts.addWidget(t); texts.addWidget(d); r.addLayout(texts,1); r.addWidget(switch,0,Qt.AlignVCenter); return r

    def _setup_table(self, table, headers, stretch_cols):
        table.setColumnCount(len(headers)); table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True); table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection); table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setShowGrid(False); table.setWordWrap(False); table.setTextElideMode(Qt.ElideMiddle)
        table.verticalHeader().setVisible(False); table.verticalHeader().setDefaultSectionSize(40)
        table.horizontalHeader().setMinimumSectionSize(76)
        for i in range(len(headers)): table.horizontalHeader().setSectionResizeMode(i,QHeaderView.ResizeToContents)
        for i in stretch_cols: table.horizontalHeader().setSectionResizeMode(i,QHeaderView.Stretch)

    # ---------- refresh ----------
    def format_last_scan(self):
        row = self.db.get_last_completed_scan()
        if not row:
            return "Mai"

        ts = str(row["finished_ts"] or "")
        if not ts:
            return "Mai"

        # SQLite stores UTC timestamp text. For the MVP we display the persisted
        # timestamp without pretending a timezone conversion we have not applied.
        return ts[:16]

    def refresh_all(self):
        self.refresh_dashboard(); self.refresh_protection(); self.refresh_settings_lists()

    def refresh_dashboard(self):
        rows=self.db.current_detection_history(500)
        active=sum(1 for r in rows if r["action"] in {"logged","quarantined"})
        q=self.db.execute(
            "SELECT COUNT(*) AS n FROM quarantine WHERE deleted=0 AND restored=0"
        )[0]["n"]

        self.stat_last.set_display(self.format_last_scan(), False)
        self.stat_detect.set_display(active, self.animations_enabled)
        self.stat_quarantine.set_display(q, self.animations_enabled)
        states={"realtime":(self.settings.realtime_enabled and self.realtime_running,"Attivo"),"ransomware":(self.settings.ransomware_enabled,"Attivo"),"behavior":(self.settings.behavior_enabled,"Attivo"),"ai":(self.db.get_setting("ai_enabled","0")=="1","Beta")}
        self._refresh_telemetry_visual_state()

        for key,(on,label) in states.items():
            old=self.dashboard_module_states.get(key)
            if old:
                old.setText(label if on else ("Beta" if key=="ai" else "Disattivo"))
                self._set_badge_tone(old, "safe" if on else "inactive")

    def refresh_protection(self):
        if not hasattr(self,'protection_cards'): return
        service_web=(self.telemetry_service_status or {}).get("web_protection") or {}
        web_on=bool(service_web.get("enabled") and service_web.get("dns_etw")) if self.telemetry_service_status is not None else bool(self.settings.network_enabled and self.settings.etw_enabled and self.etw_running)
        service_antispyware=(self.telemetry_service_status or {}).get("antispyware") or {}
        antispyware_on=bool(service_antispyware.get("running")) if self.telemetry_service_status is not None else False
        vals={"realtime":self.settings.realtime_enabled and self.realtime_running,"ransomware":self.settings.ransomware_enabled,"behavior":self.settings.behavior_enabled,"ai":self.db.get_setting("ai_enabled","0")=="1","etw":self.settings.etw_enabled and self.telemetry_advanced_active,"persistence":self.settings.persistence_enabled and self.persistence_running,"antispyware":antispyware_on,"network":self.settings.network_enabled and self.network_running,"web":web_on,"reputation":self.settings.reputation_enabled}
        for k,on in vals.items():
            b=self.protection_cards[k]
            b.setText("Beta" if k=="ai" and on else ("Attivo" if on else ("Opzionale" if k=="ai" else "Disattivo")))
            self._set_badge_tone(b, "safe" if on else "inactive")

    def refresh_settings_lists(self):
        if hasattr(self,'dirs_list'):
            self.dirs_list.clear();
            for d in self.settings.monitored_dirs: self.dirs_list.addItem(d)
        if hasattr(self,'allow_list'):
            self.allow_list.clear();
            for row in self.db.list_allowlist():
                item=QListWidgetItem(f"{row['kind'].upper()}   {row['value']}"); item.setData(Qt.UserRole,row['id']); self.allow_list.addItem(item)
        self._refresh_telemetry_visual_state()
        self._refresh_ioc_status()

    def _refresh_ioc_status(self):
        if not hasattr(self, "ioc_status_label"):
            return
        status={}
        if self.telemetry_service_status is not None:
            try:
                status=self.telemetry_client.ioc_status() or {}
            except Exception:
                status={}
        if not status:
            try:
                status=self.db.ioc_status() or {}
            except Exception:
                status={}
        installed=bool(status.get("installed"))
        active=int(status.get("active_entries") or 0)
        if installed:
            seq=int(status.get("sequence") or 0)
            bundle=str(status.get("bundle_id") or "")
            expires=float(status.get("expires_at") or 0.0)
            exp=time.strftime("%Y-%m-%d %H:%M", time.localtime(expires)) if expires else "n/d"
            self.ioc_status_label.setText(f"Attivo · seq {seq}")
            self._set_inline_tone(self.ioc_status_label, "safe")
            self.ioc_detail_label.setText(f"{bundle} · {active} IOC attivi · scadenza {exp}")
        else:
            self.ioc_status_label.setText("Nessun feed")
            self._set_inline_tone(self.ioc_status_label, "inactive")
            self.ioc_detail_label.setText("Nessun bundle IOC firmato installato.")
        if hasattr(self, "threat_package_status_label"):
            threat={}
            if self.telemetry_service_status is not None:
                try:
                    threat=self.telemetry_client.threat_intel_status() or {}
                except Exception:
                    threat={}
            active=threat.get("active") if isinstance(threat,dict) else None
            if isinstance(active,dict) and active.get("package_id"):
                self.threat_package_status_label.setText(f"Attivo · seq {active.get('sequence')}")
                self._set_inline_tone(self.threat_package_status_label, "safe")
                self.threat_package_detail_label.setText(
                    f"{active.get('package_id')} · key {threat.get('key_fingerprint') or '—'} · high-water {threat.get('high_water_sequence') or 0} · LKG {'disponibile' if threat.get('last_known_good') else 'non ancora disponibile'}"
                )
            elif threat:
                self.threat_package_status_label.setText("Canale pronto")
                self._set_inline_tone(self.threat_package_status_label, "info")
                self.threat_package_detail_label.setText(
                    f"Ed25519 · key {threat.get('key_fingerprint') or '—'} · staging verificato · rollback LKG supportato"
                )
            else:
                self.threat_package_status_label.setText("Servizio non verificato")
                self._set_inline_tone(self.threat_package_status_label, "inactive")
                self.threat_package_detail_label.setText("Il Protection Service deve essere attivo per gestire pacchetti v0.8.")

    def import_signed_ioc_bundle(self):
        if self.telemetry_service_status is None:
            QMessageBox.warning(
                self, "Threat Intelligence",
                "L'import dei feed IOC richiede il BC Sentinel Protection Service attivo. "
                "La GUI non può bypassare la verifica privilegiata della firma."
            )
            return
        raw,_=QFileDialog.getOpenFileName(
            self, "Seleziona bundle IOC firmato", str(Path.home()), "IOC JSON (*.json);;Tutti i file (*)"
        )
        if not raw:
            return
        bundle_path=Path(raw)
        sig_path=bundle_path.with_suffix(".sig")
        if not sig_path.exists():
            sig_raw,_=QFileDialog.getOpenFileName(
                self, "Seleziona firma Ed25519", str(bundle_path.parent), "Firma IOC (*.sig);;Tutti i file (*)"
            )
            if not sig_raw:
                return
            sig_path=Path(sig_raw)
        try:
            bundle=json.loads(bundle_path.read_text(encoding="utf-8"))
            signature=sig_path.read_text(encoding="utf-8").strip()
        except Exception as exc:
            QMessageBox.warning(self,"Threat Intelligence",f"Bundle/firma non leggibili: {exc}")
            return
        if QMessageBox.question(
            self, "Importa IOC firmati",
            f"Importare il bundle {bundle_path.name}?\n\nBC Sentinel verificherà firma Ed25519, validità temporale e anti-rollback prima di installarlo.",
            QMessageBox.Yes|QMessageBox.No,
        )!=QMessageBox.Yes:
            return
        response=self.telemetry_client.import_ioc_bundle(bundle,signature,approved=True)
        if not response.get("ok"):
            QMessageBox.warning(
                self,"Threat Intelligence",
                self.telemetry_client.last_error or "Il Protection Service ha rifiutato il bundle IOC."
            )
            return
        # Mirror the already service-approved feed into the GUI database so
        # manual scans use the same signed intelligence. The GUI independently
        # verifies the pinned Ed25519 signature; no unsigned local bypass exists.
        try:
            self.db.install_ioc_bundle(SignedIOCVerifier().verify(bundle, signature))
        except Exception as exc:
            QMessageBox.warning(
                self, "Threat Intelligence",
                f"Il servizio ha accettato il feed, ma la replica locale verificata non è riuscita: {exc}"
            )
        self._refresh_ioc_status()
        payload=response.get("ioc") or {}
        status=payload.get("status") or {}
        self._notify(
            "Threat Intelligence aggiornata",
            f"Firma verificata · sequenza {status.get('sequence') or payload.get('sequence') or '?'} · "
            f"{status.get('active_entries') or 0} IOC attivi",
            "safe",
        )

    def import_signed_threat_package(self):
        if self.telemetry_service_status is None:
            QMessageBox.warning(self, "Pacchetto sicurezza", "Il BC Sentinel Protection Service deve essere attivo. La GUI non può attivare contenuti firmati fuori dal boundary privilegiato.")
            return
        raw,_=QFileDialog.getOpenFileName(
            self, "Seleziona pacchetto sicurezza firmato", str(Path.home()), "BC Threat Package (*.json);;Tutti i file (*)"
        )
        if not raw:
            return
        package_path=Path(raw)
        sig_path=package_path.with_suffix(".sig")
        if not sig_path.exists():
            sig_raw,_=QFileDialog.getOpenFileName(
                self, "Seleziona firma Ed25519", str(package_path.parent), "Firma pacchetto (*.sig);;Tutti i file (*)"
            )
            if not sig_raw:
                return
            sig_path=Path(sig_raw)
        try:
            package=json.loads(package_path.read_text(encoding="utf-8"))
            signature=sig_path.read_text(encoding="utf-8").strip()
        except Exception as exc:
            QMessageBox.warning(self,"Pacchetto sicurezza",f"Pacchetto/firma non leggibili: {exc}")
            return
        validation=self.telemetry_client.validate_threat_package(package,signature)
        if not isinstance(validation,dict) or not validation.get("valid"):
            QMessageBox.warning(self,"Pacchetto sicurezza",self.telemetry_client.last_error or "Firma o contenuto del pacchetto non validi.")
            return
        components=validation.get("components") or {}
        if QMessageBox.question(
            self, "Installa pacchetto sicurezza",
            f"Pacchetto: {validation.get('package_id')}\nSequenza: {validation.get('sequence')}\nIOC: {components.get('ioc_entries',0)} · YARA: {components.get('yara_rules',0)} · Behavior advisory: {components.get('behavior_rules',0)}\n\nIl servizio eseguirà staging verificato e attivazione atomica. L'azione richiede UAC e non esegue codice contenuto nel pacchetto.",
            QMessageBox.Yes|QMessageBox.No,
        )!=QMessageBox.Yes:
            return
        response=self.telemetry_client.install_threat_package(package,signature,approved=True)
        if not response.get("ok"):
            QMessageBox.warning(self,"Pacchetto sicurezza",self.telemetry_client.last_error or "Il Protection Service ha rifiutato il pacchetto.")
            return
        # Mirror only the cryptographically verified IOC overlay into the GUI
        # database so manual scans share the service's signed file/domain data.
        try:
            verified=SignedThreatPackageVerifier().verify(package,signature)
            self.db.activate_threat_package_iocs(verified,[entry.to_dict() for entry in verified.ioc_entries])
        except Exception as exc:
            QMessageBox.warning(self,"Pacchetto sicurezza",f"Il servizio ha attivato il pacchetto, ma la replica IOC locale verificata non è riuscita: {exc}")
        self._refresh_ioc_status()
        active=((response.get("threat_package") or {}).get("activation") or {}).get("active") or {}
        self._notify(
            "Pacchetto sicurezza attivato",
            f"{active.get('package_id') or validation.get('package_id')} · sequenza {active.get('sequence') or validation.get('sequence')}",
            "safe",
        )

    # ---------- scan logic ----------
    def quick_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.nav_to(1)
            return
        roots=[p for p in [Path.home()/"Downloads",Path.home()/"Desktop"] if p.exists()] or [Path.home()]
        self.nav_to(1)
        self.start_scan(roots,"Scansione rapida")

    def full_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.nav_to(1)
            return
        raw=QFileDialog.getExistingDirectory(self,"Scegli la cartella da analizzare",str(Path.home()))
        if raw:
            self.nav_to(1)
            self.start_scan([Path(raw)],"Scansione completa")

    def _set_scan_buttons_enabled(self,enabled):
        for button in getattr(self,"scan_action_buttons",[]):
            button.setEnabled(bool(enabled))

    def _begin_scan_feedback(self,label):
        self.scan_started=time.monotonic()
        self._current_scan_label=label
        self._scan_has_progress=False
        self._scan_prepare_phase=0
        self.scan_hits_count=0
        self._set_scan_buttons_enabled(False)
        self.cancel_scan_btn.show()
        self.cancel_scan_btn.setText("Annulla scansione")
        self.cancel_scan_btn.setEnabled(True)
        self.scan_indicator.set_active(True,animate=self.animations_enabled)
        self._set_scan_state("scanning")
        self.scan_status.setText(f"Avvio {label.lower()}…")
        self.scan_desc.setText("Preparazione del motore e indicizzazione dei file.")
        self.scan_progress.setRange(0,0)
        self.scan_progress.setFormat("")
        self.scan_count.setText("Preparazione elenco file…")
        self.scan_hits.setText("0 elementi rilevati")
        self.scan_current.setText("Inizializzazione protezione…")
        self.scan_elapsed.setText("Tempo trascorso: 00:00.0")
        self.scan_ui_timer.start()
        self._micro_fade(self.scan_status,180,0.30)
        self._micro_fade(self.scan_desc,230,0.28)

    def _tick_scan_clock(self):
        started=getattr(self,"scan_started",None)
        if started is None:
            return
        elapsed=max(0.0,time.monotonic()-started)
        minutes=int(elapsed//60)
        seconds=int(elapsed%60)
        tenths=int((elapsed-int(elapsed))*10)
        self.scan_elapsed.setText(f"Tempo trascorso: {minutes:02d}:{seconds:02d}.{tenths}")
        if not self._scan_has_progress:
            self._scan_prepare_phase=(self._scan_prepare_phase+1)%12
            dots="."*(1+(self._scan_prepare_phase//4))
            self.scan_current.setText("Preparazione scansione"+dots)

    def start_scan(self,roots,label):
        if self.scan_thread and self.scan_thread.isRunning():
            return
        self._begin_scan_feedback(label)
        kind="quick" if label=="Scansione rapida" else "full"
        self._current_scan_kind=kind
        try:
            self._current_scan_db_id=self.db.start_scan_record(kind)
            self._alerted_hashes.clear()
            self.scan_thread=ScanThread(roots,self.settings,self.reputation_engine)
            self.scan_thread.progress.connect(self.scan_progress_update)
            self.scan_thread.detection.connect(self.scan_detection)
            self.scan_thread.finished_summary.connect(self.scan_finished)
            self.scan_thread.start()
        except Exception:
            self.scan_ui_timer.stop()
            self.scan_indicator.set_active(False)
            self._set_scan_buttons_enabled(True)
            self.cancel_scan_btn.hide()
            self._set_scan_state("threat")
            self.scan_status.setText("Impossibile avviare la scansione")
            self.scan_desc.setText("Si è verificato un errore durante l'inizializzazione.")
            raise

    def _animate_scan_progress_to(self,target):
        target=max(self.scan_progress.minimum(),min(int(target),self.scan_progress.maximum()))
        if not self.animations_enabled:
            self.scan_progress.setValue(target)
            return
        if self._scan_progress_animation and self._scan_progress_animation.state()==QPropertyAnimation.Running:
            self._scan_progress_animation.stop()
        anim=QPropertyAnimation(self.scan_progress,b"value",self)
        anim.setDuration(135)
        anim.setStartValue(self.scan_progress.value())
        anim.setEndValue(target)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        self._scan_progress_animation=anim
        anim.start()

    def scan_progress_update(self,i,t,path):
        if not self._scan_has_progress:
            self._scan_has_progress=True
            self._set_scan_state("analyzing")
            self.scan_status.setText(f"{self._current_scan_label} in corso")
            self.scan_desc.setText("Analisi dei file nelle aree selezionate.")
            self.scan_progress.setRange(0,max(1,t))
            self.scan_progress.setValue(0)
            self.scan_progress.setFormat("%p%")
            self._micro_fade(self.scan_status,170,0.45)
        if self.scan_progress.maximum()!=max(1,t):
            self.scan_progress.setMaximum(max(1,t))
        self._animate_scan_progress_to(i)
        self.scan_count.setText(f"{i:,} / {t:,} file")
        self.scan_current.setText(path)

    def scan_detection(self,report):
        a=report.assessment
        signed_ioc = self.db.match_ioc_hash(report.sha256) if hasattr(self.db, "match_ioc_hash") else None
        if report.sha256 in self._alerted_hashes or (signed_ioc is None and self.db.is_allowlisted(report.path,report.sha256)):
            return
        self._alerted_hashes.add(report.sha256)
        inserted=self.db.add_detection(report.path,report.sha256,a.score,a.level,json.dumps(a.reasons),"logged",dedupe_minutes=10)
        if inserted:
            self.scan_hits_count+=1
            self.scan_hits.setText(f"{self.scan_hits_count} elementi rilevati")
            self._set_scan_state("threat")
            QTimer.singleShot(720, lambda: self._set_scan_state("analyzing") if self.scan_thread and self.scan_thread.isRunning() else None)
            self._micro_fade(self.scan_hits,180,0.35)
            if a.score>=70:
                self.present_threat(report)

    def scan_finished(self,scanned,detections,cancelled,elapsed):
        ui_elapsed=max(float(elapsed),time.monotonic()-getattr(self,"scan_started",time.monotonic()))
        self.scan_ui_timer.stop()
        self.scan_indicator.set_active(False)
        self.cancel_scan_btn.hide()
        self._set_scan_buttons_enabled(True)
        if self._scan_progress_animation and self._scan_progress_animation.state()==QPropertyAnimation.Running:
            self._scan_progress_animation.stop()
        if self.scan_progress.maximum()==0:
            self.scan_progress.setRange(0,max(1,scanned))
        if not cancelled:
            self.scan_progress.setValue(self.scan_progress.maximum())
            self.scan_progress.setFormat("100%")
        else:
            self.scan_progress.setFormat("%p%")
        self._set_scan_state("idle" if cancelled else ("warning" if detections else "safe"))
        self.scan_status.setText("Scansione annullata" if cancelled else ("Scansione completata · verifica richiesta" if detections else "Sistema sicuro"))
        self.scan_desc.setText(f"{scanned:,} file analizzati · {detections} elementi da verificare")
        minutes=int(ui_elapsed//60)
        seconds=int(ui_elapsed%60)
        tenths=int((ui_elapsed-int(ui_elapsed))*10)
        self.scan_elapsed.setText(f"Tempo trascorso: {minutes:02d}:{seconds:02d}.{tenths}")
        if not cancelled:
            self.scan_current.setText("Analisi completata. Il sistema resta protetto.")
        self._micro_fade(self.scan_status,230,0.22)
        self._micro_fade(self.scan_desc,260,0.25)
        if self._current_scan_db_id is not None:
            self.db.finish_scan_record(self._current_scan_db_id,scanned,detections,cancelled)
            self._current_scan_db_id=None
        self.refresh_dashboard()

    def cancel_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            # Set the cancellation flag first so enumeration/hash loops see it
            # before any further UI work.
            self.scan_thread.cancel()
            self.cancel_scan_btn.setEnabled(False)
            self.cancel_scan_btn.setText("Annullamento…")
            self._set_scan_state("scanning")
            self.scan_status.setText("Annullamento scansione…")
            self.scan_desc.setText(
                "Interruzione richiesta. BC Sentinel sta chiudendo "
                "in sicurezza l'operazione corrente."
            )
            self.scan_current.setText("Arresto del worker in corso…")
            self.scan_indicator.set_active(
                True,
                animate=self.animations_enabled,
            )
            self._micro_fade(self.scan_status,160,0.45)

    # ---------- detection / realtime ----------
    def present_threat(self,report):
        analyst=self.analyst if self.db.get_setting("ai_enabled","0")=="1" else None
        attribution=self._attribution_for_path(report.path)
        self._notify(
            "Minaccia rilevata",
            f"{Path(report.path).name} · {report.assessment.level} "
            f"{report.assessment.score}/100",
            "critical",
        )
        dlg=ThreatDialog(
            report,
            self,
            analyst=analyst,
            attribution=attribution,
        )
        dlg.exec()
        decision = str(getattr(dlg, "decision", "") or "")
        if not decision:
            return
        try:
            if decision == "quarantine":
                if self._service_owns_protection():
                    result = self.telemetry_client.threat_file_action(
                        "quarantine",
                        report.path,
                        report.sha256,
                        score=report.assessment.score,
                        level=report.assessment.level,
                        reasons=list(report.assessment.reasons or []),
                        approved=True,
                    )
                    if not result.get("ok"):
                        raise RuntimeError(
                            self.telemetry_client.last_error or
                            "Il Protection Service ha rifiutato la quarantena."
                        )
                else:
                    self.quarantine.quarantine(
                        report.path,
                        report.assessment.score,
                        "; ".join(report.assessment.reasons),
                        expected_sha256=report.sha256,
                    )
                self.db.update_detection_action(report.sha256, "quarantined")
                self._record_threat_decision(report, "quarantine", "success")
            elif decision == "delete":
                if self._service_owns_protection():
                    result = self.telemetry_client.threat_file_action(
                        "delete",
                        report.path,
                        report.sha256,
                        score=report.assessment.score,
                        level=report.assessment.level,
                        reasons=list(report.assessment.reasons or []),
                        approved=True,
                    )
                    if not result.get("ok"):
                        raise RuntimeError(
                            self.telemetry_client.last_error or
                            "Il Protection Service ha rifiutato l'eliminazione."
                        )
                else:
                    self.quarantine.delete_detected_file(report.path, report.sha256)
                self.db.update_detection_action(report.sha256, "deleted")
                self._record_threat_decision(report, "delete_permanently", "success")
            elif decision == "allow_hash":
                if self._service_owns_protection():
                    result = self.telemetry_client.add_exclusion("hash", report.sha256)
                    if not result.get("ok"):
                        raise RuntimeError(
                            self.telemetry_client.last_error or
                            "Il Protection Service ha rifiutato la allowlist hash."
                        )
                self.db.add_allowlist("hash", report.sha256)
                if self._service_owns_protection():
                    ack=self.telemetry_client.acknowledge_threat_decision(report.sha256,"allowlisted_hash","hash allowlist approved")
                    if not ack.get("ok"):
                        raise RuntimeError(self.telemetry_client.last_error or "Decisione non sincronizzata con il Protection Service.")
                self.db.update_detection_action(report.sha256, "allowlisted_hash")
                self._record_threat_decision(report, "allow_hash", "success")
            elif decision == "keep_once":
                if self._service_owns_protection():
                    ack=self.telemetry_client.acknowledge_threat_decision(report.sha256,"allowed_once","operator keep-once")
                    if not ack.get("ok"):
                        raise RuntimeError(self.telemetry_client.last_error or "Decisione non sincronizzata con il Protection Service.")
                self.db.update_detection_action(report.sha256, "allowed_once")
                self._record_threat_decision(report, "keep_once", "success")
            self.refresh_dashboard()
            self.refresh_history()
        except FileNotFoundError:
            self._record_threat_decision(report, decision, "failed", "file_not_found")
            QMessageBox.information(
                self, "File non disponibile",
                "Il file non è più presente. Potrebbe essere stato rimosso da un altro sistema di protezione."
            )
        except Exception as exc:
            self._record_threat_decision(report, decision, "failed", str(exc))
            QMessageBox.critical(self, "Operazione non completata", str(exc))

    def _record_threat_decision(self, report, action, status, detail=""):
        try:
            self.db.record_security_event(SecurityEvent(
                category="threat_decision",
                action=str(action),
                source="ui_threat_decision",
                score=int(report.assessment.score),
                path=str(report.path),
                reasons=list(report.assessment.reasons or [])[:8],
                data={
                    "status": str(status),
                    "detail": str(detail or ""),
                    "sha256": str(report.sha256 or ""),
                    "level": str(report.assessment.level or ""),
                    "explicit_user_decision": True,
                },
            ))
        except Exception:
            pass

    def on_realtime_detection(self,report): self.realtime_report.emit(report)
    def _handle_realtime_detection(self,report):
        if report.assessment.score>=70: self.present_threat(report)
    def on_ransomware_detection(self,path,assessment,attribution=None):
        if attribution is None or not getattr(attribution,"available",False):
            attribution=self._attribution_for_path(path)
        self.ransomware_report.emit(path,assessment,attribution)

    def _handle_ransomware_detection(self,path,assessment,attribution):
        process=""
        if attribution is not None and getattr(attribution,"available",False):
            process=f" · {attribution.name or attribution.path}"
        self._notify("Attività file sospetta",f"{assessment.level} {assessment.score}/100{process}","warning")
        dialog=RansomwareDialog(path,assessment,self,attribution=attribution)
        dialog.exec()

    # ---------- quarantine ----------
    def refresh_quarantine(self):
        local_rows=[dict(row) for row in self.quarantine.list_items(False)]
        for row in local_rows: row["_source"]="local"
        service_rows=[]
        if self._service_owns_protection():
            try:
                service_rows=[dict(row) for row in self.telemetry_client.quarantine_items()]
                for row in service_rows:row["_source"]="service"
            except Exception:
                service_rows=[]
        rows=local_rows+[r for r in service_rows if not bool(r.get("restored")) and not bool(r.get("deleted"))]
        self.qtable.setRowCount(len(rows))
        if hasattr(self, "q_empty"): self.q_empty.setVisible(not rows)
        for r,row in enumerate(rows):
            source="Protection Service" if row.get("_source")=="service" else "Locale"
            vals=[Path(row['original_path']).name,row['original_path'],str(row['score']),f"{row['reason']} · {source}","In quarantena"]
            for c,val in enumerate(vals): self.qtable.setItem(r,c,QTableWidgetItem(val))
            self.qtable.item(r,0).setData(Qt.UserRole,(row.get("_source","local"),row['id']))
        local_restored=[dict(row) for row in self.quarantine.list_restored()]
        for row in local_restored:row["_source"]="local"
        restored=local_restored+[r for r in service_rows if bool(r.get("restored")) and not bool(r.get("deleted"))]
        self.rtable.setRowCount(len(restored))
        if hasattr(self, "r_empty"): self.r_empty.setVisible(not restored)
        for r,row in enumerate(restored):
            vals=[row['ts'],row['original_path'],str(row['score']),row['reason']]
            for c,val in enumerate(vals): self.rtable.setItem(r,c,QTableWidgetItem(val))

    def selected_qid(self):
        r=self.qtable.currentRow(); return self.qtable.item(r,0).data(Qt.UserRole) if r>=0 and self.qtable.item(r,0) else None
    def restore_selected(self):
        selected=self.selected_qid()
        if not selected:return
        source,qid=selected if isinstance(selected,(tuple,list)) and len(selected)==2 else ("local",selected)
        if QMessageBox.warning(self,"Ripristino file","Il file è stato isolato perché considerato rischioso. Ripristinarlo comunque?",QMessageBox.Yes|QMessageBox.No)==QMessageBox.Yes:
            if source=="service":
                result=self.telemetry_client.restore_quarantine(qid,approved=True)
                if not result.get("ok"):
                    QMessageBox.critical(self,"Errore",self.telemetry_client.last_error or "Ripristino rifiutato dal Protection Service.")
            else:
                try:self.quarantine.restore(qid)
                except Exception as exc:QMessageBox.critical(self,"Errore",str(exc))
            self.refresh_quarantine(); self.refresh_dashboard()
    def delete_selected(self):
        selected=self.selected_qid()
        if not selected:return
        source,qid=selected if isinstance(selected,(tuple,list)) and len(selected)==2 else ("local",selected)
        if source=="service":
            QMessageBox.information(self,"Protection Service","La cancellazione definitiva degli elementi di quarantena service-owned non è esposta in v0.6 Beta. Ripristino e audit restano disponibili; la cancellazione privilegiata sarà introdotta solo con un gate dedicato.")
            return
        if QMessageBox.question(self,"Eliminazione definitiva","Questa operazione non può essere annullata.",QMessageBox.Yes|QMessageBox.No)==QMessageBox.Yes:
            self.quarantine.delete_permanently(qid); self.refresh_quarantine(); self.refresh_dashboard()
    def quarantine_details(self):
        r=self.qtable.currentRow()
        if r<0:return
        QMessageBox.information(self,"Dettagli quarantena",f"File: {self.qtable.item(r,0).text()}\nPercorso: {self.qtable.item(r,1).text()}\nRischio: {self.qtable.item(r,2).text()}\n\n{self.qtable.item(r,3).text()}")

    # ---------- history ----------
    def set_history_filter(self,key): self.history_filter=key; self.refresh_history()
    def _pending_threat_rows(self):
        rows=[]
        seen=set()
        if self._service_owns_protection():
            try:
                for raw in self.telemetry_client.pending_threats():
                    item=dict(raw); item["_source"]="Protection Service"
                    digest=str(item.get("sha256") or "").casefold()
                    if digest:
                        seen.add(digest)
                    rows.append(item)
            except Exception:
                pass
        try:
            for raw in self.db.pending_threat_decisions(100):
                item=dict(raw); digest=str(item.get("sha256") or "").casefold()
                if digest and digest in seen:
                    continue
                item["_source"]="GUI locale"
                rows.append(item)
        except Exception:
            pass
        rows.sort(key=lambda x:(-int(x.get("score") or 0), str(x.get("ts") or "")), reverse=False)
        return rows[:100]

    def _refresh_security_inbox(self):
        if not hasattr(self, "security_inbox_table"):
            return
        rows=self._pending_threat_rows()
        count=len(rows)
        self.security_inbox_summary.setText(
            "Decisione richiesta: quarantena consigliata per le detection qualificate." if count
            else "Nessuna minaccia in attesa di decisione."
        )
        self.security_inbox_badge.setText(f"{count} da decidere")
        self._set_badge_tone(self.security_inbox_badge, "danger" if count else "safe")
        self.security_inbox_empty.setVisible(not rows)
        self.security_inbox_table.setVisible(bool(rows))
        self.security_inbox_table.setRowCount(count)
        for r,row in enumerate(rows):
            path=str(row.get("path") or "")
            vals=[Path(path).name or path, str(row.get("score") or 0), str(row.get("level") or ""), str(row.get("_source") or "")]
            for c,val in enumerate(vals):
                item=QTableWidgetItem(val)
                if c==0:
                    item.setToolTip(path)
                    item.setData(Qt.UserRole, dict(row))
                self.security_inbox_table.setItem(r,c,item)
        self.security_inbox_review.setEnabled(self.security_inbox_table.currentRow() >= 0 and count > 0)

    def _security_inbox_selection_changed(self):
        if hasattr(self, "security_inbox_review"):
            self.security_inbox_review.setEnabled(self.security_inbox_table.currentRow() >= 0)

    def _ack_pending_threat(self, row, action, detail=""):
        digest=str(row.get("sha256") or "").casefold()
        source=str(row.get("_source") or "")
        if source == "Protection Service" and self._service_owns_protection():
            result=self.telemetry_client.acknowledge_threat_decision(digest, action, detail)
            if not result.get("ok"):
                raise RuntimeError(self.telemetry_client.last_error or "Impossibile aggiornare la Security Inbox del servizio.")
        try:
            self.db.update_detection_action(digest, action)
        except Exception:
            pass

    def _review_pending_threat(self):
        r=self.security_inbox_table.currentRow() if hasattr(self,"security_inbox_table") else -1
        if r<0:
            return
        item=self.security_inbox_table.item(r,0)
        row=dict(item.data(Qt.UserRole) or {}) if item else {}
        path=Path(str(row.get("path") or ""))
        digest=str(row.get("sha256") or "").casefold()
        if not path.exists():
            try:self._ack_pending_threat(row,"missing","file no longer exists")
            except Exception:pass
            self.refresh_history()
            QMessageBox.information(self,"File non disponibile","La minaccia resta nello storico, ma il file non è più presente.")
            return
        try:
            verification=StaticScanner(self.settings, reputation_engine=self.reputation_engine, db=self.db).scan_file(path)
        except Exception as exc:
            QMessageBox.critical(self,"Verifica non completata",str(exc)); return
        if verification.sha256.casefold()!=digest:
            try:self._ack_pending_threat(row,"superseded","file content changed since detection")
            except Exception:pass
            self.refresh_history()
            QMessageBox.warning(self,"File modificato","Il contenuto non coincide più con la detection originale. BC Sentinel non applicherà una decisione al file sostitutivo.")
            return
        try:
            reasons=json.loads(str(row.get("reasons_json") or "[]"))
            if not isinstance(reasons,list): reasons=[]
        except Exception:
            reasons=[]
        stored_score=int(row.get("score") or 0); stored_level=str(row.get("level") or "HIGH")
        if stored_score < 70:
            try:self._ack_pending_threat(row,"no_longer_qualified","stored score below decision threshold")
            except Exception:pass
            self.refresh_history(); return
        verification.assessment=ThreatAssessment(stored_score, stored_level, [str(x) for x in reasons], [])
        self.present_threat(verification)
        self.refresh_history()

    def _refresh_web_center(self):
        if not hasattr(self, "web_findings_table"):
            return
        status={}
        service_active=self.telemetry_service_status is not None
        if service_active:
            try:
                status=self.telemetry_client.web_status() or {}
            except Exception:
                status={}
        dns_etw=bool(status.get("dns_etw"))
        domain_iocs=int(status.get("domain_iocs") or self.db.ioc_kind_count("domain"))
        trusted_domains=int(status.get("trusted_domains") or 0)
        trust_conflicts=int(status.get("trust_conflicts") or 0)
        reputation_domains=int(status.get("reputation_domains") or 0)
        tracked_downloads=int(status.get("tracked_downloads") or 0)
        mode=str(status.get("mode") or "observe_recommend")
        actionable=int(status.get("actionable_findings") or 0)
        active_mode=mode=="active_reversible"
        self.web_center_badge.setText("Protezione attiva" if active_mode and dns_etw else "DNS ETW attivo" if dns_etw else "Observe only")
        self._set_badge_tone(self.web_center_badge, "safe" if dns_etw else "warning")
        conflict_text=f" · {trust_conflicts} fiducia override da IOC" if trust_conflicts else ""
        self.web_center_summary.setText(
            f"{domain_iocs} IOC firmati · {trusted_domains} domini fidati · {reputation_domains} domini osservati · {tracked_downloads} download tracciati · {actionable} finding da valutare{conflict_text} · exact-domain trust · shared-IP guard · nessun MITM HTTPS / auto-blocco."
        )
        rows=[]
        if service_active:
            try: rows=self.telemetry_client.web_findings(50) or []
            except Exception: rows=[]
        if not rows and hasattr(self.db,"recent_web_findings"):
            try: rows=[dict(row) for row in self.db.recent_web_findings(50,min_score=1)]
            except Exception: rows=[]
        self.web_findings_empty.setVisible(not rows)
        self.web_findings_table.setVisible(bool(rows))
        self.web_findings_table.setRowCount(len(rows))
        for r,raw in enumerate(rows):
            row=dict(raw)
            domain=str(row.get("domain") or row.get("path") or "—")
            score=int(row.get("score") or 0)
            verdict=str(row.get("decision") or row.get("source") or "review")
            if bool(row.get("shared_ip")):
                verdict="shared/CDN · review"
            if bool(row.get("trusted_domain")):
                verdict="IOC override fiducia" if bool(row.get("trust_overridden")) else "dominio fidato"
            process=str(row.get("process_name") or "—")
            evidence=row.get("evidence") or {}
            if isinstance(evidence,dict) and evidence.get("browser_family"):
                process=f"{process} · {evidence.get('browser_family')}"
            status_text=str(row.get("status") or "pending")
            values=(domain,str(score),verdict,process,status_text)
            for c,val in enumerate(values):
                item=QTableWidgetItem(val)
                if c==0:item.setData(Qt.UserRole,row)
                self.web_findings_table.setItem(r,c,item)
        trust_rows=[]
        if service_active:
            try: trust_rows=self.telemetry_client.web_domain_trust() or []
            except Exception: trust_rows=[]
        if hasattr(self,"web_trust_empty"):
            self.web_trust_empty.setVisible(not trust_rows)
        if hasattr(self,"web_trust_table"):
            self.web_trust_table.setVisible(bool(trust_rows))
            self.web_trust_table.setRowCount(len(trust_rows))
            for r,raw in enumerate(trust_rows):
                trust=dict(raw)
                domain=str(trust.get("domain") or "—")
                state="IOC override" if bool(trust.get("overridden_by_signed_ioc")) else "Fidato · exact"
                reason=str(trust.get("reason") or "—")
                for c,val in enumerate((domain,state,reason)):
                    item=QTableWidgetItem(val)
                    if c==0:item.setData(Qt.UserRole,trust)
                    self.web_trust_table.setItem(r,c,item)
        download_rows=[]
        if service_active:
            try: download_rows=self.telemetry_client.web_downloads(50) or []
            except Exception: download_rows=[]
        if not download_rows and hasattr(self.db,"recent_web_downloads"):
            try: download_rows=[dict(row) for row in self.db.recent_web_downloads(50)]
            except Exception: download_rows=[]
        if hasattr(self,"web_downloads_empty"):
            self.web_downloads_empty.setVisible(not download_rows)
        if hasattr(self,"web_downloads_table"):
            self.web_downloads_table.setVisible(bool(download_rows))
            self.web_downloads_table.setRowCount(len(download_rows))
            for r,raw in enumerate(download_rows):
                row=dict(raw)
                file_name=Path(str(row.get("file_path") or "")).name or str(row.get("file_path") or "—")
                domain=str(row.get("domain") or "—")
                browser=str(row.get("browser_family") or row.get("browser_process_name") or "—")
                file_score=int(row.get("file_score") or 0)
                file_level=str(row.get("file_level") or "UNSCANNED")
                verdict=f"{file_level} {file_score}/100" if file_level != "UNSCANNED" else "Non ancora valutato"
                state=str(row.get("status") or row.get("stage") or "tracked")
                for c,val in enumerate((file_name,domain,browser,verdict,state)):
                    item=QTableWidgetItem(str(val))
                    if c==0:item.setData(Qt.UserRole,row)
                    self.web_downloads_table.setItem(r,c,item)
        self._web_finding_selection_changed()
        self._web_trust_selection_changed()
        self._web_download_selection_changed()

    def _selected_web_finding(self):
        if not hasattr(self,"web_findings_table"):
            return {}
        r=self.web_findings_table.currentRow()
        if r<0:return {}
        item=self.web_findings_table.item(r,0)
        return dict(item.data(Qt.UserRole) or {}) if item else {}

    def _selected_web_trust(self):
        if not hasattr(self,"web_trust_table"):
            return {}
        r=self.web_trust_table.currentRow()
        if r<0:return {}
        item=self.web_trust_table.item(r,0)
        return dict(item.data(Qt.UserRole) or {}) if item else {}

    def _web_trust_selection_changed(self):
        row=self._selected_web_trust()
        if hasattr(self,"web_revoke_trust"):
            self.web_revoke_trust.setEnabled(bool(row) and bool(row.get("domain")) and self.telemetry_service_status is not None)
            if bool(row.get("overridden_by_signed_ioc")):
                self.web_revoke_trust.setToolTip("La fiducia è già ignorata da un IOC firmato; la revoca rimuove anche la policy locale storica.")
            else:
                self.web_revoke_trust.setToolTip("Revoca la fiducia persistente exact-domain tramite UAC.")

    def _selected_web_download(self):
        if not hasattr(self,"web_downloads_table"):
            return {}
        r=self.web_downloads_table.currentRow()
        if r<0:return {}
        item=self.web_downloads_table.item(r,0)
        return dict(item.data(Qt.UserRole) or {}) if item else {}

    def _web_download_selection_changed(self):
        row=self._selected_web_download()
        if hasattr(self,"web_download_details"):
            self.web_download_details.setEnabled(bool(row) and bool(row.get("download_id")))

    def _show_selected_web_download_details(self):
        row=self._selected_web_download()
        download_id=str(row.get("download_id") or "")
        if not download_id:
            return
        detail=row
        if self.telemetry_service_status is not None:
            try: detail=self.telemetry_client.web_download_detail(download_id) or row
            except Exception: detail=row
        origin_signed=bool(detail.get("origin_signed_ioc"))
        lines=[
            f"Download: {download_id}",
            f"File: {detail.get('file_path') or '—'}",
            f"Dominio origine: {detail.get('domain') or '—'}",
            f"IP remoto: {detail.get('remote_address') or '—'}",
            f"Browser: {detail.get('browser_family') or detail.get('browser_process_name') or '—'}",
            f"Stadio: {detail.get('stage') or '—'}",
            f"Rischio origine: {int(detail.get('origin_score') or 0)}/100 · {'IOC firmato' if origin_signed else detail.get('origin_source') or 'locale'}",
            f"Verdetto file: {detail.get('file_level') or 'UNSCANNED'} {int(detail.get('file_score') or 0)}/100",
            f"Stato: {detail.get('status') or 'tracked'}",
        ]
        if detail.get("executed_pid"):
            lines.append(f"Eseguito: sì · PID {detail.get('executed_pid')}" + (f" · Incident {detail.get('incident_id')}" if detail.get('incident_id') else ""))
        lines.append("\nIl rischio del dominio non sostituisce mai il verdict del file: quarantena/eliminazione restano legate alla scansione HIGH/CRITICAL.")
        QMessageBox.information(self,"Download Protection · Dettagli download","\n".join(lines))

    def _web_finding_selection_changed(self):
        row=self._selected_web_finding()
        pending=str(row.get("status") or "") == "pending"
        source=str(row.get("source") or "")
        trusted=bool(row.get("trusted_domain"))
        signed=source.startswith("signed_ioc") or bool(row.get("trust_overridden"))
        domain=bool(str(row.get("domain") or ""))
        if hasattr(self,"web_details"):
            self.web_details.setEnabled(bool(row) and domain)
        if hasattr(self,"web_ignore_once"):
            self.web_ignore_once.setEnabled(bool(row) and pending)
        if hasattr(self,"web_trust_domain"):
            self.web_trust_domain.setEnabled(bool(row) and pending and domain and not trusted and not signed and self.telemetry_service_status is not None)
            self.web_trust_domain.setToolTip("Fiducia persistente exact-domain con UAC. Gli IOC firmati hanno sempre precedenza.")
        eligible=(pending and bool(row.get("block_recommended")) and not bool(row.get("shared_ip")) and bool(row.get("remote_address")))
        if hasattr(self,"web_block_15m"):
            self.web_block_15m.setEnabled(bool(eligible))
            if row and pending and bool(row.get("shared_ip")):
                self.web_block_15m.setToolTip("Blocco disabilitato: IP condiviso/CDN. BC Sentinel evita il blocco dell'intero indirizzo.")
            else:
                self.web_block_15m.setToolTip("Crea un BLOCK BC Sentinel reversibile di 15 minuti dopo nuova verifica IOC/DNS.")

    def _ignore_selected_web_finding(self):
        row=self._selected_web_finding()
        finding_id=str(row.get("finding_id") or "")
        if not finding_id:return
        ok=False
        if self.telemetry_service_status is not None:
            try: ok=bool(self.telemetry_client.web_finding_decide(finding_id,"ignore_once","operator ignore once").get("ok"))
            except Exception: ok=False
        else:
            try:
                self.db.resolve_web_finding(finding_id,status="ignored_once",resolution="operator ignore once")
                ok=True
            except Exception:ok=False
        if not ok:
            QMessageBox.warning(self,"Web Protection","Impossibile registrare la decisione.")
        self._refresh_web_center()

    def _trust_selected_web_domain(self):
        row=self._selected_web_finding()
        domain=str(row.get("domain") or "").strip()
        finding_id=str(row.get("finding_id") or "")
        if not domain or self.telemetry_service_status is None:
            return
        if str(row.get("source") or "").startswith("signed_ioc") or bool(row.get("trust_overridden")):
            QMessageBox.warning(self,"Fiducia rifiutata","Un IOC firmato attivo ha precedenza: questo dominio non può essere consentito finché l'IOC resta valido.")
            return
        if QMessageBox.question(
            self,"Consenti dominio",
            f"Consentire in modo persistente SOLO il dominio esatto {domain}?\n\nLa fiducia non si estende automaticamente ai sottodomini e un IOC firmato futuro avrà sempre precedenza. L'azione richiede UAC.",
            QMessageBox.Yes|QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        try:
            result=self.telemetry_client.web_domain_trust_add(
                domain, reason="Operator approved exact-domain trust", finding_id=finding_id, approved=True
            )
        except Exception:
            result={"ok":False}
        if result.get("ok"):
            QMessageBox.information(self,"Dominio consentito",f"{domain} è ora fidato con scope exact-domain.\nGli IOC firmati restano prioritari.")
        else:
            QMessageBox.warning(self,"Fiducia non applicata",self.telemetry_client.last_error or "Il Protection Service ha rifiutato la modifica.")
        self._refresh_web_center()

    def _revoke_selected_web_domain_trust(self):
        row=self._selected_web_trust() or self._selected_web_finding()
        domain=str(row.get("domain") or "").strip()
        if not domain or self.telemetry_service_status is None:
            return
        if QMessageBox.question(self,"Revoca fiducia",f"Revocare la fiducia persistente per {domain}?",QMessageBox.Yes|QMessageBox.No) != QMessageBox.Yes:
            return
        try:
            result=self.telemetry_client.web_domain_trust_remove(domain,approved=True)
        except Exception:
            result={"ok":False}
        if not result.get("ok"):
            QMessageBox.warning(self,"Revoca non completata",self.telemetry_client.last_error or "Il Protection Service ha rifiutato la modifica.")
        self._refresh_web_center()

    def _show_selected_web_domain_details(self):
        row=self._selected_web_finding()
        domain=str(row.get("domain") or "").strip()
        if not domain:
            return
        reputation=None
        if self.telemetry_service_status is not None:
            try: reputation=self.telemetry_client.web_domain_reputation(domain)
            except Exception: reputation=None
        if not reputation:
            try: reputation=self.db.web_domain_reputation(domain)
            except Exception: reputation={"domain":domain,"observed":False}
        assessment=dict(reputation.get("current_assessment") or {}) if isinstance(reputation,dict) else {}
        provenance=list(assessment.get("provenance") or [])
        lines=[
            f"Dominio: {domain}",
            f"Osservazioni locali: {int(reputation.get('observations') or 0)}",
            f"Score massimo osservato: {int(reputation.get('max_score') or 0)}",
            f"Processi campionati: {int(reputation.get('process_count_sampled') or 0)}",
            f"Indirizzi campionati: {int(reputation.get('address_count_sampled') or 0)}",
            f"Fiducia locale: {'sì' if reputation.get('trusted_domain') else 'no'}",
            f"IOC firmato attivo: {'sì' if reputation.get('signed_ioc_active') else 'no'}",
        ]
        if provenance:
            lines.append("\nProvenance:")
            for item in provenance[:5]:
                if isinstance(item,dict): lines.append(f"• {item.get('tier')}: {item.get('state') or item.get('label') or item.get('scope') or ''}")
        QMessageBox.information(self,"Web Protection · Dettagli dominio","\n".join(lines))

    def _block_selected_web_finding(self):
        row=self._selected_web_finding()
        finding_id=str(row.get("finding_id") or "")
        if not finding_id:return
        if bool(row.get("shared_ip")):
            QMessageBox.warning(self,"Blocco non sicuro","Questo IP è condiviso/CDN. BC Sentinel non bloccherà l'intero indirizzo da sola evidenza di dominio.")
            return
        if self.telemetry_service_status is None:
            QMessageBox.warning(self,"Protection Service richiesto","Il containment web richiede il Protection Service privilegiato.")
            return
        if QMessageBox.question(
            self,"Blocca temporaneamente",
            f"Bloccare per 15 minuti l'IP {row.get('remote_address') or '—'} associato a {row.get('domain') or '—'}?\n\nBC Sentinel ricontrollerà IOC, PID, mapping DNS e shared-IP prima di creare la regola.",
            QMessageBox.Yes|QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        try:
            result=self.telemetry_client.web_containment_create(
                finding_id,ttl_seconds=900,approved=True,reason="Web Protection operator containment"
            )
        except Exception:
            result={"ok":False}
        if result.get("ok"):
            lease=result.get("lease") or {}
            QMessageBox.information(self,"Containment attivo",f"Blocco temporaneo creato.\nLease: {lease.get('lease_id') or '—'}\nScadenza automatica: 15 minuti.")
        else:
            detail=self.telemetry_client.last_error or "Il finding non è più qualificato: mapping DNS/IOC/shared-IP potrebbe essere cambiato."
            QMessageBox.warning(self,"Containment rifiutato",detail)
        self._refresh_web_center()

    def _analyze_web_url(self):
        raw=self.web_url_input.text().strip() if hasattr(self,"web_url_input") else ""
        if not raw:
            return
        result=None
        if self.telemetry_service_status is not None:
            try:result=self.telemetry_client.web_assess(raw)
            except Exception:result=None
        if not result:
            try:result=self.web_protection.assess_url(raw).to_dict()
            except Exception:result=None
        if not result:
            QMessageBox.warning(self,"Web Protection","Impossibile analizzare l'URL.")
            return
        reasons=list(result.get("reasons") or [])
        text=(
            f"Dominio: {result.get('indicator') or '—'}\n"
            f"Score: {int(result.get('score') or 0)}/100 · {result.get('level') or 'SAFE'}\n"
            f"Verdetto: {result.get('status') or 'unknown'}\n"
            f"Azione: {result.get('decision') or 'observe'}"
        )
        if reasons:
            text += "\n\nEvidenze:\n• " + "\n• ".join(str(x) for x in reasons[:6])
        if result.get("trusted_domain"):
            text += "\n\nFiducia locale exact-domain attiva. Gli IOC firmati hanno comunque precedenza."
        provenance=list(result.get("provenance") or [])
        if provenance:
            text += "\n\nProvenance:\n" + "\n".join(f"• {str(item.get('tier') or '')}" for item in provenance[:5] if isinstance(item,dict))
        if result.get("block_recommended"):
            text += "\n\nIl blocco è solo consigliato: richiede comunque una decisione esplicita e un IP risolto qualificato."
        QMessageBox.information(self,"Web Protection · Analisi URL",text)

    def refresh_history(self):
        self._refresh_security_inbox()
        self._refresh_web_center()
        rows=self.db.current_detection_history(500)
        if self.history_filter!="all": rows=[r for r in rows if r['level']==self.history_filter]
        if hasattr(self, "h_empty"): self.h_empty.setVisible(not rows)
        self.htable.setRowCount(len(rows)); labels={"logged":"Da decidere","quarantined":"In quarantena","restored":"Ripristinato","deleted":"Eliminato","allowed_once":"Mantenuto una volta","allowlisted_hash":"Hash consentito","missing":"File non presente","superseded":"File sostituito","no_longer_qualified":"Non più qualificato"}
        for r,row in enumerate(rows):
            vals=[row['ts'],row['path'],str(row['score']),row['level'],labels.get(row['action'],row['action'])]
            for c,val in enumerate(vals): self.htable.setItem(r,c,QTableWidgetItem(val))
    def cleanup_history(self):
        if QMessageBox.question(self,"Pulisci cronologia","Rimuovere eventi SAFE/LOW, duplicati e falsi positivi legacy? La quarantena non verrà cancellata.",QMessageBox.Yes|QMessageBox.No)!=QMessageBox.Yes:return
        stats=self.db.cleanup_detection_history(); QMessageBox.information(self,"Cronologia pulita",f"SAFE/LOW: {stats['low_score']}\nDuplicati: {stats['duplicates']}\nLegacy BC Sentinel: {stats['legacy_self']}"); self.refresh_history(); self.refresh_dashboard()

    # ---------- settings actions ----------
    def toggle_realtime(self,on):
        self.settings.realtime_enabled=bool(on); self._save_bool("realtime_enabled",on)
        if self._service_owns_protection():
            self._sync_protection_service_config({"realtime_enabled":bool(on)})
            self.realtime_running=bool((self.telemetry_client.status() or {}).get("realtime"))
        else:
            if on and not self.realtime_running:self.realtime_running=bool(self.realtime.start())
            elif not on and self.realtime_running:self.realtime.stop(); self.realtime_running=False
        self.refresh_dashboard(); self.refresh_protection()
    def toggle_ransomware(self,on):
        self.settings.ransomware_enabled=bool(on); self._save_bool("ransomware_enabled",on)
        if self._service_owns_protection():self._sync_protection_service_config({"ransomware_enabled":bool(on)})
        self.refresh_dashboard(); self.refresh_protection()
    def toggle_behavior(self,on):
        self.settings.behavior_enabled=bool(on); self._save_bool("behavior_enabled",on)
        if self._service_owns_protection():
            self._sync_protection_service_config({"behavior_enabled":bool(on)})
        elif on:self.procmon.start()
        else:self.procmon.stop()
        self.refresh_dashboard(); self.refresh_protection()
    def add_monitored_dir(self):
        raw=QFileDialog.getExistingDirectory(self,"Aggiungi cartella monitorata",str(Path.home()))
        if raw and raw not in self.settings.monitored_dirs:
            self.settings.monitored_dirs.append(raw); self.db.set_setting("monitored_dirs",json.dumps(self.settings.monitored_dirs)); self._sync_protection_service_config({"monitored_dirs":list(self.settings.monitored_dirs)}); self.refresh_settings_lists(); QMessageBox.information(self,"Riavvio monitor","La nuova cartella sarà applicata completamente al monitor real-time al prossimo riavvio del Protection Service.")
    def remove_monitored_dir(self):
        item=self.dirs_list.currentItem()
        if item and item.text() in self.settings.monitored_dirs:
            self.settings.monitored_dirs.remove(item.text()); self.db.set_setting("monitored_dirs",json.dumps(self.settings.monitored_dirs)); self._sync_protection_service_config({"monitored_dirs":list(self.settings.monitored_dirs)}); self.refresh_settings_lists()
    def add_allow_file(self):
        raw,_=QFileDialog.getOpenFileName(self,"Aggiungi file alla allowlist",str(Path.home()))
        if raw:
            self.db.add_allowlist("file",raw)
            if self._service_owns_protection():self.telemetry_client.request("add_exclusion",kind="file",value=raw)
            self.refresh_settings_lists()
    def add_allow_dir(self):
        raw=QFileDialog.getExistingDirectory(self,"Aggiungi cartella alla allowlist",str(Path.home()))
        if raw:
            self.db.add_allowlist("directory",raw)
            if self._service_owns_protection():self.telemetry_client.request("add_exclusion",kind="directory",value=raw)
            self.refresh_settings_lists()
    def remove_allow(self):
        item=self.allow_list.currentItem()
        if item:self.db.remove_allowlist(item.data(Qt.UserRole)); self.refresh_settings_lists()

    def toggle_ai(self,on):
        self.db.set_setting("ai_enabled","1" if on else "0")
        self.refresh_dashboard(); self.refresh_protection()

    def save_ai_model(self):
        model=self.ai_model_input.text().strip() or "qwen3:4b"
        self.db.set_setting("ai_model",model); self.analyst.model=model

    def test_ollama(self):
        self.save_ai_model(); self.ai_status.setText("Verifica…"); QApplication.processEvents()
        status=self.analyst.health(timeout=2.0)
        if status.get("ok"):
            models=status.get("models") or []
            self.ai_status.setText("Connesso · modello disponibile" if self.analyst.model in models else ("Connesso · modello selezionato non trovato" if models else "Connesso"))
            self._set_inline_tone(self.ai_status, "safe")
        else:
            self.ai_status.setText("Ollama non raggiungibile"); self._set_inline_tone(self.ai_status, "warning")

    def toggle_etw(self,on):
        self.settings.etw_enabled=bool(on)
        self._save_bool("etw_enabled",on)
        if self._service_owns_protection():self._sync_protection_service_config({"etw_enabled":bool(on)})
        self.telemetry_advanced_active=bool(on and self.telemetry_service_status and self.telemetry_service_status.get("etw",{}).get("running"))
        self.etw_running=self.telemetry_advanced_active
        self._refresh_telemetry_visual_state(); self.refresh_protection()

    def toggle_persistence(self,on):
        self.settings.persistence_enabled=bool(on); self._save_bool("persistence_enabled",on)
        if self._service_owns_protection():
            self._sync_protection_service_config({"persistence_enabled":bool(on)})
            self.persistence.stop()
            self.persistence_running=bool((self.telemetry_client.status() or {}).get("persistence"))
        elif on:
            if not (self.persistence._thread and self.persistence._thread.is_alive()):self.persistence_running=bool(self.persistence.start())
        else:
            self.persistence.stop(); self.persistence_running=False
        self.refresh_protection()

    def toggle_network(self,on):
        self.settings.network_enabled=bool(on); self._save_bool("network_enabled",on)
        if self._service_owns_protection():
            ok=self.telemetry_client.set_network_collection(bool(on))
            if not ok:
                QMessageBox.warning(self,"Protection Service",self.telemetry_client.last_error or "Modifica rete rifiutata dal servizio.")
            self.network_monitor.stop()
            self.network_running=bool((self.telemetry_client.status() or {}).get("network"))
        elif on:
            self.network_running=bool(self.network_monitor.start())
        else:
            self.network_monitor.stop(); self.network_running=False
        if hasattr(self,"activity_summary"):self.refresh_activity()
        self.refresh_protection()

    def toggle_reputation(self,on):
        self.settings.reputation_enabled=bool(on)
        self._save_bool("reputation_enabled",on)
        self.refresh_protection()

    def toggle_notifications(self,on):
        self.settings.notifications_enabled=on; self._save_bool("notifications_enabled",on)

    def toggle_close_to_tray(self,on):
        self.settings.close_to_tray=on; self._save_bool("close_to_tray",on)

    def toggle_animations(self,on):
        self.settings.animations_enabled=on; self.animations_enabled=on; self._save_bool("animations_enabled",on)

    def open_logs(self):
        try:
            LOG_DIR.mkdir(parents=True,exist_ok=True)
            if os.name=="nt":os.startfile(str(LOG_DIR))
        except Exception as exc:QMessageBox.critical(self,"Log",str(exc))

    # ---------- Windows startup ----------
    def is_autostart_enabled(self):
        return self.startup.enabled()

    def toggle_autostart(self,on):
        try:self.startup.set_enabled(on)
        except Exception as exc:QMessageBox.critical(self,"Avvio automatico",str(exc))
