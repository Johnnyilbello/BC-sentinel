from __future__ import annotations

"""B13-1 consumer notification center and tray UX.

The UI is intentionally non-destructive. Alert CTAs navigate to existing review
surfaces or invoke an injected review callback; they never quarantine, delete,
repair, terminate a process, mutate trust or restore a file directly.
"""

from typing import Callable

from PySide6.QtCore import QSize, QTimer, Qt
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from sentinel import beta12_product_integration_ui as b128_ui
from sentinel import beta13_safe_response as response
from sentinel import home_security_ui
from sentinel.ui_design_system import COLORS, make_icon

ALERTS_PAGE_NAME = "Avvisi"


class TrayNotificationAdapter:
    """Best-effort local Windows/Qt tray notifier with no security authority."""

    def __init__(self, tray: QSystemTrayIcon | object | None = None) -> None:
        self._tray = tray
        self._owned_tray = False

    def show(self, notice: response.ConsumerNotification) -> dict[str, object]:
        notice.validate()
        tray = self._tray
        if tray is None:
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return {
                    "available": False,
                    "shown": False,
                    "notification_id": notice.notification_id,
                    "reason": "system_tray_unavailable",
                }
            tray = QSystemTrayIcon(make_icon("shield", COLORS["accent_bright"], 20))
            tray.setToolTip("BC Sentinel")
            tray.show()
            self._tray = tray
            self._owned_tray = True

        show = getattr(tray, "show", None)
        if callable(show):
            show()
        show_message = getattr(tray, "showMessage", None)
        if not callable(show_message):
            return {
                "available": True,
                "shown": False,
                "notification_id": notice.notification_id,
                "reason": "show_message_unavailable",
            }

        icon = (
            QSystemTrayIcon.MessageIcon.Critical
            if notice.severity == "CRITICAL"
            else QSystemTrayIcon.MessageIcon.Warning
            if notice.severity == "HIGH"
            else QSystemTrayIcon.MessageIcon.Information
        )
        try:
            show_message("BC Sentinel", notice.summary, icon, 8000)
        except TypeError:
            # Allows deterministic fake tray objects in unit tests.
            show_message("BC Sentinel", notice.summary)
        return {
            "available": True,
            "shown": True,
            "notification_id": notice.notification_id,
            "severity": notice.severity,
            "raw_path_exposed": False,
            "command_line_exposed": False,
        }

    def close(self) -> None:
        tray = self._tray
        if tray is not None and self._owned_tray:
            hide = getattr(tray, "hide", None)
            if callable(hide):
                hide()


class _AlertCard(QFrame):
    def __init__(
        self,
        notice: response.ConsumerNotification,
        *,
        on_review: Callable[[response.ConsumerNotification], None],
    ) -> None:
        super().__init__()
        notice.validate()
        self.notice = notice
        self.setObjectName("ActivityCard")
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(8)

        header = QLabel(f"{notice.severity} · {'NON LETTO' if not notice.read else 'LETTO'}")
        header.setObjectName("PosturePill")
        header.setProperty(
            "posture",
            "CRITICAL" if notice.severity in {"HIGH", "CRITICAL"} else "PROTECTED",
        )
        header.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)

        title = QLabel(notice.title)
        title.setObjectName("CardTitle")
        title.setWordWrap(True)

        summary = QLabel(notice.summary)
        summary.setObjectName("CardSummary")
        summary.setWordWrap(True)

        state = QLabel(
            "Quarantena reversibile consigliata"
            if notice.response_state == response.STATE_ACTION_REQUIRED
            else "Revisione richiesta"
            if notice.response_state == response.STATE_REVIEW_REQUIRED
            else "Informazione"
        )
        state.setObjectName("SectionHint")
        state.setWordWrap(True)

        button = QPushButton(
            "Apri quarantena"
            if notice.recommended_action == response.ACTION_QUARANTINE
            else "Rivedi rilevamento"
        )
        button.setObjectName("SecondaryButton")
        button.setAccessibleName(
            f"Rivedi avviso {notice.notification_id}"
        )
        button.clicked.connect(lambda checked=False: on_review(notice))
        self.review_button = button

        layout.addWidget(header, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(title)
        layout.addWidget(summary)
        layout.addWidget(state)
        layout.addWidget(button, 0, Qt.AlignmentFlag.AlignLeft)


class B13ResponseCenterPage(QWidget):
    def __init__(
        self,
        center: response.NotificationCenter,
        *,
        on_review: Callable[[response.ConsumerNotification], None],
    ) -> None:
        super().__init__()
        self.center = center
        self.on_review = on_review
        self._compact = False
        self._cards: list[_AlertCard] = []
        self.setObjectName("B13ResponseCenterPage")
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(24)

        hero = QFrame()
        hero.setObjectName("PostureHero")
        hero.setProperty("posture", "PROTECTED")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(28, 24, 28, 24)
        hero_layout.setSpacing(8)

        eyebrow = QLabel("BETA13 · RESPONSE CENTER")
        eyebrow.setObjectName("PosturePill")
        eyebrow.setProperty("posture", "PROTECTED")
        eyebrow.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        title = QLabel("Avvisi di sicurezza")
        title.setObjectName("HeroTitle")
        summary = QLabel(
            "Gli avvisi spiegano cosa è successo e quale azione è consigliata. "
            "BC Sentinel non esegue quarantena o ripristino senza conferma esplicita."
        )
        summary.setObjectName("HeroSummary")
        summary.setWordWrap(True)
        hero_layout.addWidget(eyebrow, 0, Qt.AlignmentFlag.AlignLeft)
        hero_layout.addWidget(title)
        hero_layout.addWidget(summary)
        root.addWidget(hero)

        self.status_label = QLabel()
        self.status_label.setObjectName("SectionHint")
        self.status_label.setWordWrap(True)
        root.addWidget(self.status_label)

        self.grid = QGridLayout()
        self.grid.setHorizontalSpacing(16)
        self.grid.setVerticalSpacing(16)
        root.addLayout(self.grid)

        boundary = QFrame()
        boundary.setObjectName("ActivityCard")
        boundary_layout = QVBoxLayout(boundary)
        boundary_layout.setContentsMargins(20, 18, 20, 18)
        boundary_layout.setSpacing(8)
        boundary_title = QLabel("Risposta sicura")
        boundary_title.setObjectName("CardTitle")
        boundary_copy = QLabel(
            "Ask First è il comportamento accettato: nessuna quarantena automatica silenziosa, "
            "nessuna cancellazione, nessuna terminazione processo. La quarantena verificata rimane reversibile."
        )
        boundary_copy.setObjectName("CardSummary")
        boundary_copy.setWordWrap(True)
        boundary_layout.addWidget(boundary_title)
        boundary_layout.addWidget(boundary_copy)
        root.addWidget(boundary)

        self.refresh()

    @staticmethod
    def _clear_grid(grid: QGridLayout) -> None:
        while grid.count():
            item = grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)

    def refresh(self) -> None:
        self._clear_grid(self.grid)
        self._cards = []
        items = self.center.items()
        self.status_label.setText(
            f"{self.center.unread_count()} non letti · {len(items)} avvisi locali · nessun dato inviato al cloud."
        )
        columns = 1 if self._compact else 2
        if not items:
            empty = QLabel("Nessun avviso di sicurezza.")
            empty.setObjectName("CardSummary")
            self.grid.addWidget(empty, 0, 0)
            return
        for index, notice in enumerate(items):
            card = _AlertCard(notice, on_review=self.on_review)
            self._cards.append(card)
            self.grid.addWidget(card, index // columns, index % columns)
        self.grid.setColumnStretch(0, 1)
        self.grid.setColumnStretch(1, 0 if self._compact else 1)

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        del mobile
        if compact == self._compact:
            return
        self._compact = compact
        self.refresh()

    @property
    def alert_cards(self) -> tuple[_AlertCard, ...]:
        return tuple(self._cards)


class B13ConsumerWindow(b128_ui.Beta12TrustCenterWindow):
    def __init__(
        self,
        *,
        snapshot: dict,
        notification_center: response.NotificationCenter,
        tray_adapter: TrayNotificationAdapter | None = None,
        status_provider=None,
    ) -> None:
        self.notification_center = notification_center
        self.tray_adapter = tray_adapter or TrayNotificationAdapter()
        self.reviewed_notification_ids: list[str] = []
        super().__init__(snapshot=snapshot, status_provider=status_provider)
        self._install_response_center()
        QTimer.singleShot(0, lambda: self._apply_responsive_layout(force=True))

    def _install_response_center(self) -> None:
        self.response_center_page = B13ResponseCenterPage(
            self.notification_center,
            on_review=self._review_notification,
        )
        self.response_center_scroll = home_security_ui._PageScroll(self.response_center_page)
        self.stack.addWidget(self.response_center_scroll)
        self.secondary_scrolls.append(self.response_center_scroll)

        button = QPushButton()
        button.setObjectName("NavItem")
        button.setIcon(make_icon("history", COLORS["text_secondary"], 20))
        button.setIconSize(QSize(20, 20))
        button.setCheckable(True)
        button.setEnabled(True)
        button.setToolTip("Apri avvisi di sicurezza")
        button.setAccessibleName("Avvisi di sicurezza")
        button.clicked.connect(lambda checked=False: self._navigate(ALERTS_PAGE_NAME))
        self.nav_buttons[ALERTS_PAGE_NAME] = button

        sidebar_layout = self.sidebar.layout()
        trust_index = sidebar_layout.indexOf(self.trust_center_nav_button)
        insert_at = trust_index + 1 if trust_index >= 0 else max(0, sidebar_layout.count() - 4)
        sidebar_layout.insertWidget(insert_at, button)
        self.response_center_nav_button = button
        self._sync_alert_nav_label()

    def _sync_alert_nav_label(self) -> None:
        button = getattr(self, "response_center_nav_button", None)
        if button is None:
            return
        if self._layout_mode == "mobile":
            button.setText("")
        else:
            unread = self.notification_center.unread_count()
            button.setText(ALERTS_PAGE_NAME if unread == 0 else f"{ALERTS_PAGE_NAME} ({unread})")

    def publish_notification(self, notice: response.ConsumerNotification) -> dict[str, object]:
        self.notification_center.publish(notice)
        self.response_center_page.refresh()
        self._sync_alert_nav_label()
        return self.tray_adapter.show(notice)

    def _review_notification(self, notice: response.ConsumerNotification) -> None:
        self.notification_center.mark_read(notice.notification_id)
        self.reviewed_notification_ids.append(notice.notification_id)
        self.response_center_page.refresh()
        self._sync_alert_nav_label()
        target_page = (
            "Quarantena"
            if notice.recommended_action == response.ACTION_QUARANTINE
            else "Protezione"
        )
        super()._navigate(target_page)

    def _navigate(self, page: str) -> None:
        if page != ALERTS_PAGE_NAME:
            super()._navigate(page)
            return
        self._current_page = ALERTS_PAGE_NAME
        self.stack.setCurrentWidget(self.response_center_scroll)
        for name, button in self.nav_buttons.items():
            selected = name == ALERTS_PAGE_NAME
            button.setChecked(selected)
            button.setObjectName("NavActive" if selected else "NavItem")
            button.style().unpolish(button)
            button.style().polish(button)
        if self._layout_mode != "mobile":
            self.topbar_title.setText("BC SENTINEL · Avvisi")
        QTimer.singleShot(0, self._sync_all_scroll_widths)

    def _apply_responsive_layout(self, force: bool = False) -> None:
        super()._apply_responsive_layout(force=force)
        page = getattr(self, "response_center_page", None)
        if page is not None:
            compact = self._layout_mode in {"compact", "mobile"}
            page.set_compact(compact, self._layout_mode == "mobile")
        self._sync_alert_nav_label()

    def closeEvent(self, event) -> None:  # noqa: N802
        try:
            self.tray_adapter.close()
        finally:
            super().closeEvent(event)


def _sample_center() -> response.NotificationCenter:
    center = response.NotificationCenter()
    plans = (
        response.SafeResponsePlan(
            "b131-critical",
            "Minaccia ad alta priorità",
            "CRITICAL",
            0.98,
            response.STATE_ACTION_REQUIRED,
            response.ACTION_QUARANTINE,
            "Quarantena reversibile disponibile.",
            True,
            True,
            True,
            "a" * 64,
        ),
        response.SafeResponsePlan(
            "b131-review",
            "Rilevamento da verificare",
            "HIGH",
            None,
            response.STATE_REVIEW_REQUIRED,
            response.ACTION_REVIEW,
            "Target non idoneo alla quarantena.",
            False,
            False,
            False,
            "",
        ),
        response.SafeResponsePlan(
            "b131-info",
            "Attività registrata",
            "MEDIUM",
            0.55,
            response.STATE_NOTIFY_ONLY,
            response.ACTION_NONE,
            "Nessuna azione automatica.",
            False,
            False,
            False,
            "",
        ),
    )
    for index, plan in enumerate(plans, start=1):
        center.publish(response.notification_from_plan(plan, now=float(index)))
    return center


def smoke_test_window(snapshot: dict) -> dict[str, object]:
    app = QApplication.instance() or QApplication([])
    center = _sample_center()
    window = B13ConsumerWindow(
        snapshot=snapshot,
        notification_center=center,
        tray_adapter=TrayNotificationAdapter(),
    )
    widths = (1440, 960, 680, 560)
    overflow: dict[str, int] = {}
    try:
        window.show()
        app.processEvents()
        window._navigate(ALERTS_PAGE_NAME)
        for width in widths:
            window.resize(width, 820)
            window._apply_responsive_layout(force=True)
            app.processEvents()
            window.response_center_scroll.sync_width()
            app.processEvents()
            overflow[str(width)] = int(
                window.response_center_scroll.horizontalScrollBar().maximum()
            )

        buttons = [
            card.review_button for card in window.response_center_page.alert_cards
        ]
        passed = (
            window.stack.count() == 8
            and window.stack.currentWidget() is window.response_center_scroll
            and window.response_center_nav_button.isEnabled()
            and len(window.response_center_page.alert_cards) == 3
            and len(buttons) == 3
            and all(button.isEnabled() for button in buttons)
            and center.unread_count() == 3
            and all(value == 0 for value in overflow.values())
        )
        return {
            "passed": passed,
            "page_count": window.stack.count(),
            "alerts_selected": window.stack.currentWidget() is window.response_center_scroll,
            "alert_card_count": len(window.response_center_page.alert_cards),
            "review_button_count": len(buttons),
            "unread_count": center.unread_count(),
            "horizontal_overflow": overflow,
            "nav_enabled": window.response_center_nav_button.isEnabled(),
            "automatic_quarantine": False,
            "destructive_ui_action": False,
        }
    finally:
        window.close()
        app.processEvents()
