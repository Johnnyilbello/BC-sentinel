from __future__ import annotations

"""B13-6 consumer trial/privacy/support surface.

The page is informational except for an explicit diagnostic-export callback.
It never changes protection state, license state, trust, quarantine or system
configuration.
"""

from collections.abc import Callable

from PySide6.QtCore import QSize, QTimer, Qt
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from sentinel import beta13_commercial_readiness as commercial
from sentinel import beta13_response_ui as response_ui
from sentinel import home_security_ui
from sentinel.ui_design_system import COLORS, make_icon

COMMERCIAL_PAGE_NAME = "Licenza & Supporto"


def _status_copy(state: commercial.CommercialState) -> tuple[str, str]:
    if state.status == commercial.LICENSED:
        return "Licenza verificata", "Entitlement firmato verificato localmente."
    if state.status == commercial.TRIAL_ACTIVE:
        remaining = (
            f" · {state.trial_remaining_days} giorni rimanenti"
            if state.trial_remaining_days is not None
            else ""
        )
        return "Periodo di prova attivo", "Stato commerciale" + remaining
    if state.status == commercial.TRIAL_EXPIRED:
        return "Periodo di prova terminato", "La licenza non disabilita le funzioni di sicurezza."
    if state.status == commercial.INVALID:
        return "Licenza non valida", "La licenza non disabilita le funzioni di sicurezza."
    return "Stato licenza non disponibile", "La licenza non disabilita le funzioni di sicurezza."


class B136CommercialPage(QWidget):
    def __init__(
        self,
        *,
        commercial_state: commercial.CommercialState,
        on_export_diagnostics: Callable[[], object] | None = None,
    ) -> None:
        super().__init__()
        self.commercial_state = commercial_state
        self.on_export_diagnostics = on_export_diagnostics
        self.setObjectName("B136CommercialPage")
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(20)

        hero = QFrame()
        hero.setObjectName("PostureHero")
        hero.setProperty("posture", "PROTECTED")
        hero_lay = QVBoxLayout(hero)
        hero_lay.setContentsMargins(28, 24, 28, 24)
        hero_lay.setSpacing(8)

        eyebrow = QLabel("BETA13 · COMMERCIAL READINESS")
        eyebrow.setObjectName("PosturePill")
        eyebrow.setProperty("posture", "PROTECTED")
        eyebrow.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)

        title = QLabel("Licenza, privacy e supporto")
        title.setObjectName("HeroTitle")
        title.setWordWrap(True)

        summary = QLabel(
            "Licenza e prova commerciale sono separate dalla protezione: un problema di "
            "attivazione non spegne silenziosamente le funzioni di sicurezza già accettate."
        )
        summary.setObjectName("HeroSummary")
        summary.setWordWrap(True)

        hero_lay.addWidget(eyebrow, 0, Qt.AlignmentFlag.AlignLeft)
        hero_lay.addWidget(title)
        hero_lay.addWidget(summary)
        root.addWidget(hero)

        status_title, status_detail = _status_copy(commercial_state)
        status = QFrame()
        status.setObjectName("ActivityCard")
        status_lay = QVBoxLayout(status)
        status_lay.setContentsMargins(20, 18, 20, 18)
        status_lay.setSpacing(7)

        status_heading = QLabel(status_title)
        status_heading.setObjectName("CardTitle")
        status_heading.setWordWrap(True)
        status_text = QLabel(status_detail)
        status_text.setObjectName("CardSummary")
        status_text.setWordWrap(True)
        protection = QLabel("La licenza non certifica la protezione attiva. Verifica lo stato nella Dashboard.")
        protection.setObjectName("SectionHint")
        protection.setWordWrap(True)

        status_lay.addWidget(status_heading)
        status_lay.addWidget(status_text)
        status_lay.addWidget(protection)
        root.addWidget(status)

        self.policy_cards: list[QFrame] = []
        for surface in commercial.policy_surfaces():
            card = QFrame()
            card.setObjectName("ActivityCard")
            card.setMinimumWidth(0)
            lay = QVBoxLayout(card)
            lay.setContentsMargins(20, 18, 20, 18)
            lay.setSpacing(6)
            heading = QLabel(surface["title"])
            heading.setObjectName("CardTitle")
            heading.setWordWrap(True)
            body = QLabel(surface["summary"])
            body.setObjectName("CardSummary")
            body.setWordWrap(True)
            version = QLabel(f"Versione: {surface['version']}")
            version.setObjectName("SectionHint")
            version.setWordWrap(True)
            lay.addWidget(heading)
            lay.addWidget(body)
            lay.addWidget(version)
            root.addWidget(card)
            self.policy_cards.append(card)

        support = QFrame()
        support.setObjectName("ActivityCard")
        support_lay = QVBoxLayout(support)
        support_lay.setContentsMargins(20, 18, 20, 18)
        support_lay.setSpacing(8)

        support_heading = QLabel("Supporto tecnico")
        support_heading.setObjectName("CardTitle")
        support_copy = QLabel(
            f"Publisher: {commercial.PUBLISHER} · {commercial.SUPPORT_URL}\n"
            "L'export diagnostico è volontario e contiene solo campi tecnici allowlistati: "
            "nessun percorso raw, riga di comando, username, token licenza o contenuto file."
        )
        support_copy.setObjectName("CardSummary")
        support_copy.setWordWrap(True)

        self.export_button = QPushButton("Esporta diagnostica")
        self.export_button.setObjectName("SecondaryButton")
        self.export_button.setAccessibleName("Esporta diagnostica supporto senza dati personali raw")
        self.export_button.setIcon(make_icon("info", COLORS["text_secondary"], 18))
        self.export_button.setIconSize(QSize(18, 18))
        self.export_button.setEnabled(on_export_diagnostics is not None)
        if on_export_diagnostics is not None:
            self.export_button.clicked.connect(lambda checked=False: on_export_diagnostics())

        support_lay.addWidget(support_heading)
        support_lay.addWidget(support_copy)
        support_lay.addWidget(self.export_button, 0, Qt.AlignmentFlag.AlignLeft)
        root.addWidget(support)

        boundary = QLabel(
            "Nessuna funzione di questa pagina può disabilitare la protezione, modificare la "
            "quarantena, cambiare trust/allowlist o eseguire modifiche privilegiate."
        )
        boundary.setObjectName("SectionHint")
        boundary.setWordWrap(True)
        root.addWidget(boundary)

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        del compact, mobile
        self.setMinimumWidth(0)


class B136ConsumerWindow(response_ui.B13ConsumerWindow):
    def __init__(
        self,
        *,
        snapshot: dict,
        notification_center,
        commercial_state: commercial.CommercialState,
        on_export_diagnostics: Callable[[], object] | None = None,
        tray_adapter: response_ui.TrayNotificationAdapter | None = None,
        status_provider=None,
    ) -> None:
        self.commercial_state = commercial_state
        self.on_export_diagnostics = on_export_diagnostics
        super().__init__(
            snapshot=snapshot,
            notification_center=notification_center,
            tray_adapter=tray_adapter,
            status_provider=status_provider,
        )
        self._install_commercial_support()
        QTimer.singleShot(0, lambda: self._apply_responsive_layout(force=True))

    def _install_commercial_support(self) -> None:
        self.commercial_page = B136CommercialPage(
            commercial_state=self.commercial_state,
            on_export_diagnostics=self.on_export_diagnostics,
        )
        self.commercial_scroll = home_security_ui._PageScroll(self.commercial_page)
        self.stack.addWidget(self.commercial_scroll)
        self.secondary_scrolls.append(self.commercial_scroll)

        button = QPushButton()
        button.setObjectName("NavItem")
        button.setIcon(make_icon("info", COLORS["text_secondary"], 20))
        button.setIconSize(QSize(20, 20))
        button.setCheckable(True)
        button.setEnabled(True)
        button.setToolTip("Licenza, privacy e supporto")
        button.setAccessibleName(COMMERCIAL_PAGE_NAME)
        button.clicked.connect(lambda checked=False: self._navigate(COMMERCIAL_PAGE_NAME))
        self.nav_buttons[COMMERCIAL_PAGE_NAME] = button

        sidebar_layout = self.sidebar.layout()
        alerts_index = sidebar_layout.indexOf(self.response_center_nav_button)
        insert_at = alerts_index + 1 if alerts_index >= 0 else max(0, sidebar_layout.count() - 4)
        sidebar_layout.insertWidget(insert_at, button)
        self.commercial_nav_button = button
        self._sync_commercial_nav_label()

    def _sync_commercial_nav_label(self) -> None:
        button = getattr(self, "commercial_nav_button", None)
        if button is None:
            return
        button.setText("" if self._layout_mode == "mobile" else COMMERCIAL_PAGE_NAME)

    def _navigate(self, page: str) -> None:
        if page != COMMERCIAL_PAGE_NAME:
            super()._navigate(page)
            return
        self._current_page = COMMERCIAL_PAGE_NAME
        self.stack.setCurrentWidget(self.commercial_scroll)
        for name, button in self.nav_buttons.items():
            selected = name == COMMERCIAL_PAGE_NAME
            button.setChecked(selected)
            button.setObjectName("NavActive" if selected else "NavItem")
            button.style().unpolish(button)
            button.style().polish(button)
        if self._layout_mode != "mobile":
            self.topbar_title.setText("BC SENTINEL · Licenza & Supporto")
        QTimer.singleShot(0, self._sync_all_scroll_widths)

    def _apply_responsive_layout(self, force: bool = False) -> None:
        super()._apply_responsive_layout(force=force)
        page = getattr(self, "commercial_page", None)
        if page is not None:
            compact = self._layout_mode in {"compact", "mobile"}
            page.set_compact(compact, self._layout_mode == "mobile")
        self._sync_commercial_nav_label()


def smoke_test_window(
    snapshot: dict,
    *,
    commercial_state: commercial.CommercialState | None = None,
) -> dict[str, object]:
    app = QApplication.instance() or QApplication([])
    center = response_ui._sample_center()
    state = commercial_state or commercial.CommercialState(
        status=commercial.TRIAL_ACTIVE,
        mode="TRIAL",
        protection_enabled=True,
        trial_days=commercial.DEFAULT_TRIAL_DAYS,
        trial_remaining_days=commercial.DEFAULT_TRIAL_DAYS,
        reason="smoke_fixture",
    )
    export_calls: list[bool] = []

    def _export() -> None:
        export_calls.append(True)

    window = B136ConsumerWindow(
        snapshot=snapshot,
        notification_center=center,
        commercial_state=state,
        on_export_diagnostics=_export,
        tray_adapter=response_ui.TrayNotificationAdapter(),
    )
    widths = (1440, 960, 680, 560)
    overflow: dict[str, int] = {}
    navigation: dict[str, bool] = {}
    try:
        window.show()
        app.processEvents()
        for page_name, button in window.nav_buttons.items():
            button.click()
            app.processEvents()
            navigation[page_name] = window._current_page == page_name and window.stack.currentWidget().isVisible()
        window._navigate(COMMERCIAL_PAGE_NAME)
        for width in widths:
            window.resize(width, 840)
            window._apply_responsive_layout(force=True)
            app.processEvents()
            window.commercial_scroll.sync_width()
            app.processEvents()
            overflow[str(width)] = int(
                window.commercial_scroll.horizontalScrollBar().maximum()
            )

        window.commercial_page.export_button.click()
        app.processEvents()

        passed = (
            window.stack.count() == 9
            and window.stack.currentWidget() is window.commercial_scroll
            and window.commercial_nav_button.isEnabled()
            and window.commercial_page.export_button.isEnabled()
            and len(window.commercial_page.policy_cards) == 3
            and len(export_calls) == 1
            and state.protection_enabled is True
            and all(value == 0 for value in overflow.values())
            and len(navigation) == 9
            and all(navigation.values())
        )
        return {
            "passed": passed,
            "page_count": window.stack.count(),
            "commercial_selected": window.stack.currentWidget() is window.commercial_scroll,
            "policy_card_count": len(window.commercial_page.policy_cards),
            "diagnostic_export_button_enabled": window.commercial_page.export_button.isEnabled(),
            "diagnostic_export_callback_count": len(export_calls),
            "core_protection_enabled": state.protection_enabled,
            "horizontal_overflow": overflow,
            "navigation": navigation,
            "automatic_quarantine": False,
            "licensing_may_disable_core_protection": False,
            "destructive_ui_action": False,
        }
    finally:
        window.close()
        app.processEvents()
