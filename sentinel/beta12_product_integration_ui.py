from __future__ import annotations

"""B12-8 read-only Trust Center product integration."""

from typing import Any

from PySide6.QtCore import QSize, QTimer, Qt
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from sentinel import beta10_trust_center_ui as legacy_ui
from sentinel import beta12_product_integration as product
from sentinel import home_security_ui
from sentinel.ui_design_system import COLORS, make_icon

TRUST_PAGE_NAME = "Trust Center"


class Beta12TrustCenterPage(QWidget):
    def __init__(self, snapshot: dict[str, Any]) -> None:
        super().__init__()
        validation = product.validate_snapshot(snapshot)
        if not validation["passed"]:
            raise RuntimeError("B12-8 Trust Center snapshot refused: " + ";".join(validation["failures"]))
        self.snapshot = snapshot
        self.setObjectName("Beta12TrustCenterPage")
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self._compact = False
        self._mobile = False
        self._build_ui()

    @staticmethod
    def _clear_grid(grid: QGridLayout) -> None:
        while grid.count():
            item = grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(24)

        hero = QFrame()
        hero.setObjectName("PostureHero")
        hero.setProperty("posture", "PROTECTED")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(28, 24, 28, 24)
        hero_layout.setSpacing(8)

        eyebrow = QLabel("BETA12 · EVIDENZA · LOW NOISE")
        eyebrow.setObjectName("PosturePill")
        eyebrow.setProperty("posture", "PROTECTED")
        eyebrow.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        title = QLabel(str(self.snapshot["headline"]))
        title.setObjectName("HeroTitle")
        title.setWordWrap(True)
        summary = QLabel(str(self.snapshot["summary"]))
        summary.setObjectName("HeroSummary")
        summary.setWordWrap(True)
        hero_layout.addWidget(eyebrow, 0, Qt.AlignmentFlag.AlignLeft)
        hero_layout.addWidget(title)
        hero_layout.addWidget(summary)
        root.addWidget(hero)

        coverage = self.snapshot["coverage_summary"]
        self.summary_grid = QGridLayout()
        self.summary_grid.setHorizontalSpacing(16)
        self.summary_grid.setVerticalSpacing(16)
        self.summary_cards = [
            legacy_ui._SummaryCard("Verificati", str(coverage["VERIFIED"]), "Scenari con evidenza Windows accettata.", accent=True),
            legacy_ui._SummaryCard("Parziali", str(coverage["PARTIAL"]), "Copertura presente ma con limiti ancora espliciti."),
            legacy_ui._SummaryCard("Gap", str(coverage["GAP"]), "Scenari senza copertura dichiarata."),
        ]
        self._render_summary_cards(columns=3)
        root.addLayout(self.summary_grid)

        coverage_panel = QFrame()
        coverage_panel.setObjectName("ModulesPanel")
        coverage_layout = QVBoxLayout(coverage_panel)
        coverage_layout.setContentsMargins(24, 20, 24, 24)
        coverage_layout.setSpacing(16)
        coverage_title = QLabel("Protection Proof · Beta12")
        coverage_title.setObjectName("SectionTitle")
        coverage_hint = QLabel(
            "VERIFIED deriva solo dai checkpoint accettati. La UI non può promuovere coverage né nascondere i limiti."
        )
        coverage_hint.setObjectName("SectionHint")
        coverage_hint.setWordWrap(True)
        coverage_layout.addWidget(coverage_title)
        coverage_layout.addWidget(coverage_hint)
        self.scenario_grid = QGridLayout()
        self.scenario_grid.setHorizontalSpacing(16)
        self.scenario_grid.setVerticalSpacing(16)
        self.scenario_cards = [legacy_ui._ScenarioCard(item) for item in self.snapshot["scenarios"]]
        self._render_scenarios(columns=2)
        coverage_layout.addLayout(self.scenario_grid)
        root.addWidget(coverage_panel)

        capability_panel = QFrame()
        capability_panel.setObjectName("ModulesPanel")
        capability_layout = QVBoxLayout(capability_panel)
        capability_layout.setContentsMargins(24, 20, 24, 24)
        capability_layout.setSpacing(16)
        capability_title = QLabel("Capacità Beta12")
        capability_title.setObjectName("SectionTitle")
        capability_hint = QLabel(
            "Correlazione, process tree, ransomware attribution, reputazione locale e low-noise sono evidence-driven e read-only in questa vista."
        )
        capability_hint.setObjectName("SectionHint")
        capability_hint.setWordWrap(True)
        capability_layout.addWidget(capability_title)
        capability_layout.addWidget(capability_hint)
        self.capability_grid = QGridLayout()
        self.capability_grid.setHorizontalSpacing(16)
        self.capability_grid.setVerticalSpacing(16)
        self.capability_cards = [legacy_ui._CapabilityCard(item) for item in self.snapshot["capabilities"]]
        self._render_capabilities(columns=2)
        capability_layout.addLayout(self.capability_grid)
        root.addWidget(capability_panel)

        impact_panel = QFrame()
        impact_panel.setObjectName("ActivityCard")
        impact_layout = QVBoxLayout(impact_panel)
        impact_layout.setContentsMargins(20, 18, 20, 18)
        impact_layout.setSpacing(8)
        impact_title = QLabel("Low-Noise & Performance")
        impact_title.setObjectName("CardTitle")
        impact = self.snapshot["operational_impact"]
        if impact["measured"]:
            metrics = impact["metrics"]
            impact_text = (
                f"Misurato · p95 wall {metrics['p95_wall_ms']} ms · p95 CPU {metrics['p95_cpu_ms']} ms · "
                f"Δ RAM max {metrics['max_rss_delta_mib']} MiB · falsi positivi {metrics['max_false_positive_detections']} · "
                f"drift outcome {metrics['max_outcome_drift']} · interruzioni utente {metrics['max_user_interruptions']}."
            )
        else:
            impact_text = "Metriche B12-7 non caricate in questa sessione. La UI non inventa valori."
        impact_copy = QLabel(impact_text)
        impact_copy.setObjectName("CardSummary")
        impact_copy.setWordWrap(True)
        impact_layout.addWidget(impact_title)
        impact_layout.addWidget(impact_copy)
        root.addWidget(impact_panel)

        boundary_panel = QFrame()
        boundary_panel.setObjectName("ActivityCard")
        boundary_layout = QVBoxLayout(boundary_panel)
        boundary_layout.setContentsMargins(20, 18, 20, 18)
        boundary_layout.setSpacing(8)
        boundary_title = QLabel("Confini di protezione")
        boundary_title.setObjectName("CardTitle")
        boundary_copy = QLabel(
            "Local-first. Nessun accesso credenziali, nessun lookup cloud obbligatorio, nessuna quarantena/riparazione/restore "
            "automatica generale, nessuna terminazione processo e nessuna mutazione automatica della trust list."
        )
        boundary_copy.setObjectName("CardSummary")
        boundary_copy.setWordWrap(True)
        boundary_layout.addWidget(boundary_title)
        boundary_layout.addWidget(boundary_copy)
        root.addWidget(boundary_panel)

    def _render_summary_cards(self, *, columns: int) -> None:
        self._clear_grid(self.summary_grid)
        for index, card in enumerate(self.summary_cards):
            self.summary_grid.addWidget(card, index // columns, index % columns)
        for column in range(3):
            self.summary_grid.setColumnStretch(column, 1 if column < columns else 0)

    def _render_scenarios(self, *, columns: int) -> None:
        self._clear_grid(self.scenario_grid)
        for index, card in enumerate(self.scenario_cards):
            self.scenario_grid.addWidget(card, index // columns, index % columns)
        for column in range(2):
            self.scenario_grid.setColumnStretch(column, 1 if column < columns else 0)

    def _render_capabilities(self, *, columns: int) -> None:
        self._clear_grid(self.capability_grid)
        for index, card in enumerate(self.capability_cards):
            self.capability_grid.addWidget(card, index // columns, index % columns)
        for column in range(2):
            self.capability_grid.setColumnStretch(column, 1 if column < columns else 0)

    def set_compact(self, compact: bool, mobile: bool = False) -> None:
        if compact == self._compact and mobile == self._mobile:
            return
        self._compact = compact
        self._mobile = mobile
        self._render_summary_cards(columns=1 if compact else 3)
        self._render_scenarios(columns=1 if compact else 2)
        self._render_capabilities(columns=1 if compact else 2)


class Beta12TrustCenterWindow(home_security_ui.SecurityOverviewWindow):
    def __init__(self, *, snapshot: dict[str, Any], status_provider=None) -> None:
        self._beta12_snapshot = snapshot
        super().__init__(status_provider=status_provider)
        self._install_beta12_trust_center()
        QTimer.singleShot(0, lambda: self._apply_responsive_layout(force=True))

    def _install_beta12_trust_center(self) -> None:
        validation = product.validate_snapshot(self._beta12_snapshot)
        if not validation["passed"]:
            raise RuntimeError("B12-8 Trust Center window refused: " + ";".join(validation["failures"]))

        self.trust_center_page = Beta12TrustCenterPage(self._beta12_snapshot)
        self.trust_center_scroll = home_security_ui._PageScroll(self.trust_center_page)
        self.stack.addWidget(self.trust_center_scroll)
        self.secondary_scrolls.append(self.trust_center_scroll)

        button = QPushButton(TRUST_PAGE_NAME)
        button.setObjectName("NavItem")
        button.setIcon(make_icon("shield", COLORS["text_secondary"], 20))
        button.setIconSize(QSize(20, 20))
        button.setCheckable(True)
        button.setEnabled(True)
        button.setToolTip("Apri Trust Center Beta12")
        button.setAccessibleName("Trust Center Beta12")
        button.clicked.connect(lambda checked=False: self._navigate(TRUST_PAGE_NAME))
        self.nav_buttons[TRUST_PAGE_NAME] = button

        sidebar_layout = self.sidebar.layout()
        existing = [sidebar_layout.indexOf(widget) for name, widget in self.nav_buttons.items() if name != TRUST_PAGE_NAME]
        insert_at = max(existing) + 1 if existing else max(0, sidebar_layout.count() - 4)
        sidebar_layout.insertWidget(insert_at, button)
        self.trust_center_nav_button = button

    def _navigate(self, page: str) -> None:
        if page != TRUST_PAGE_NAME:
            super()._navigate(page)
            return
        self._current_page = TRUST_PAGE_NAME
        self.stack.setCurrentWidget(self.trust_center_scroll)
        for name, button in self.nav_buttons.items():
            selected = name == TRUST_PAGE_NAME
            button.setChecked(selected)
            button.setObjectName("NavActive" if selected else "NavItem")
            button.style().unpolish(button)
            button.style().polish(button)
        if self._layout_mode != "mobile":
            self.topbar_title.setText("BC SENTINEL · Trust Center")
        QTimer.singleShot(0, self._sync_all_scroll_widths)

    def _apply_responsive_layout(self, force: bool = False) -> None:
        super()._apply_responsive_layout(force=force)
        page = getattr(self, "trust_center_page", None)
        if page is not None:
            compact = self._layout_mode in {"compact", "mobile"}
            page.set_compact(compact, self._layout_mode == "mobile")
        button = getattr(self, "trust_center_nav_button", None)
        if button is not None:
            button.setText("" if self._layout_mode == "mobile" else TRUST_PAGE_NAME)


def smoke_test_window(snapshot: dict[str, Any]) -> dict[str, Any]:
    app = QApplication.instance() or QApplication([])
    window = Beta12TrustCenterWindow(snapshot=snapshot)
    widths = (1440, 960, 680, 560)
    overflow: dict[str, int] = {}
    try:
        window.show()
        app.processEvents()
        window._navigate(TRUST_PAGE_NAME)
        for width in widths:
            window.resize(width, 820)
            window._apply_responsive_layout(force=True)
            app.processEvents()
            window.trust_center_scroll.sync_width()
            app.processEvents()
            overflow[str(width)] = int(window.trust_center_scroll.horizontalScrollBar().maximum())

        action_buttons = window.trust_center_page.findChildren(QPushButton)
        passed = (
            window.stack.count() == 7
            and window.stack.currentWidget() is window.trust_center_scroll
            and window.trust_center_nav_button.isEnabled()
            and len(window.trust_center_page.scenario_cards) == 11
            and len(window.trust_center_page.capability_cards) == 7
            and len(action_buttons) == 0
            and all(value == 0 for value in overflow.values())
        )
        return {
            "passed": passed,
            "page_count": window.stack.count(),
            "trust_center_selected": window.stack.currentWidget() is window.trust_center_scroll,
            "scenario_card_count": len(window.trust_center_page.scenario_cards),
            "capability_card_count": len(window.trust_center_page.capability_cards),
            "action_button_count": len(action_buttons),
            "horizontal_overflow": overflow,
            "nav_enabled": window.trust_center_nav_button.isEnabled(),
        }
    finally:
        window.close()
        app.processEvents()
