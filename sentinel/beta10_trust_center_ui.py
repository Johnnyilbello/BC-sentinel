from __future__ import annotations

"""B10-8 customer-facing Trust Center UI.

The Trust Center extends the accepted BC Sentinel desktop shell without editing
frozen predecessor UI sources. It is intentionally read-only: the page presents
accepted protection evidence, limitations, privacy and response capability, but
never dispatches remediation or promotes coverage.
"""

import argparse
import json
import os
import sys
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

from sentinel import beta10_trust_center as trust
from sentinel import home_security_ui
from sentinel.ui_design_system import COLORS, make_icon

TRUST_PAGE_NAME = "Trust Center"


def _status_copy(status: str) -> str:
    return {
        "VERIFIED": "Verificato",
        "PARTIAL": "Parziale",
        "GAP": "Gap",
    }.get(status, status)


class _SummaryCard(QFrame):
    def __init__(self, label: str, value: str, detail: str, *, accent: bool = False) -> None:
        super().__init__()
        self.setObjectName("MetricCard")
        self.setProperty("accentMetric", accent)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(118)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 15, 18, 15)
        layout.setSpacing(7)
        title = QLabel(label.upper())
        title.setObjectName("MetricLabel")
        value_label = QLabel(value)
        value_label.setObjectName("MetricValueAccent" if accent else "MetricValue")
        detail_label = QLabel(detail)
        detail_label.setObjectName("CardSummary")
        detail_label.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(value_label)
        layout.addWidget(detail_label)


class _ScenarioCard(QFrame):
    def __init__(self, scenario: dict[str, Any]) -> None:
        super().__init__()
        self.setObjectName("ActivityCard")
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)

        top = QHBoxLayout()
        title = QLabel(str(scenario["label"]))
        title.setObjectName("CardTitle")
        title.setWordWrap(True)
        status = QLabel(_status_copy(str(scenario["status"])))
        status.setObjectName("PosturePill" if scenario["status"] == "VERIFIED" else "NeutralPill")
        status.setProperty("posture", "PROTECTED" if scenario["status"] == "VERIFIED" else "UNKNOWN")
        top.addWidget(title, 1)
        top.addWidget(status, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(top)

        evidence = QLabel(str(scenario["evidence_basis"]).replace("_", " "))
        evidence.setObjectName("SectionHint")
        evidence.setWordWrap(True)
        limitation = QLabel(str(scenario["limitation"]))
        limitation.setObjectName("CardSummary")
        limitation.setWordWrap(True)
        layout.addWidget(evidence)
        layout.addWidget(limitation)


class _CapabilityCard(QFrame):
    def __init__(self, capability: dict[str, Any]) -> None:
        super().__init__()
        self.setObjectName("ActivityCard")
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)
        title = QLabel(str(capability["label"]))
        title.setObjectName("CardTitle")
        state = QLabel(str(capability["status"]).replace("_", " "))
        state.setObjectName("SectionHint")
        state.setWordWrap(True)
        summary = QLabel(str(capability["summary"]))
        summary.setObjectName("CardSummary")
        summary.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(state)
        layout.addWidget(summary)


class TrustCenterPage(QWidget):
    def __init__(self, snapshot: dict[str, Any] | None = None) -> None:
        super().__init__()
        self.snapshot = snapshot or trust.build_trust_center_snapshot()
        validation = trust.validate_snapshot(self.snapshot)
        if not validation["passed"]:
            raise RuntimeError("B10-8 Trust Center snapshot refused: " + ";".join(validation["failures"]))
        self.setObjectName("TrustCenterPage")
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self._compact = False
        self._mobile = False
        self._build_ui()

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
        eyebrow = QLabel("VERIFICABILITÀ · PRIVACY · RISPOSTA")
        eyebrow.setObjectName("PosturePill")
        eyebrow.setProperty("posture", "PROTECTED")
        eyebrow.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        title = QLabel("Trust Center")
        title.setObjectName("HeroTitle")
        title.setWordWrap(True)
        summary = QLabel(
            "Una vista unica di ciò che BC Sentinel ha realmente verificato, di ciò che resta parziale "
            "e delle azioni che il prodotto è autorizzato a compiere."
        )
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
            _SummaryCard("Verificati", str(coverage["VERIFIED"]), "Scenari con percorso live accettato.", accent=True),
            _SummaryCard("Parziali", str(coverage["PARTIAL"]), "Copertura presente ma non ancora verificata live."),
            _SummaryCard("Gap", str(coverage["GAP"]), "Scenari senza copertura dichiarata."),
        ]
        self._render_summary_cards(columns=3)
        root.addLayout(self.summary_grid)

        coverage_panel = QFrame()
        coverage_panel.setObjectName("ModulesPanel")
        coverage_layout = QVBoxLayout(coverage_panel)
        coverage_layout.setContentsMargins(24, 20, 24, 24)
        coverage_layout.setSpacing(16)
        coverage_title = QLabel("Protection Proof")
        coverage_title.setObjectName("SectionTitle")
        coverage_hint = QLabel("La UI non può promuovere uno scenario: VERIFIED deriva solo da evidenza accettata.")
        coverage_hint.setObjectName("SectionHint")
        coverage_hint.setWordWrap(True)
        coverage_layout.addWidget(coverage_title)
        coverage_layout.addWidget(coverage_hint)
        self.scenario_grid = QGridLayout()
        self.scenario_grid.setHorizontalSpacing(16)
        self.scenario_grid.setVerticalSpacing(16)
        self.scenario_cards = [_ScenarioCard(item) for item in self.snapshot["scenarios"]]
        self._render_scenarios(columns=2)
        coverage_layout.addLayout(self.scenario_grid)
        root.addWidget(coverage_panel)

        capability_panel = QFrame()
        capability_panel.setObjectName("ModulesPanel")
        capability_layout = QVBoxLayout(capability_panel)
        capability_layout.setContentsMargins(24, 20, 24, 24)
        capability_layout.setSpacing(16)
        capability_title = QLabel("Capacità accettate")
        capability_title.setObjectName("SectionTitle")
        capability_hint = QLabel("Attack Story resta evidence-only; Safe Response non implica esecuzione automatica.")
        capability_hint.setObjectName("SectionHint")
        capability_hint.setWordWrap(True)
        capability_layout.addWidget(capability_title)
        capability_layout.addWidget(capability_hint)
        self.capability_grid = QGridLayout()
        self.capability_grid.setHorizontalSpacing(16)
        self.capability_grid.setVerticalSpacing(16)
        self.capability_cards = [_CapabilityCard(item) for item in self.snapshot["capabilities"]]
        self._render_capabilities(columns=2)
        capability_layout.addLayout(self.capability_grid)
        root.addWidget(capability_panel)

        privacy_panel = QFrame()
        privacy_panel.setObjectName("ActivityCard")
        privacy_layout = QVBoxLayout(privacy_panel)
        privacy_layout.setContentsMargins(20, 18, 20, 18)
        privacy_layout.setSpacing(8)
        privacy_title = QLabel("Privacy e autorità")
        privacy_title.setObjectName("CardTitle")
        privacy_copy = QLabel(
            "Local-first. Nessun accesso credenziali, nessun contenuto PowerShell letto, nessun traffico di rete di test, "
            "nessuna quarantena automatica e nessuna esecuzione Home generale. Il solo pilot esecutivo resta confinato "
            "a un workspace temporaneo, con conferma esplicita e rollback."
        )
        privacy_copy.setObjectName("CardSummary")
        privacy_copy.setWordWrap(True)
        privacy_layout.addWidget(privacy_title)
        privacy_layout.addWidget(privacy_copy)
        root.addWidget(privacy_panel)

        impact_panel = QFrame()
        impact_panel.setObjectName("ActivityCard")
        impact_layout = QVBoxLayout(impact_panel)
        impact_layout.setContentsMargins(20, 18, 20, 18)
        impact_layout.setSpacing(8)
        impact_title = QLabel("Operational Impact")
        impact_title.setObjectName("CardTitle")
        impact_view = self.snapshot["operational_impact"]
        if impact_view["measured"]:
            metrics = impact_view["metrics"]
            impact_text = (
                f"Misurato · p95 latenza {metrics['p95_wall_ms']} ms · p95 CPU {metrics['p95_cpu_ms']} ms · "
                f"Δ RAM max {metrics['max_rss_delta_mib']} MiB · interruzioni utente {metrics['max_user_interruptions']}."
            )
        else:
            impact_text = "Metriche runtime non caricate in questa sessione. I budget B10-7 restano disponibili e la UI non inventa valori."
        impact_copy = QLabel(impact_text)
        impact_copy.setObjectName("CardSummary")
        impact_copy.setWordWrap(True)
        impact_layout.addWidget(impact_title)
        impact_layout.addWidget(impact_copy)
        root.addWidget(impact_panel)

        self._coverage_panel = coverage_panel
        self._capability_panel = capability_panel
        self._privacy_panel = privacy_panel
        self._impact_panel = impact_panel

    @staticmethod
    def _clear_grid(grid: QGridLayout) -> None:
        while grid.count():
            item = grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)

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


class TrustCenterWindow(home_security_ui.SecurityOverviewWindow):
    def __init__(self, *, trust_snapshot: dict[str, Any] | None = None, status_provider=None) -> None:
        self._trust_snapshot_input = trust_snapshot
        super().__init__(status_provider=status_provider)
        self._install_trust_center()
        QTimer.singleShot(0, lambda: self._apply_responsive_layout(force=True))

    def _install_trust_center(self) -> None:
        snapshot = self._trust_snapshot_input or trust.build_trust_center_snapshot()
        validation = trust.validate_snapshot(snapshot)
        if not validation["passed"]:
            raise RuntimeError("B10-8 Trust Center window refused: " + ";".join(validation["failures"]))

        self.trust_center_page = TrustCenterPage(snapshot)
        self.trust_center_scroll = home_security_ui._PageScroll(self.trust_center_page)
        self.stack.addWidget(self.trust_center_scroll)
        self.secondary_scrolls.append(self.trust_center_scroll)

        button = QPushButton(TRUST_PAGE_NAME)
        button.setObjectName("NavItem")
        button.setIcon(make_icon("shield", COLORS["text_secondary"], 20))
        button.setIconSize(QSize(20, 20))
        button.setCheckable(True)
        button.setChecked(False)
        button.setEnabled(True)
        button.setToolTip("Apri Trust Center")
        button.setAccessibleName("Trust Center")
        button.clicked.connect(lambda checked=False: self._navigate(TRUST_PAGE_NAME))
        self.nav_buttons[TRUST_PAGE_NAME] = button

        sidebar_layout = self.sidebar.layout()
        existing_indexes = [sidebar_layout.indexOf(widget) for name, widget in self.nav_buttons.items() if name != TRUST_PAGE_NAME]
        insert_at = max(existing_indexes) + 1 if existing_indexes else max(0, sidebar_layout.count() - 4)
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
    window = TrustCenterWindow(trust_snapshot=snapshot)
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
        passed = (
            window.stack.count() == 7
            and window.stack.currentWidget() is window.trust_center_scroll
            and window.trust_center_nav_button.isEnabled()
            and all(value == 0 for value in overflow.values())
        )
        return {
            "passed": passed,
            "page_count": window.stack.count(),
            "trust_center_selected": window.stack.currentWidget() is window.trust_center_scroll,
            "horizontal_overflow": overflow,
            "nav_enabled": window.trust_center_nav_button.isEnabled(),
        }
    finally:
        window.close()
        app.processEvents()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()

    if args.snapshot:
        try:
            snapshot = json.loads(open(args.snapshot, "r", encoding="utf-8-sig").read())
        except (OSError, UnicodeError, ValueError):
            print(json.dumps({"passed": False, "failures": ["snapshot_unreadable"]}, indent=2))
            return 1
    else:
        snapshot = trust.build_trust_center_snapshot()

    if args.smoke:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        result = smoke_test_window(snapshot)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1

    app = QApplication.instance() or QApplication(sys.argv)
    window = TrustCenterWindow(trust_snapshot=snapshot)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
