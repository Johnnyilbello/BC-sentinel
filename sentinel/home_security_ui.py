from __future__ import annotations

"""Stable public entry for the B6-2 Home UI.

The Stitch-aligned implementation lives in ``home_security_ui_impl``.  This
module keeps the public import/``python -m`` surface stable while applying the
small-screen geometry contract required by the real Windows acceptance gate.
"""

from sentinel import home_security_ui_impl as _impl

# Re-export the implementation surface, including private helpers that are part
# of the B6-2 regression/acceptance contract.
for _name in dir(_impl):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_impl, _name)


class SecurityOverviewWindow(_impl.SecurityOverviewWindow):
    """Stitch Home with a shrink-safe Qt scroll host and deterministic reflow."""

    def _build_ui(self) -> None:
        super()._build_ui()

        # QScrollArea otherwise keeps the minimumSizeHint calculated from the
        # initial wide hero/grid composition.  On a 1080px desktop window that
        # stale hint made the page ~229px wider than the viewport even after
        # the visual layout had reflowed.  Ignored applies only to the scroll
        # host: the actual Home root remains Expanding as required by Stitch.
        self.page_host = self.page_scroll.widget()
        self.page_host.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Preferred,
        )
        self.page_host.setMinimumWidth(0)
        self.content_root.setMinimumWidth(0)
        self.hero.setMinimumWidth(0)
        self.modules_panel.setMinimumWidth(0)
        self.activity.setMinimumWidth(0)

        # Wide-mode minimums must not become permanent constraints once the
        # hero stacks vertically.
        self.headline_label.setMinimumWidth(0)
        for card in self.card_widgets.values():
            card.setMinimumWidth(240)

    def _reset_grid_stretches(self) -> None:
        # QGridLayout retains stretch values for now-empty columns.  Reset them
        # before changing column count so compact mode has no phantom columns.
        for column in range(4):
            self.metrics_grid.setColumnStretch(column, 0)
            self.cards_grid.setColumnStretch(column, 0)

    def _activate_reflow_geometry(self) -> None:
        layouts = (
            self.hero_layout,
            self.hero_actions,
            self.metrics_grid,
            self.cards_grid,
            self.content_root.layout(),
            self.modules_panel.layout(),
            self.page_host.layout(),
        )
        for layout in layouts:
            if layout is not None:
                layout.invalidate()
                layout.activate()
        self.content_root.updateGeometry()
        self.modules_panel.updateGeometry()
        self.hero.updateGeometry()
        self.page_host.updateGeometry()

    def _apply_responsive_layout(self, force: bool = False) -> None:
        width = self._content_width()

        # Reflow earlier than the previous thresholds.  At the minimum
        # supported 1080px window the 260px sidebar leaves roughly 770px of
        # content canvas; that should be a deliberate compact desktop layout,
        # not a compressed version of the 2-column desktop composition.
        compact = width < 980
        narrow_metrics = width < 900
        mode = (compact, narrow_metrics)
        if not force and mode == self._last_layout_mode:
            return
        self._last_layout_mode = mode

        self.hero_layout.setDirection(
            QBoxLayout.Direction.TopToBottom
            if compact
            else QBoxLayout.Direction.LeftToRight
        )
        self.hero_actions.setDirection(
            QBoxLayout.Direction.TopToBottom
            if compact
            else (
                QBoxLayout.Direction.TopToBottom
                if width < 1060
                else QBoxLayout.Direction.LeftToRight
            )
        )

        if compact:
            self.hero_layout.setContentsMargins(22, 20, 22, 20)
            self.hero_layout.setSpacing(18)
            self.hero_actions.setAlignment(Qt.AlignmentFlag.AlignLeft)
            self.headline_label.setMinimumWidth(0)
            self.hero_summary.setMaximumWidth(16777215)
            self.smart_scan_button.setMinimumWidth(0)
            self.full_scan_button.setMinimumWidth(0)
        else:
            self.hero_layout.setContentsMargins(30, 24, 30, 24)
            self.hero_layout.setSpacing(24)
            self.hero_actions.setAlignment(Qt.AlignmentFlag.AlignVCenter)
            self.headline_label.setMinimumWidth(320)
            self.hero_summary.setMaximumWidth(620)
            self.smart_scan_button.setMinimumWidth(190)
            self.full_scan_button.setMinimumWidth(190)

        self.section_hint.setVisible(width >= 920)
        self._reset_grid_stretches()
        self._render_metrics(columns=1 if narrow_metrics else 3)
        self._render_cards(columns=1 if compact else 2)

        for card in self.card_widgets.values():
            card.setMinimumWidth(240 if compact else 280)

        self._activate_reflow_geometry()


# The implementation's CLI/acceptance helpers resolve this global at runtime.
# Point them at the shrink-safe subclass while preserving the established API.
_impl.SecurityOverviewWindow = SecurityOverviewWindow

self_check = _impl.self_check
main = _impl.main


if __name__ == "__main__":
    raise SystemExit(main())
