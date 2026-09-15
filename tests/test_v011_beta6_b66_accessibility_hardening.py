from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QTimer, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QBoxLayout, QPushButton

from sentinel import rescue_technician_portable as b57
from sentinel import rescue_technician_ui as ui
from sentinel import rescue_technician_ui_model as model


@pytest.fixture
def app() -> QApplication:
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app: QApplication):
    result = ui.TechnicianWindow()
    result.show()
    app.processEvents()
    yield result
    if result.fixture_worker is not None:
        result.fixture_worker.wait(2000)
    result.close()
    app.processEvents()


def test_b66_contract_preserves_all_execution_boundaries() -> None:
    contract = model.validate_b66_accessibility_contract()
    assert contract["passed"] is True
    assert contract["background_work_is_read_only_fixture_only"] is True
    assert all(
        contract[key] is False
        for key in (
            "automatic_command_dispatch",
            "automatic_repair",
            "automatic_quarantine",
            "automatic_restore",
            "repair_execute_exposed",
            "target_execution",
        )
    )


def test_activity_log_limits_entries_and_long_messages() -> None:
    log = model.BoundedActivityLog(limit=3)
    for index in range(5):
        log.append("fixture", f"entry {index}")
    assert log.entries() == ("fixture: entry 2", "fixture: entry 3", "fixture: entry 4")
    rendered = log.append("long", "C:\\" + ("very-long-path\\" * 90))
    assert len(rendered) <= len("long: ") + model.MAX_ACTIVITY_MESSAGE_CHARS
    assert rendered.endswith("…")


def test_wide_and_compact_layouts_remain_readable(window: ui.TechnicianWindow, app: QApplication) -> None:
    window.resize(1500, 950)
    app.processEvents()
    assert window._layout_mode == "wide"
    assert window.cards.direction() == QBoxLayout.Direction.LeftToRight
    window.resize(1000, 820)
    app.processEvents()
    assert window._layout_mode == "compact"
    assert window.cards.direction() == QBoxLayout.Direction.TopToBottom
    assert window.header.direction() == QBoxLayout.Direction.TopToBottom
    assert all(card.value_label.wordWrap() for card in window.info_cards)
    assert window.findChild(type(window.centralWidget()), "missing") is None


@pytest.mark.parametrize("point_size", [10, 12, 15])
def test_supported_text_scales_keep_actions_and_details_available(
    window: ui.TechnicianWindow, app: QApplication, point_size: int
) -> None:
    previous = app.font()
    font = app.font()
    font.setPointSize(point_size)
    app.setFont(font)
    try:
        window.resize(1200, 900)
        app.processEvents()
        assert window.contract_button.isVisible()
        assert window.contract_button.accessibleName()
        assert window.activity_view.isVisible()
        assert all(button.toolTip() for button in window.workflow_buttons)
    finally:
        app.setFont(previous)


def test_keyboard_contract_action_and_focus_are_operable(window: ui.TechnicianWindow, app: QApplication) -> None:
    window.contract_button.setFocus()
    QTest.keyClick(window.contract_button, Qt.Key.Key_Return)
    app.processEvents()
    assert "SAFETY: Safety contract inspected by operator." in window.activity_view.toPlainText()
    QTest.keyClick(window, Qt.Key.Key_C, Qt.KeyboardModifier.AltModifier)
    app.processEvents()
    assert len([entry for entry in window.activity_log.entries() if entry.startswith("SAFETY:")]) == 2


def test_fixture_worker_keeps_event_loop_responsive_and_never_dispatches_engine(
    window: ui.TechnicianWindow, app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    dispatches: list[str] = []

    def forbidden(*_args, **_kwargs):
        dispatches.append("engine")
        raise AssertionError("engine command must not be dispatched")

    for command in list(b57.COMMANDS):
        monkeypatch.setitem(b57.COMMANDS, command, forbidden)

    ticks: list[bool] = []
    timer = QTimer()
    timer.timeout.connect(lambda: ticks.append(True))
    timer.start(5)
    try:
        assert window.start_read_only_fixture_worker(lambda: (time.sleep(0.08) or "Fixture completed"))
        assert window.ui_state.state == "RUNNING"
        deadline = time.monotonic() + 2
        while window.fixture_worker is not None and time.monotonic() < deadline:
            app.processEvents()
            QTest.qWait(5)
        assert window.fixture_worker is None
    finally:
        timer.stop()
    assert ticks
    assert window.ui_state.state == "REVIEW"
    assert "Fixture completed" in window.activity_view.toPlainText()
    assert dispatches == []


def test_visible_controls_have_semantics_and_engine_controls_remain_disabled(window: ui.TechnicianWindow) -> None:
    for button in window.findChildren(QPushButton):
        if button.isVisible():
            assert button.accessibleName() or button.text()
            assert button.toolTip() or button.text() == "Not started"
    assert all(not button.isEnabled() for button in window.workflow_buttons)
