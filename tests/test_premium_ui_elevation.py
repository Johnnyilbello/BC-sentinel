from pathlib import Path
import ast


def _ui():
    return Path("app/ui/main_window.py").read_text(encoding="utf-8")


def test_premium_design_system_has_semantic_tokens_and_motion_tokens():
    source = _ui()
    for token in (
        '"safe"', '"warning"', '"danger"', '"info"', '"inactive"',
        '"surface_low"', '"surface_high"', '"border_strong"', '"focus"',
    ):
        assert token in source
    assert 'MOTION = {' in source
    assert '"fast": 150' in source
    assert '"slow": 320' in source
    assert 'SPACING = {' in source
    assert 'RADIUS = {' in source
    assert 'ICON_SIZE = {' in source
    assert 'ELEVATION = {' in source
    assert 'QGraphicsDropShadowEffect' in source


def test_typography_roles_are_centralized_in_qss():
    source = _ui()
    for role in (
        'role="pageTitle"', 'role="heroTitle"', 'role="sectionTitle"',
        'role="metricValue"', 'role="scanStatus"', 'role="empty"',
    ):
        assert role in source


def test_toggle_has_non_blocking_property_animation_and_focus_state():
    source = _ui()
    assert 'thumbPosition = Property(float' in source
    assert 'QPropertyAnimation(self, b"thumbPosition"' in source
    assert 'self.toggled.connect(self._animate_state)' in source
    assert 'self.setFocusPolicy(Qt.StrongFocus)' in source


def test_scan_cinematic_states_are_driven_by_real_scan_callbacks():
    source = _ui()
    assert 'self._set_scan_state("scanning")' in source
    assert 'self._set_scan_state("analyzing")' in source
    assert 'self._set_scan_state("threat")' in source
    assert '("warning" if detections else "safe")' in source
    assert 'QFrame#scanPanel[state="threat"]' in source


def test_responsive_sidebar_collapses_at_narrow_width_without_removing_routes():
    source = _ui()
    assert 'compact_nav = width < 980' in source
    assert 'self.sidebar.setFixedWidth(76 if compact_nav else 212)' in source
    assert 'button.setToolTip(label if compact_nav else "")' in source


def test_tables_have_empty_states_and_readability_hardening():
    source = _ui()
    assert 'self.q_empty' in source
    assert 'self.h_empty' in source
    assert 'self.activity_empty' in source
    assert 'table.setShowGrid(False)' in source
    assert 'table.setTextElideMode(Qt.ElideMiddle)' in source
    assert 'table.verticalHeader().setDefaultSectionSize(40)' in source


def test_premium_ui_source_parses():
    ast.parse(_ui())
