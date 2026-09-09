\
from pathlib import Path
import ast

def _ui():
    return Path("app/ui/main_window.py").read_text(encoding="utf-8")

def test_scan_feedback_starts_before_db_and_worker_setup():
    source=_ui(); start=source.index("    def start_scan(self,roots,label):"); end=source.index("    def _animate_scan_progress_to",start); block=source[start:end]
    assert block.index("self._begin_scan_feedback(label)") < block.index("self.db.start_scan_record(kind)") < block.index("ScanThread(roots")

def test_scan_has_independent_100ms_ui_clock():
    source=_ui(); assert "self.scan_ui_timer.setInterval(100)" in source; assert "self.scan_ui_timer.timeout.connect(self._tick_scan_clock)" in source; assert "self.scan_ui_timer.start()" in source; assert "tenths=" in source

def test_scan_uses_indeterminate_preparation_then_smooth_progress():
    source=_ui(); assert "self.scan_progress.setRange(0,0)" in source; assert "def _animate_scan_progress_to" in source; assert "anim.setDuration(135)" in source; assert "QPropertyAnimation.Running" in source

def test_scan_buttons_disable_immediately_and_restore():
    source=_ui(); assert "self._set_scan_buttons_enabled(False)" in source; assert "self._set_scan_buttons_enabled(True)" in source; assert "self.scan_action_buttons" in source

def test_premium_motion_respects_animation_toggle():
    source=_ui(); assert "def _micro_fade" in source; assert "if not self.animations_enabled" in source; assert "animate=self.animations_enabled" in source

def test_dashboard_manage_opens_protection():
    assert 'manage.clicked.connect(lambda:self.nav_to(5))' in _ui()

def test_ui_parses(): ast.parse(_ui())
