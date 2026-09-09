from pathlib import Path

def test_sidebar_settings_uses_same_nav_component():
    ui = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert '("Impostazioni", "⚙")' in ui
    assert 'b.setObjectName("nav")' in ui
    assert 'self.nav_buttons.append(b)' in ui

def test_footer_uses_current_app_version_and_is_not_fixed_to_old_release():
    ui = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert 'self.footer_version = QLabel(f"v{APP_VERSION}  ·  MVP")' in ui
    assert 'setMinimumHeight(24)' in ui

def test_ui_uses_persistent_last_scan():
    db = Path("sentinel/database.py").read_text(encoding="utf-8")
    ui = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert 'get_last_completed_scan' in db
    assert 'start_scan_record' in db
    assert 'finish_scan_record' in db
    assert 'format_last_scan' in ui

def test_app_enables_predictable_high_dpi_rounding():
    main = Path("app/main.py").read_text(encoding="utf-8")
    assert 'HighDpiScaleFactorRoundingPolicy.PassThrough' in main

def test_window_minimum_is_laptop_dpi_friendly():
    ui = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert 'self.setMinimumSize(820, 520)' in ui
