from __future__ import annotations
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from app.ui.main_window import MainWindow
from sentinel.logging_setup import configure_logging, event_log
from sentinel.config import APP_ROOT


def main():
    # Qt 6 is high-DPI aware by default; explicit rounding policy keeps
    # 125%/150% Windows scaling predictable and avoids clipped geometry.
    try:
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )
    except Exception:
        pass

    configure_logging()

    if os.name == "nt" and getattr(sys, "frozen", False):
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "BCSentinel.Security"
            )
        except Exception:
            pass

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    icon_path = APP_ROOT / "app" / "assets" / "bc_sentinel_icon.png"
    if not icon_path.exists():
        icon_path = APP_ROOT / "app" / "assets" / "bc_sentinel.ico"
    if icon_path.exists():
        qt_icon = QIcon(str(icon_path))
        if not qt_icon.isNull():
            app.setWindowIcon(qt_icon)
    app.setApplicationName("BC Sentinel")
    app.setOrganizationName("BC Sentinel")
    win = MainWindow()
    if "--background" in sys.argv:
        win.hide()
        event_log("Started in tray background mode",event="background_start")
    else:
        win.show()
    raise SystemExit(app.exec())


if __name__ == "__main__":
    main()
