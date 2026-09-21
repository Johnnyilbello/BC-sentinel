from __future__ import annotations

"""Frozen Windows runtime hardening for the BC Sentinel PySide6 desktop build.

The hook runs before the application imports Qt.  It keeps the packaged Qt
runtime self-contained by preferring DLLs/plugins that ship inside the
PyInstaller bundle instead of inheriting unrelated Qt installations from the
host PATH.  It does not elevate, modify system configuration, access the
network, or weaken host protections.
"""

import os
from pathlib import Path
import sys


_DLL_DIRECTORY_HANDLES: list[object] = []


def _existing_unique(paths: list[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        key = os.path.normcase(str(resolved))
        if key in seen or not resolved.is_dir():
            continue
        seen.add(key)
        result.append(resolved)
    return result


def _bundle_roots() -> list[Path]:
    roots: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        roots.append(Path(meipass))

    executable_root = Path(sys.executable).resolve().parent
    roots.extend(
        [
            executable_root,
            executable_root / "_internal",
        ]
    )
    return _existing_unique(roots)


def _configure_frozen_qt_runtime() -> None:
    if os.name != "nt" or not getattr(sys, "frozen", False):
        return

    roots = _bundle_roots()
    dll_dirs: list[Path] = []
    plugin_dirs: list[Path] = []
    qml_dirs: list[Path] = []

    for root in roots:
        dll_dirs.extend(
            [
                root / "PySide6",
                root / "PySide6" / "Qt" / "bin",
                root,
            ]
        )
        plugin_dirs.extend(
            [
                root / "PySide6" / "plugins",
                root / "PySide6" / "Qt" / "plugins",
            ]
        )
        qml_dirs.extend(
            [
                root / "PySide6" / "qml",
                root / "PySide6" / "Qt" / "qml",
            ]
        )

    dll_dirs = _existing_unique(dll_dirs)
    plugin_dirs = _existing_unique(plugin_dirs)
    qml_dirs = _existing_unique(qml_dirs)

    if dll_dirs:
        current_path = os.environ.get("PATH", "")
        packaged_path = os.pathsep.join(str(path) for path in dll_dirs)
        os.environ["PATH"] = packaged_path + (os.pathsep + current_path if current_path else "")

        add_dll_directory = getattr(os, "add_dll_directory", None)
        if add_dll_directory is not None:
            for path in dll_dirs:
                try:
                    _DLL_DIRECTORY_HANDLES.append(add_dll_directory(str(path)))
                except OSError:
                    continue

    if plugin_dirs:
        os.environ["QT_PLUGIN_PATH"] = str(plugin_dirs[0])
        platforms = plugin_dirs[0] / "platforms"
        if platforms.is_dir():
            os.environ["QT_QPA_PLATFORM_PLUGIN_PATH"] = str(platforms)

    if qml_dirs:
        os.environ["QML2_IMPORT_PATH"] = str(qml_dirs[0])


if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")

_configure_frozen_qt_runtime()
