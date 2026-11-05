"""Resolve and launch the bundled, user-invoked Windows storage companion."""
from __future__ import annotations

import sys
import subprocess
from pathlib import Path

EXECUTABLE = "BC Storage Analyzer.exe"


def executable_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "storage_analyzer" / EXECUTABLE
    return Path(__file__).resolve().parents[1] / "build" / "storage_analyzer" / EXECUTABLE


def availability() -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, "BC Storage Analyzer è disponibile su Windows."
    if not executable_path().is_file():
        return False, (
            "Componente mancante. Dalla repository esegui "
            "tools/BUILD-STORAGE-ANALYZER.ps1. Per la versione portabile, estrai nuovamente il pacchetto completo."
        )
    return True, "Pronto. Lo strumento si apre in una finestra dedicata."


def launch() -> subprocess.Popen:
    ready, message = availability()
    if not ready:
        raise OSError(message)
    path = executable_path()
    return subprocess.Popen([str(path)], cwd=str(path.parent), shell=False)
