from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import os
import sys

APP_NAME = "BC Sentinel"
APP_VERSION = "0.9.0-rc.1"

DATA_DIR = Path(os.getenv("LOCALAPPDATA", Path.home() / ".bc_sentinel")) / "BCSentinel"
DB_PATH = DATA_DIR / "sentinel.db"
QUARANTINE_DIR = DATA_DIR / "quarantine"
KEY_PATH = DATA_DIR / "quarantine.key"
PROGRAM_DATA_DIR = Path(os.getenv("PROGRAMDATA", str(Path.home() / ".bc_sentinel_programdata"))) / "BCSentinel"

if getattr(sys, "frozen", False):
    APP_ROOT = Path(
        getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent)
    ).resolve()
    EXE_DIR = Path(sys.executable).resolve().parent
else:
    APP_ROOT = Path(__file__).resolve().parent.parent
    EXE_DIR = APP_ROOT

RULES_DIR = APP_ROOT / "rules" / "yara"

POTENTIALLY_EXECUTABLE = {
    ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".com", ".msi",
    ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta",
    ".jar", ".lnk",
}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf"}

@dataclass(slots=True)
class Settings:
    realtime_enabled: bool = True
    ransomware_enabled: bool = True
    behavior_enabled: bool = True
    auto_quarantine_threshold: int = 90
    scan_size_limit_mb: int = 256
    monitored_dirs: list[str] = field(default_factory=list)
    ransomware_dirs: list[str] = field(default_factory=list)
    ransomware_startup_grace_seconds: int = 30
    etw_enabled: bool = True
    telemetry_service_enabled: bool = True
    notifications_enabled: bool = True
    close_to_tray: bool = True
    animations_enabled: bool = True
    persistence_enabled: bool = True
    network_enabled: bool = True
    reputation_enabled: bool = True
    exclude_self: bool = True

    @classmethod
    def defaults(cls) -> "Settings":
        home = Path.home()
        candidates = [
            home / "Downloads",
            home / "Desktop",
            home / "Documents",
            Path(os.getenv("TEMP", "")),
            Path(os.getenv("APPDATA", "")),
        ]
        ransomware_candidates = [
            home / "Desktop",
            home / "Documents",
            home / "Pictures",
        ]
        return cls(
            monitored_dirs=[str(p) for p in candidates if str(p) and p.exists()],
            ransomware_dirs=[str(p) for p in ransomware_candidates if p.exists()],
        )

def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    for directory in (DATA_DIR, QUARANTINE_DIR):
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
