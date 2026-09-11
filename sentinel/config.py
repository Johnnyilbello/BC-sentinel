from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import os
import sys

APP_NAME = "BC Sentinel"
APP_VERSION = "0.11.0-beta.1"

DATA_DIR = Path(os.getenv("LOCALAPPDATA", Path.home() / ".bc_sentinel")) / "BCSentinel"
DB_PATH = DATA_DIR / "sentinel.db"
QUARANTINE_DIR = DATA_DIR / "quarantine"
KEY_PATH = DATA_DIR / "quarantine.key"
PROGRAM_DATA_DIR = Path(os.getenv("PROGRAMDATA", str(Path.home() / ".bc_sentinel_programdata"))) / "BCSentinel"
EDR_DB_PATH = PROGRAM_DATA_DIR / "EDR" / "edr-telemetry.sqlite3"

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

_SERVICE_IDENTITIES = {"system", "local service", "network service"}
_SERVICE_HOME_MARKERS = (
    "\\system32\\config\\systemprofile",
    "\\serviceprofiles\\localservice",
    "\\serviceprofiles\\networkservice",
)
_IGNORED_WINDOWS_PROFILE_NAMES = {
    "all users",
    "default",
    "default user",
    "defaultuser0",
    "public",
    "wdagutilityaccount",
}


def _service_identity_needs_local_profiles(home: Path | None = None, username: str | None = None) -> bool:
    user = str(username if username is not None else os.getenv("USERNAME", "")).strip().casefold()
    home_text = str(home if home is not None else Path.home()).replace("/", "\\").casefold()
    if user in _SERVICE_IDENTITIES:
        return True
    return any(marker in home_text for marker in _SERVICE_HOME_MARKERS)


def _discover_local_user_profiles(users_root: Path | None = None) -> list[Path]:
    if users_root is None:
        system_drive = str(os.getenv("SystemDrive", "C:") or "C:")
        users_root = Path(system_drive + "\\Users")
    root = Path(users_root)
    try:
        entries = list(root.iterdir())
    except OSError:
        return []

    profiles: list[Path] = []
    for entry in sorted(entries, key=lambda item: item.name.casefold()):
        if entry.name.casefold() in _IGNORED_WINDOWS_PROFILE_NAMES:
            continue
        try:
            if not entry.is_dir():
                continue
        except OSError:
            continue
        markers = (
            entry / "NTUSER.DAT",
            entry / "AppData",
            entry / "Desktop",
            entry / "Documents",
            entry / "Downloads",
        )
        try:
            if not any(marker.exists() for marker in markers):
                continue
        except OSError:
            continue
        profiles.append(entry)
    return profiles


def _profile_monitor_candidates(profile: Path) -> list[Path]:
    profile = Path(profile)
    return [
        profile / "Downloads",
        profile / "Desktop",
        profile / "Documents",
        profile / "AppData" / "Local" / "Temp",
        profile / "AppData" / "Roaming",
    ]


def _profile_ransomware_candidates(profile: Path) -> list[Path]:
    profile = Path(profile)
    return [
        profile / "Desktop",
        profile / "Documents",
        profile / "Pictures",
    ]


def _existing_unique(paths: list[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        text = str(path)
        if not text:
            continue
        try:
            if not path.exists():
                continue
        except OSError:
            continue
        key = os.path.normcase(os.path.normpath(text))
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


def _merge_path_strings(configured: list[str], required: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for raw in [*configured, *required]:
        text = str(raw).strip()
        if not text:
            continue
        key = os.path.normcase(os.path.normpath(text))
        if key in seen:
            continue
        seen.add(key)
        result.append(text)
    return result


def _default_root_candidates(
    home: Path,
    *,
    temp: str = "",
    appdata: str = "",
    include_local_profiles: bool = False,
    users_root: Path | None = None,
) -> tuple[list[Path], list[Path]]:
    home = Path(home)
    candidates = [
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
    ]
    ransomware_candidates = _profile_ransomware_candidates(home)

    if temp:
        candidates.append(Path(temp))
    if appdata:
        candidates.append(Path(appdata))

    if include_local_profiles:
        for profile in _discover_local_user_profiles(users_root):
            candidates.extend(_profile_monitor_candidates(profile))
            ransomware_candidates.extend(_profile_ransomware_candidates(profile))

    return _existing_unique(candidates), _existing_unique(ransomware_candidates)


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
    edr_enabled: bool = True
    edr_retention_days: int = 7
    edr_max_events: int = 100000
    edr_correlation_window_seconds: int = 90
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
        include_local_profiles = bool(
            os.name == "nt" and _service_identity_needs_local_profiles(home)
        )
        candidates, ransomware_candidates = _default_root_candidates(
            home,
            temp=str(os.getenv("TEMP", "") or ""),
            appdata=str(os.getenv("APPDATA", "") or ""),
            include_local_profiles=include_local_profiles,
        )
        return cls(
            monitored_dirs=[str(path) for path in candidates],
            ransomware_dirs=[str(path) for path in ransomware_candidates],
        )


def ensure_service_profile_roots(settings: Settings) -> Settings:
    """Preserve configured roots while guaranteeing real-user coverage for service identities."""
    if os.name != "nt" or not _service_identity_needs_local_profiles(Path.home()):
        return settings
    required = Settings.defaults()
    settings.monitored_dirs = _merge_path_strings(settings.monitored_dirs, required.monitored_dirs)
    settings.ransomware_dirs = _merge_path_strings(settings.ransomware_dirs, required.ransomware_dirs)
    return settings


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    for directory in (DATA_DIR, QUARANTINE_DIR):
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
