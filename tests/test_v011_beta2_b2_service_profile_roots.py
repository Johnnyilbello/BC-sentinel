from __future__ import annotations

from pathlib import Path

import sentinel.config as config
from sentinel.config import (
    Settings,
    _default_root_candidates,
    _discover_local_user_profiles,
    _merge_path_strings,
    _profile_monitor_candidates,
    _service_identity_needs_local_profiles,
    ensure_service_profile_roots,
)


def _make_profile(users_root: Path, name: str) -> Path:
    profile = users_root / name
    for relative in (
        "Downloads",
        "Desktop",
        "Documents",
        "Pictures",
        "AppData/Local/Temp",
        "AppData/Roaming",
    ):
        (profile / relative).mkdir(parents=True, exist_ok=True)
    (profile / "NTUSER.DAT").write_text("fixture", encoding="utf-8")
    return profile


def test_service_identity_detection_covers_localsystem_and_service_profiles():
    assert _service_identity_needs_local_profiles(
        Path(r"C:\Windows\System32\config\systemprofile"),
        "SYSTEM",
    ) is True
    assert _service_identity_needs_local_profiles(
        Path(r"C:\Windows\ServiceProfiles\LocalService"),
        "LOCAL SERVICE",
    ) is True
    assert _service_identity_needs_local_profiles(
        Path(r"C:\Users\Alice"),
        "Alice",
    ) is False


def test_local_profile_discovery_excludes_windows_pseudo_profiles(tmp_path: Path):
    users_root = tmp_path / "Users"
    alice = _make_profile(users_root, "Alice")
    _make_profile(users_root, "Public")
    _make_profile(users_root, "Default")
    _make_profile(users_root, "defaultuser0")

    discovered = _discover_local_user_profiles(users_root)

    assert discovered == [alice]


def test_profile_monitor_candidates_include_interactive_temp_and_roaming(tmp_path: Path):
    profile = _make_profile(tmp_path / "Users", "Alice")
    candidates = _profile_monitor_candidates(profile)

    assert profile / "Downloads" in candidates
    assert profile / "Desktop" in candidates
    assert profile / "Documents" in candidates
    assert profile / "AppData" / "Local" / "Temp" in candidates
    assert profile / "AppData" / "Roaming" in candidates


def test_system_service_default_roots_include_real_user_profile(tmp_path: Path):
    users_root = tmp_path / "Users"
    alice = _make_profile(users_root, "Alice")

    system_home = tmp_path / "Windows" / "System32" / "config" / "systemprofile"
    system_temp = system_home / "AppData" / "Local" / "Temp"
    system_appdata = system_home / "AppData" / "Roaming"
    system_temp.mkdir(parents=True, exist_ok=True)
    system_appdata.mkdir(parents=True, exist_ok=True)

    monitored, ransomware = _default_root_candidates(
        system_home,
        temp=str(system_temp),
        appdata=str(system_appdata),
        include_local_profiles=True,
        users_root=users_root,
    )

    assert alice / "Downloads" in monitored
    assert alice / "Desktop" in monitored
    assert alice / "Documents" in monitored
    assert alice / "AppData" / "Local" / "Temp" in monitored
    assert alice / "AppData" / "Roaming" in monitored
    assert alice / "Desktop" in ransomware
    assert alice / "Documents" in ransomware
    assert alice / "Pictures" in ransomware


def test_normal_user_defaults_do_not_expand_other_profiles(tmp_path: Path):
    users_root = tmp_path / "Users"
    alice = _make_profile(users_root, "Alice")
    bob = _make_profile(users_root, "Bob")

    monitored, _ = _default_root_candidates(
        alice,
        temp=str(alice / "AppData" / "Local" / "Temp"),
        appdata=str(alice / "AppData" / "Roaming"),
        include_local_profiles=False,
        users_root=users_root,
    )

    assert alice / "Downloads" in monitored
    assert alice / "AppData" / "Local" / "Temp" in monitored
    assert bob / "Downloads" not in monitored
    assert bob / "AppData" / "Local" / "Temp" not in monitored


def test_merge_path_strings_preserves_configured_and_adds_required_without_duplicates():
    merged = _merge_path_strings(
        [r"C:\Legacy", r"C:\Users\Alice\Desktop"],
        [r"c:\users\alice\desktop", r"C:\Users\Alice\AppData\Local\Temp"],
    )

    assert merged[0] == r"C:\Legacy"
    assert sum(path.casefold().endswith(r"users\alice\desktop") for path in merged) == 1
    assert any(path.casefold().endswith(r"appdata\local\temp") for path in merged)


def test_service_profile_root_migration_preserves_legacy_and_adds_required(monkeypatch):
    required = Settings(
        monitored_dirs=[r"C:\Users\Alice\Downloads", r"C:\Users\Alice\AppData\Local\Temp"],
        ransomware_dirs=[r"C:\Users\Alice\Documents"],
    )
    persisted = Settings(
        monitored_dirs=[r"C:\Windows\Temp", r"D:\CustomWatch"],
        ransomware_dirs=[r"D:\Protected"],
    )

    monkeypatch.setattr(config.os, "name", "nt")
    monkeypatch.setattr(config, "_service_identity_needs_local_profiles", lambda *args, **kwargs: True)
    monkeypatch.setattr(config.Settings, "defaults", classmethod(lambda cls: required))

    result = ensure_service_profile_roots(persisted)

    assert r"C:\Windows\Temp" in result.monitored_dirs
    assert r"D:\CustomWatch" in result.monitored_dirs
    assert r"C:\Users\Alice\Downloads" in result.monitored_dirs
    assert r"C:\Users\Alice\AppData\Local\Temp" in result.monitored_dirs
    assert r"D:\Protected" in result.ransomware_dirs
    assert r"C:\Users\Alice\Documents" in result.ransomware_dirs


def test_normal_user_persisted_roots_are_not_forced(monkeypatch):
    persisted = Settings(monitored_dirs=[r"D:\CustomWatch"], ransomware_dirs=[r"D:\Protected"])
    monkeypatch.setattr(config.os, "name", "nt")
    monkeypatch.setattr(config, "_service_identity_needs_local_profiles", lambda *args, **kwargs: False)

    result = ensure_service_profile_roots(persisted)

    assert result.monitored_dirs == [r"D:\CustomWatch"]
    assert result.ransomware_dirs == [r"D:\Protected"]
