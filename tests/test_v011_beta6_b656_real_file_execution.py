from __future__ import annotations

from pathlib import Path

import pytest

from sentinel import guided_resolution_real_file_execution as b656


def _profile(tmp_path: Path) -> Path:
    root = tmp_path / "User"
    for name in ("Desktop", "Documents", "Downloads"):
        (root / name).mkdir(parents=True, exist_ok=True)
    return root


def test_contract_is_single_action_reversible_and_home_stays_disabled() -> None:
    contract = b656.validate_b656_contract()
    assert contract["passed"] is True
    assert contract["supported_mutating_actions"] == ["QUARANTINE"]
    assert contract["authority_scope"] == "EXPLICIT_NON_PRIVILEGED_USER_FILE_ONLY"
    assert contract["live_home_execution_authorized"] is False
    assert contract["automatic_action"] is False
    assert contract["destructive_authority"] is False
    assert contract["delete_authorized"] is False
    assert contract["repair_authorized"] is False
    assert contract["terminate_process_authorized"] is False


def test_regular_file_in_documents_is_eligible(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "OtherLocalData"))
    profile = _profile(tmp_path)
    target = profile / "Documents" / "sample.txt"
    target.write_text("safe fixture", encoding="utf-8")
    decision = b656.assess_target_eligibility(target, user_profile=profile, extra_protected_roots=(tmp_path / "Protected",))
    assert decision["eligible"] is True
    assert decision["reasons"] == []


def test_file_outside_allowed_user_roots_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "OtherLocalData"))
    profile = _profile(tmp_path)
    other = profile / "Pictures"
    other.mkdir()
    target = other / "sample.txt"
    target.write_text("x", encoding="utf-8")
    decision = b656.assess_target_eligibility(target, user_profile=profile)
    assert decision["eligible"] is False
    assert "outside_allowed_user_roots" in decision["reasons"]


def test_explicit_protected_root_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "OtherLocalData"))
    profile = _profile(tmp_path)
    protected = profile / "Documents" / "BC-Sentinel-SelfManaged"
    protected.mkdir()
    target = protected / "sample.txt"
    target.write_text("x", encoding="utf-8")
    decision = b656.assess_target_eligibility(target, user_profile=profile, extra_protected_roots=(protected,))
    assert decision["eligible"] is False
    assert "protected_or_self_managed_path" in decision["reasons"]


def test_oversized_file_is_refused_without_reading_contents(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "OtherLocalData"))
    profile = _profile(tmp_path)
    target = profile / "Downloads" / "large.bin"
    with target.open("wb") as handle:
        handle.truncate(b656.MAX_TARGET_BYTES + 1)
    decision = b656.assess_target_eligibility(target, user_profile=profile)
    assert decision["eligible"] is False
    assert "target_too_large" in decision["reasons"]


def test_symlink_target_is_refused_when_supported(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "OtherLocalData"))
    profile = _profile(tmp_path)
    original = profile / "Documents" / "original.txt"
    original.write_text("x", encoding="utf-8")
    link = profile / "Documents" / "link.txt"
    try:
        link.symlink_to(original)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable on this runner")
    decision = b656.assess_target_eligibility(link, user_profile=profile)
    assert decision["eligible"] is False
    assert "symlink_refused" in decision["reasons"] or "symlink_component_refused" in decision["reasons"]


def test_default_storage_root_is_dedicated_localappdata(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    local = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    assert b656.default_storage_root() == (local / "BCSentinel" / "B656").resolve()
