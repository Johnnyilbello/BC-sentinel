from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import rescue_target_discovery as b50


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_hashes(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): _sha(p) for p in root.rglob("*") if p.is_file()}


def _make_windows(root: Path, *, complete: bool = True) -> Path:
    config = root / "Windows/System32/config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"B50 SYSTEM")
    if complete:
        (config / "SOFTWARE").write_bytes(b"B50 SOFTWARE")
        (root / "Windows/System32/ntoskrnl.exe").write_bytes(b"MZ B50 KERNEL")
    return root


def _no_bitlocker(_: Path) -> dict:
    return {"provider": "test", "available": True, "locked": False}


def test_profile_and_state_contract() -> None:
    assert b50.PROFILE == "v0.11.0-beta.5-b50"
    assert {b50.STATE_READY, b50.STATE_LOCKED, b50.STATE_ACCESS_DENIED, b50.STATE_INCOMPLETE, b50.STATE_UNSUPPORTED, b50.STATE_ERROR} == {
        "READY", "LOCKED", "ACCESS_DENIED", "INCOMPLETE", "UNSUPPORTED", "ERROR"
    }


def test_complete_offline_windows_is_ready_and_rr6_bound(tmp_path: Path) -> None:
    root = _make_windows(tmp_path / "target")
    record = b50.classify_candidate(root, discovery_source="test", bitlocker_probe=_no_bitlocker)
    assert record.state == b50.STATE_READY
    assert record.reason == "validated_by_rr6_target_contract"
    assert len(record.target_fingerprint) == 64
    assert record.markers_missing == ()
    assert record.write_attempted is False


def test_incomplete_windows_is_not_ready(tmp_path: Path) -> None:
    root = _make_windows(tmp_path / "partial", complete=False)
    record = b50.classify_candidate(root, discovery_source="test", bitlocker_probe=_no_bitlocker)
    assert record.state == b50.STATE_INCOMPLETE
    assert "Windows/System32/config/SOFTWARE" in record.markers_missing
    assert "Windows/System32/ntoskrnl.exe" in record.markers_missing
    assert record.target_fingerprint == ""


def test_non_windows_directory_is_unsupported(tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    (root / "notes.txt").write_text("hello", encoding="utf-8")
    record = b50.classify_candidate(root, discovery_source="test", bitlocker_probe=_no_bitlocker)
    assert record.state == b50.STATE_UNSUPPORTED
    assert record.reason == "no_windows_markers"


def test_locked_bitlocker_refuses_before_marker_access(tmp_path: Path) -> None:
    root = tmp_path / "locked"
    root.mkdir()
    probe = lambda _: {"provider": "test", "available": True, "locked": True, "lock_status": 1}
    record = b50.classify_candidate(root, discovery_source="test", bitlocker_probe=probe)
    assert record.state == b50.STATE_LOCKED
    assert record.reason == "bitlocker_volume_locked"
    assert record.write_attempted is False
    assert record.target_fingerprint == ""


def test_permission_error_classification_is_access_denied() -> None:
    state, reason = b50._classify_exception(PermissionError("denied"), {"locked": False})
    assert state == b50.STATE_ACCESS_DENIED
    assert "permission_denied" in reason


def test_known_locked_windows_error_has_locked_precedence() -> None:
    exc = OSError("locked")
    exc.winerror = 33
    state, reason = b50._classify_exception(exc, {"locked": None})
    assert state == b50.STATE_LOCKED
    assert "33" in reason


def test_discovery_is_deterministic_and_deduplicated(tmp_path: Path) -> None:
    a = _make_windows(tmp_path / "B")
    b = _make_windows(tmp_path / "a")
    result = b50.discover_targets(
        [a, b, a], include_windows_volumes=False,
        limits=b50.DiscoveryLimits(max_roots=8, probe_children=False), bitlocker_probe=_no_bitlocker,
    )
    roots = [item["normalized_root"] for item in result["candidates"]]
    assert roots == sorted(set(roots), key=str.casefold)
    assert result["counts"][b50.STATE_READY] == 2


def test_discovery_respects_max_roots(tmp_path: Path) -> None:
    roots = []
    for i in range(5):
        root = tmp_path / f"root-{i}"
        root.mkdir()
        roots.append(root)
    result = b50.discover_targets(
        roots, include_windows_volumes=False,
        limits=b50.DiscoveryLimits(max_roots=3, probe_children=False), bitlocker_probe=_no_bitlocker,
    )
    assert result["roots_considered"] == 3


def test_child_probe_finds_nested_offline_windows(tmp_path: Path) -> None:
    container = tmp_path / "mounted-images"
    container.mkdir()
    nested = _make_windows(container / "WindowsDisk")
    result = b50.discover_targets(
        [container], include_windows_volumes=False,
        limits=b50.DiscoveryLimits(max_roots=8, probe_children=True, max_children_per_root=8), bitlocker_probe=_no_bitlocker,
    )
    ready = [item for item in result["candidates"] if item["state"] == b50.STATE_READY]
    assert len(ready) == 1
    assert Path(ready[0]["normalized_root"]) == nested.resolve()
    assert ready[0]["discovery_source"] == "explicit_child"


def test_discovery_never_mutates_candidate_tree(tmp_path: Path) -> None:
    root = _make_windows(tmp_path / "target")
    (root / "Users/Test").mkdir(parents=True)
    (root / "Users/Test/document.txt").write_text("preserve me", encoding="utf-8")
    before = _tree_hashes(root)
    result = b50.discover_targets(
        [root], include_windows_volumes=False,
        limits=b50.DiscoveryLimits(max_roots=4, probe_children=False), bitlocker_probe=_no_bitlocker,
    )
    after = _tree_hashes(root)
    assert before == after
    assert result["safety"]["write_attempted"] is False
    assert all(item["write_attempted"] is False for item in result["candidates"])


def test_safety_contract_disables_disk_mutation_and_unlock(tmp_path: Path) -> None:
    root = _make_windows(tmp_path / "target")
    result = b50.discover_targets(
        [root], include_windows_volumes=False,
        limits=b50.DiscoveryLimits(max_roots=4, probe_children=False), bitlocker_probe=_no_bitlocker,
    )
    safety = result["safety"]
    assert safety == {
        "read_only_discovery": True,
        "write_attempted": False,
        "unlock_attempted": False,
        "mount_mutation": False,
        "format_disk": False,
        "partition_write": False,
        "bcd_write": False,
        "filesystem_repair": False,
        "target_execution": False,
        "service_install": False,
        "driver_install": False,
        "network_required": False,
        "cloud_required": False,
    }


def test_output_is_atomic_json_and_does_not_change_target(tmp_path: Path) -> None:
    root = _make_windows(tmp_path / "target")
    before = _tree_hashes(root)
    result = b50.discover_targets(
        [root], include_windows_volumes=False,
        limits=b50.DiscoveryLimits(max_roots=4, probe_children=False), bitlocker_probe=_no_bitlocker,
    )
    output = b50.write_discovery_result(result, tmp_path / "workspace/discovery.json")
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema"] == b50.RESULT_SCHEMA
    assert payload["profile"] == b50.PROFILE
    assert _tree_hashes(root) == before


def test_limits_reject_unbounded_values() -> None:
    with pytest.raises(ValueError):
        b50.DiscoveryLimits(max_roots=b50.MAX_ROOTS_HARD + 1).validate()
    with pytest.raises(ValueError):
        b50.DiscoveryLimits(max_children_per_root=129).validate()
    with pytest.raises(ValueError):
        b50.DiscoveryLimits(bitlocker_probe_timeout_sec=60).validate()
