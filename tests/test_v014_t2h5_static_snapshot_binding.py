from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import rescue_offline_scanner as rr3


def _offline_root(base: Path) -> Path:
    root = base / "offline"
    config = root / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"SYSTEM-HIVE")
    system32 = root / "Windows" / "System32"
    (system32 / "ntoskrnl.exe").write_bytes(b"MZ-static-fixture")
    return root


def _script(root: Path, name: str = "binding.ps1") -> Path:
    path = (
        root
        / "ProgramData"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
        / name
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("Write-Output static-binding-test", encoding="utf-8")
    return path


def _catalog(tmp_path: Path, digest: str) -> Path:
    path = tmp_path / "intel.json"
    path.write_text(
        json.dumps(
            {
                "schema": "bc-sentinel-offline-intel-v1",
                "approved": True,
                "sha256": [
                    {
                        "value": digest,
                        "name": "T2.Static.Binding.IOC",
                        "source": "acceptance",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _scan(root: Path, out: Path, **kwargs):
    return rr3.scan_offline_windows(
        root,
        out,
        limits=rr3.OfflineScanLimits(max_files=128, max_file_bytes=1024 * 1024),
        **kwargs,
    )


def test_static_scan_records_matching_final_hash(tmp_path: Path):
    root = _offline_root(tmp_path)
    sample = _script(root)

    report = _scan(root, tmp_path / "out")
    finding = next(
        item for item in report["findings"]
        if item["relative_path"].endswith("binding.ps1")
    )

    assert finding["final_sha256_matches"] is True
    assert "artifact_changed_during_static_scan" not in finding["reasons"]
    assert "artifact_unavailable_after_static_scan" not in finding["reasons"]
    assert report["summary"]["static_snapshot_unstable_items"] == 0


def test_final_hash_mismatch_degrades_ioc_to_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root = _offline_root(tmp_path)
    sample = _script(root, "changed.ps1")
    initial_digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    catalog = _catalog(tmp_path, initial_digest)

    real_hash = rr3._sha256_file
    calls: dict[str, int] = {}

    def changing_hash(path: Path) -> str:
        key = str(path)
        calls[key] = calls.get(key, 0) + 1
        if path.name == "changed.ps1" and calls[key] >= 2:
            return "0" * 64
        return real_hash(path)

    monkeypatch.setattr(rr3, "_sha256_file", changing_hash)

    report = _scan(root, tmp_path / "out", intel_catalog=catalog)
    finding = next(
        item for item in report["findings"]
        if item["relative_path"].endswith("changed.ps1")
    )

    assert finding["ioc_name"] == "T2.Static.Binding.IOC"
    assert finding["final_sha256_matches"] is False
    assert "artifact_changed_during_static_scan" in finding["reasons"]
    assert finding["verdict"] == "review"
    assert finding["automatic_action"] is False
    assert report["summary"]["static_snapshot_unstable_items"] == 1


def test_final_hash_read_failure_is_review_not_trusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root = _offline_root(tmp_path)
    sample = _script(root, "disappeared.ps1")
    initial_digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    catalog = _catalog(tmp_path, initial_digest)

    real_hash = rr3._sha256_file
    calls: dict[str, int] = {}

    def unavailable_hash(path: Path) -> str:
        key = str(path)
        calls[key] = calls.get(key, 0) + 1
        if path.name == "disappeared.ps1" and calls[key] >= 2:
            raise OSError("synthetic static-scan race")
        return real_hash(path)

    monkeypatch.setattr(rr3, "_sha256_file", unavailable_hash)

    report = _scan(root, tmp_path / "out", intel_catalog=catalog)
    finding = next(
        item for item in report["findings"]
        if item["relative_path"].endswith("disappeared.ps1")
    )

    assert finding["ioc_name"] == "T2.Static.Binding.IOC"
    assert finding["final_sha256_matches"] is False
    assert "artifact_unavailable_after_static_scan" in finding["reasons"]
    assert finding["verdict"] == "review"
    assert finding["automatic_action"] is False
    assert report["summary"]["static_snapshot_unstable_items"] == 1


def test_static_snapshot_binding_does_not_expand_response_authority(tmp_path: Path):
    root = _offline_root(tmp_path)
    _script(root)

    report = _scan(root, tmp_path / "out")
    assert report["safety"]["target_read_only"] is True
    assert report["safety"]["target_file_execution"] is False
    assert report["safety"]["target_filesystem_write"] is False
    assert report["safety"]["quarantine_execution"] is False
    assert report["safety"]["automatic_action"] is False
