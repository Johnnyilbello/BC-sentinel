from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import rescue_offline_scanner as rr3


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _offline_root(base: Path) -> Path:
    root = base / "offline"
    config = root / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"SYSTEM-HIVE")
    (config / "SOFTWARE").write_bytes(b"SOFTWARE-HIVE")
    system32 = root / "Windows" / "System32"
    (system32 / "ntoskrnl.exe").write_bytes(b"MZ-harmless-kernel-fixture")
    return root


def _scan(root: Path, out: Path, **kwargs):
    return rr3.scan_offline_windows(
        root,
        out,
        limits=kwargs.pop("limits", rr3.OfflineScanLimits(max_files=128, max_file_bytes=1024 * 1024)),
        **kwargs,
    )


def test_limits_are_bounded():
    rr3.OfflineScanLimits(max_files=1, max_file_bytes=1).validate()
    with pytest.raises(ValueError):
        rr3.OfflineScanLimits(max_files=0).validate()
    with pytest.raises(ValueError):
        rr3.OfflineScanLimits(max_files=rr3.MAX_FILES_HARD + 1).validate()
    with pytest.raises(ValueError):
        rr3.OfflineScanLimits(max_file_bytes=rr3.MAX_FILE_BYTES_HARD + 1).validate()


def test_offline_root_requires_system_hive_and_kernel(tmp_path: Path):
    root = tmp_path / "bad"
    root.mkdir()
    with pytest.raises(ValueError, match="markers missing"):
        rr3.validate_offline_windows_root(root)


def test_output_must_be_outside_target(tmp_path: Path):
    root = _offline_root(tmp_path)
    out = root / "evidence"
    with pytest.raises(ValueError, match="outside"):
        _scan(root, out)


def test_basic_scan_is_read_only_and_hashes_kernel(tmp_path: Path):
    root = _offline_root(tmp_path)
    before = _sha(root / "Windows" / "System32" / "ntoskrnl.exe")
    result = _scan(root, tmp_path / "out")
    after = _sha(root / "Windows" / "System32" / "ntoskrnl.exe")
    assert before == after
    assert result["safety"]["target_read_only"] is True
    assert result["safety"]["target_filesystem_write"] is False
    assert result["safety"]["file_delete"] is False
    assert result["safety"]["repair_engine_enabled"] is False
    assert any(item["relative_path"].endswith("ntoskrnl.exe") for item in result["findings"])


def test_approved_sha256_ioc_is_deterministic(tmp_path: Path):
    root = _offline_root(tmp_path)
    sample = root / "Windows" / "System32" / "drivers" / "rr3-fixture.sys"
    sample.parent.mkdir(parents=True, exist_ok=True)
    sample.write_bytes(b"harmless deterministic IOC fixture")
    catalog = tmp_path / "intel.json"
    catalog.write_text(
        json.dumps(
            {
                "schema": "bc-sentinel-offline-intel-v1",
                "approved": True,
                "sha256": [{"value": _sha(sample), "name": "RR3.Test.IOC", "source": "acceptance"}],
            }
        ),
        encoding="utf-8",
    )
    result = _scan(root, tmp_path / "out", intel_catalog=catalog)
    matches = [item for item in result["findings"] if item["ioc_name"] == "RR3.Test.IOC"]
    assert len(matches) == 1
    assert matches[0]["verdict"] == "deterministic_ioc"
    assert matches[0]["automatic_action"] is False
    assert result["summary"]["ioc_hits"] == 1


def test_intel_catalog_must_be_explicitly_approved(tmp_path: Path):
    catalog = tmp_path / "intel.json"
    catalog.write_text(json.dumps({"schema": "bc-sentinel-offline-intel-v1", "approved": False, "sha256": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="not explicitly approved"):
        rr3.load_approved_intel_catalog(catalog)


def test_intel_catalog_schema_is_guarded(tmp_path: Path):
    catalog = tmp_path / "intel.json"
    catalog.write_text(json.dumps({"schema": "other", "approved": True, "sha256": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="schema mismatch"):
        rr3.load_approved_intel_catalog(catalog)


def test_intel_catalog_rejects_bad_hash(tmp_path: Path):
    catalog = tmp_path / "intel.json"
    catalog.write_text(
        json.dumps({"schema": "bc-sentinel-offline-intel-v1", "approved": True, "sha256": [{"value": "bad"}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid SHA-256"):
        rr3.load_approved_intel_catalog(catalog)


def test_startup_script_is_review_only(tmp_path: Path):
    root = _offline_root(tmp_path)
    script = root / "ProgramData" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "login.ps1"
    script.parent.mkdir(parents=True)
    script.write_text("Write-Output harmless", encoding="utf-8")
    result = _scan(root, tmp_path / "out")
    item = next(item for item in result["findings"] if item["relative_path"].endswith("login.ps1"))
    assert "startup_location_artifact" in item["reasons"]
    assert "startup_script" in item["reasons"]
    assert item["verdict"] == "review"
    assert item["automatic_action"] is False


def test_user_temp_executable_is_review_only(tmp_path: Path):
    root = _offline_root(tmp_path)
    sample = root / "Users" / "Alice" / "AppData" / "Local" / "Temp" / "thing.exe"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(b"MZ harmless")
    result = _scan(root, tmp_path / "out")
    item = next(item for item in result["findings"] if item["relative_path"].endswith("thing.exe"))
    assert "executable_or_script_in_user_temp" in item["reasons"]
    assert item["automatic_action"] is False


def test_lolbin_name_outside_system_directory_is_review_only(tmp_path: Path):
    root = _offline_root(tmp_path)
    sample = root / "Users" / "Alice" / "AppData" / "Local" / "Temp" / "powershell.exe"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(b"MZ harmless")
    result = _scan(root, tmp_path / "out")
    item = next(item for item in result["findings"] if item["relative_path"].endswith("powershell.exe"))
    assert "lolbin_name_outside_windows_system_directory" in item["reasons"]
    assert item["verdict"] == "review"


def test_double_extension_lure_is_review_only(tmp_path: Path):
    root = _offline_root(tmp_path)
    sample = root / "Users" / "Alice" / "AppData" / "Local" / "Temp" / "invoice.pdf.exe"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(b"MZ harmless")
    result = _scan(root, tmp_path / "out")
    item = next(item for item in result["findings"] if item["relative_path"].endswith("invoice.pdf.exe"))
    assert "double_extension_lure" in item["reasons"]


def test_large_candidate_is_skipped_not_read(tmp_path: Path):
    root = _offline_root(tmp_path)
    sample = root / "Windows" / "System32" / "drivers" / "large.sys"
    sample.parent.mkdir(parents=True, exist_ok=True)
    sample.write_bytes(b"x" * 128)
    result = _scan(root, tmp_path / "out", limits=rr3.OfflineScanLimits(max_files=128, max_file_bytes=32))
    item = next(item for item in result["findings"] if item["relative_path"].endswith("large.sys"))
    assert item["status"] == "skipped"
    assert "file_too_large" in item["reasons"]


def test_registry_hive_metadata_is_read_only(tmp_path: Path):
    root = _offline_root(tmp_path)
    ntuser = root / "Users" / "Alice" / "NTUSER.DAT"
    ntuser.parent.mkdir(parents=True)
    ntuser.write_bytes(b"NTUSER-HIVE")
    result = _scan(root, tmp_path / "out")
    labels = {item["label"] for item in result["registry_hives"]}
    assert "system:SYSTEM" in labels
    assert "system:SOFTWARE" in labels
    assert "user:Alice:NTUSER.DAT" in labels
    assert all(item["write_attempted"] is False for item in result["registry_hives"])


def test_registry_hive_can_be_metadata_only_when_large(tmp_path: Path):
    root = _offline_root(tmp_path)
    system_hive = root / "Windows" / "System32" / "config" / "SYSTEM"
    system_hive.write_bytes(b"x" * 128)
    result = _scan(root, tmp_path / "out", limits=rr3.OfflineScanLimits(max_files=128, max_file_bytes=32))
    item = next(item for item in result["registry_hives"] if item["label"] == "system:SYSTEM")
    assert item["status"] == "metadata_only_file_too_large"
    assert item["sha256"] == ""


def test_yara_match_is_optional_and_review_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = _offline_root(tmp_path)
    sample = root / "Windows" / "System32" / "drivers" / "fixture.sys"
    sample.parent.mkdir(parents=True, exist_ok=True)
    sample.write_bytes(b"YARA harmless fixture marker")

    class Match:
        rule = "RR3_Test_Rule"

    class Rules:
        def match(self, filepath: str, timeout: int):
            assert timeout == 2
            return [Match()] if filepath.endswith("fixture.sys") else []

    monkeypatch.setattr(rr3, "_compile_yara", lambda path: (Rules(), "available"))
    result = _scan(root, tmp_path / "out", yara_rules=tmp_path / "rules.yar")
    item = next(item for item in result["findings"] if item["relative_path"].endswith("fixture.sys"))
    assert item["verdict"] == "yara_match"
    assert item["yara_matches"] == ["RR3_Test_Rule"]
    assert item["automatic_action"] is False


def test_scan_without_yara_remains_functional(tmp_path: Path):
    root = _offline_root(tmp_path)
    result = _scan(root, tmp_path / "out")
    assert result["intel"]["yara_requested"] is False
    assert result["intel"]["yara_status"] == "not_requested"


def test_max_files_is_bounded_and_reported(tmp_path: Path):
    root = _offline_root(tmp_path)
    drivers = root / "Windows" / "System32" / "drivers"
    drivers.mkdir(parents=True, exist_ok=True)
    for i in range(10):
        (drivers / f"fixture-{i}.sys").write_bytes(f"fixture-{i}".encode())
    result = _scan(root, tmp_path / "out", limits=rr3.OfflineScanLimits(max_files=3, max_file_bytes=1024))
    assert result["summary"]["enumerated"] == 3
    assert result["summary"]["truncated_by_max_files"] is True


def test_audit_contains_stage_reason_and_correlation(tmp_path: Path):
    root = _offline_root(tmp_path)
    out = tmp_path / "out"
    result = _scan(root, out)
    records = [json.loads(line) for line in (out / "rr3-audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert records[0]["stage"] == "scan_start"
    assert records[-1]["stage"] == "scan_complete"
    assert all(item["session_id"] == result["session_id"] for item in records)
    assert all(item["correlation_id"] == result["correlation_id"] for item in records)
    assert all(item["reason"] for item in records)


def test_result_is_written_outside_target(tmp_path: Path):
    root = _offline_root(tmp_path)
    out = tmp_path / "evidence"
    _scan(root, out)
    payload = json.loads((out / "rr3-offline-scan.json").read_text(encoding="utf-8"))
    assert payload["profile"] == rr3.PROFILE
    assert payload["safety"]["automatic_action"] is False
    assert payload["safety"]["recovery_certification_enabled"] is False


def test_target_tree_is_byte_identical_after_scan(tmp_path: Path):
    root = _offline_root(tmp_path)
    sample = root / "Users" / "Alice" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "harmless.cmd"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(b"@echo harmless")
    before = {str(p.relative_to(root)): _sha(p) for p in root.rglob("*") if p.is_file()}
    _scan(root, tmp_path / "out")
    after = {str(p.relative_to(root)): _sha(p) for p in root.rglob("*") if p.is_file()}
    assert before == after


def test_no_destructive_capabilities_are_exposed(tmp_path: Path):
    root = _offline_root(tmp_path)
    result = _scan(root, tmp_path / "out")
    safety = result["safety"]
    assert safety == {
        "target_read_only": True,
        "target_file_execution": False,
        "target_dll_loading": False,
        "target_shell_execution": False,
        "registry_write": False,
        "boot_write": False,
        "target_filesystem_write": False,
        "file_delete": False,
        "process_kill": False,
        "quarantine_execution": False,
        "repair_engine_enabled": False,
        "recovery_certification_enabled": False,
        "network_required": False,
        "cloud_required": False,
        "automatic_action": False,
    }
