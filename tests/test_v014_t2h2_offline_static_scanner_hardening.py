from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import rescue_offline_scanner as rr3


SAFE_MARKER = b"BC_SENTINEL_T2_SAFE_STATIC_MARKER_2026"


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _offline_root(base: Path) -> Path:
    root = base / "offline"
    config = root / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"SYSTEM-HIVE")
    system32 = root / "Windows" / "System32"
    (system32 / "ntoskrnl.exe").write_bytes(b"MZ-safe-kernel-fixture")
    return root


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("max_files", True),
        ("max_files", "10"),
        ("max_files", 1.5),
        ("max_file_bytes", True),
        ("max_file_bytes", "1024"),
        ("max_file_bytes", 1.5),
    ],
    ids=[
        "files-bool",
        "files-string",
        "files-float",
        "bytes-bool",
        "bytes-string",
        "bytes-float",
    ],
)
def test_offline_scan_limits_require_real_integers(field, bad):
    kwargs = {"max_files": 10, "max_file_bytes": 1024}
    kwargs[field] = bad
    with pytest.raises(ValueError, match="bounded limit"):
        rr3.OfflineScanLimits(**kwargs).validate()


def test_missing_offline_root_fails_as_validation_error(tmp_path: Path):
    with pytest.raises(ValueError, match="offline root"):
        rr3.validate_offline_windows_root(tmp_path / "missing")


def test_intel_catalog_requires_object_top_level(tmp_path: Path):
    path = tmp_path / "intel.json"
    path.write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(ValueError, match="must be an object"):
        rr3.load_approved_intel_catalog(path)


def test_intel_catalog_rejects_duplicate_hash_identity(tmp_path: Path):
    digest = "a" * 64
    path = tmp_path / "intel.json"
    path.write_text(
        json.dumps(
            {
                "schema": "bc-sentinel-offline-intel-v1",
                "approved": True,
                "sha256": [
                    {"value": digest, "name": "first", "source": "lab"},
                    {"value": digest, "name": "second", "source": "lab"},
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate SHA-256"):
        rr3.load_approved_intel_catalog(path)


def test_intel_catalog_rejects_hidden_extra_payload_fields(tmp_path: Path):
    path = tmp_path / "intel.json"
    path.write_text(
        json.dumps(
            {
                "schema": "bc-sentinel-offline-intel-v1",
                "approved": True,
                "sha256": [
                    {
                        "value": "a" * 64,
                        "name": "safe",
                        "source": "lab",
                        "raw_sample_bytes": "forbidden",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="fields invalid"):
        rr3.load_approved_intel_catalog(path)


@pytest.mark.parametrize("field", ["name", "source"])
def test_intel_catalog_rejects_control_character_metadata(tmp_path: Path, field: str):
    item = {"value": "a" * 64, "name": "safe", "source": "lab"}
    item[field] = "trusted\nforged"
    path = tmp_path / "intel.json"
    path.write_text(
        json.dumps(
            {
                "schema": "bc-sentinel-offline-intel-v1",
                "approved": True,
                "sha256": [item],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=f"{field} invalid"):
        rr3.load_approved_intel_catalog(path)


def test_yara_rule_file_is_bounded_before_compile(tmp_path: Path):
    rule_path = tmp_path / "oversized.yar"
    rule_path.write_bytes(b"x" * (rr3.MAX_YARA_RULE_BYTES + 1))
    with pytest.raises(ValueError, match="bounded size"):
        rr3._compile_yara(rule_path)


def test_real_yara_and_hash_ioc_static_pipeline_on_safe_artifact(tmp_path: Path):
    root = _offline_root(tmp_path)
    sample = root / "Windows" / "System32" / "drivers" / "t2-safe-fixture.sys"
    sample.parent.mkdir(parents=True, exist_ok=True)
    sample.write_bytes(b"MZ" + SAFE_MARKER + b"\x00STATIC_ONLY")

    original = sample.read_bytes()
    catalog = tmp_path / "intel.json"
    catalog.write_text(
        json.dumps(
            {
                "schema": "bc-sentinel-offline-intel-v1",
                "approved": True,
                "sha256": [
                    {
                        "value": _sha_bytes(original),
                        "name": "BC.T2.Safe.Static.IOC",
                        "source": "internal-safe-artifact",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    rules = tmp_path / "t2-safe.yar"
    rules.write_text(
        """
rule BC_T2_SAFE_STATIC_MARKER
{
    strings:
        $marker = "BC_SENTINEL_T2_SAFE_STATIC_MARKER_2026" ascii
    condition:
        $marker
}
""".strip() + "\n",
        encoding="utf-8",
    )

    out = tmp_path / "evidence"
    result = rr3.scan_offline_windows(
        root,
        out,
        limits=rr3.OfflineScanLimits(max_files=128, max_file_bytes=1024 * 1024),
        intel_catalog=catalog,
        yara_rules=rules,
    )

    item = next(
        row for row in result["findings"]
        if row["relative_path"].endswith("t2-safe-fixture.sys")
    )
    assert item["sha256"] == _sha_bytes(original)
    assert item["verdict"] == "deterministic_ioc"
    assert item["ioc_name"] == "BC.T2.Safe.Static.IOC"
    assert item["yara_matches"] == ["BC_T2_SAFE_STATIC_MARKER"]
    assert item["automatic_action"] is False

    assert result["summary"]["ioc_hits"] == 1
    assert result["summary"]["yara_hits"] == 1
    assert result["intel"]["yara_status"] == "available"
    assert result["safety"]["target_file_execution"] is False
    assert result["safety"]["target_filesystem_write"] is False
    assert result["safety"]["quarantine_execution"] is False
    assert result["safety"]["network_required"] is False
    assert sample.read_bytes() == original


def test_safe_static_artifact_is_never_executed_or_quarantined(tmp_path: Path):
    root = _offline_root(tmp_path)
    sample = root / "Users" / "Alice" / "AppData" / "Local" / "Temp" / "fixture.exe"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(b"MZ" + SAFE_MARKER)

    result = rr3.scan_offline_windows(
        root,
        tmp_path / "out",
        limits=rr3.OfflineScanLimits(max_files=64, max_file_bytes=1024 * 1024),
    )
    item = next(row for row in result["findings"] if row["relative_path"].endswith("fixture.exe"))
    assert item["automatic_action"] is False
    assert result["safety"]["target_file_execution"] is False
    assert result["safety"]["quarantine_execution"] is False
