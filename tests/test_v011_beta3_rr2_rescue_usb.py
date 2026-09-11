from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.rescue_usb import (
    PROFILE,
    UsbPrepareLimits,
    discover_offline_windows,
    prepare_rescue_usb,
    verify_rescue_usb,
)


def _source_payload(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    (source / "nested").mkdir(parents=True)
    (source / "BC-Sentinel-Rescue-Portable.exe").write_bytes(b"rr2 harmless portable fixture")
    (source / "nested" / "data.bin").write_bytes(bytes(range(16)))
    return source


def _empty_destination(tmp_path: Path) -> Path:
    destination = tmp_path / "usb-sim"
    destination.mkdir()
    return destination


def test_rr2_prepare_simulation_copies_and_verifies_without_changing_source(tmp_path: Path) -> None:
    source = _source_payload(tmp_path)
    destination = _empty_destination(tmp_path)
    before = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    result = prepare_rescue_usb(source, destination, simulation=True, limits=UsbPrepareLimits(max_files=32, max_total_bytes=1024 * 1024))
    after = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    assert result["profile"] == PROFILE
    assert result["verification"]["passed"] is True
    assert result["summary"]["files"] == 2
    assert before == after
    assert (destination / "rescue-usb-manifest.json").is_file()
    assert (destination / "rescue-usb-audit.jsonl").is_file()


def test_rr2_manifest_uses_sha256_and_no_destructive_capabilities(tmp_path: Path) -> None:
    source = _source_payload(tmp_path)
    destination = _empty_destination(tmp_path)
    result = prepare_rescue_usb(source, destination, simulation=True)
    assert all(len(item["sha256"]) == 64 for item in result["records"])
    safety = result["safety"]
    assert safety["format_disk"] is False
    assert safety["partition_write"] is False
    assert safety["boot_sector_write"] is False
    assert safety["bootloader_install"] is False
    assert safety["bcd_write"] is False
    assert safety["firmware_write"] is False
    assert safety["registry_write"] is False
    assert safety["target_filesystem_write"] is False
    assert safety["file_delete"] is False
    assert safety["repair_engine_enabled"] is False
    assert safety["quarantine_execution_enabled"] is False
    assert safety["recovery_certification_enabled"] is False


def test_rr2_refuses_nonempty_destination_without_deleting_content(tmp_path: Path) -> None:
    source = _source_payload(tmp_path)
    destination = _empty_destination(tmp_path)
    marker = destination / "keep-me.txt"
    marker.write_text("must survive", encoding="utf-8")
    with pytest.raises(ValueError, match="destination must be empty"):
        prepare_rescue_usb(source, destination, simulation=True)
    assert marker.read_text(encoding="utf-8") == "must survive"


def test_rr2_refuses_destination_inside_source(tmp_path: Path) -> None:
    source = _source_payload(tmp_path)
    destination = source / "destination"
    destination.mkdir()
    with pytest.raises(ValueError, match="destination may not be inside source"):
        prepare_rescue_usb(source, destination, simulation=True)


def test_rr2_refuses_source_inside_destination(tmp_path: Path) -> None:
    destination = _empty_destination(tmp_path)
    source = destination / "source"
    source.mkdir()
    (source / "a.bin").write_bytes(b"a")
    with pytest.raises(ValueError, match="source payload may not be inside destination"):
        prepare_rescue_usb(source, destination, simulation=True)


def test_rr2_refuses_direct_filesystem_root_even_in_simulation(tmp_path: Path) -> None:
    source = _source_payload(tmp_path)
    root = Path(tmp_path.resolve().anchor)
    with pytest.raises(ValueError, match="filesystem root"):
        prepare_rescue_usb(source, root, simulation=True)


def test_rr2_detects_tampered_payload(tmp_path: Path) -> None:
    source = _source_payload(tmp_path)
    destination = _empty_destination(tmp_path)
    prepare_rescue_usb(source, destination, simulation=True)
    copied = destination / "payload" / "BC-Sentinel-Rescue-Portable.exe"
    copied.write_bytes(b"tampered")
    verification = verify_rescue_usb(destination)
    assert verification["passed"] is False
    assert any(item.startswith("sha256_mismatch:") or item.startswith("size_mismatch:") for item in verification["errors"])


def test_rr2_detects_unexpected_payload_file(tmp_path: Path) -> None:
    source = _source_payload(tmp_path)
    destination = _empty_destination(tmp_path)
    prepare_rescue_usb(source, destination, simulation=True)
    (destination / "payload" / "unexpected.bin").write_bytes(b"x")
    verification = verify_rescue_usb(destination)
    assert verification["passed"] is False
    assert "unexpected_file:unexpected.bin" in verification["errors"]


def test_rr2_file_count_limit_is_enforced(tmp_path: Path) -> None:
    source = _source_payload(tmp_path)
    destination = _empty_destination(tmp_path)
    with pytest.raises(ValueError, match="max_files"):
        prepare_rescue_usb(source, destination, simulation=True, limits=UsbPrepareLimits(max_files=1, max_total_bytes=1024 * 1024))


def test_rr2_total_bytes_limit_is_enforced(tmp_path: Path) -> None:
    source = _source_payload(tmp_path)
    destination = _empty_destination(tmp_path)
    with pytest.raises(ValueError, match="max_total_bytes"):
        prepare_rescue_usb(source, destination, simulation=True, limits=UsbPrepareLimits(max_files=32, max_total_bytes=1))


def test_rr2_offline_windows_discovery_is_read_only(tmp_path: Path) -> None:
    candidate = tmp_path / "offline-c"
    config = candidate / "Windows" / "System32" / "config"
    system32 = candidate / "Windows" / "System32"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"harmless fake hive")
    (system32 / "ntoskrnl.exe").write_bytes(b"harmless fake kernel")
    before = (config / "SYSTEM").read_bytes(), (system32 / "ntoskrnl.exe").read_bytes()
    found = discover_offline_windows([candidate])
    after = (config / "SYSTEM").read_bytes(), (system32 / "ntoskrnl.exe").read_bytes()
    assert len(found) == 1
    assert found[0]["write_attempted"] is False
    assert before == after


def test_rr2_audit_contains_stage_status_reason_and_ids(tmp_path: Path) -> None:
    source = _source_payload(tmp_path)
    destination = _empty_destination(tmp_path)
    prepare_rescue_usb(source, destination, simulation=True)
    records = [json.loads(line) for line in (destination / "rescue-usb-audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert records
    for record in records:
        assert record["stage"]
        assert record["status"]
        assert record["reason"]
        assert record["session_id"].startswith("RR2-")
        assert record["correlation_id"]
        assert "elapsed_ms" in record


def test_rr2_limits_validate() -> None:
    UsbPrepareLimits().validate()
    with pytest.raises(ValueError):
        UsbPrepareLimits(max_files=0).validate()
    with pytest.raises(ValueError):
        UsbPrepareLimits(max_total_bytes=0).validate()
