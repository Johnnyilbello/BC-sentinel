from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct

import pytest

from sentinel import rescue_offline_scanner as rr3
from sentinel import static_pe_preflight as pecheck


def _minimal_pe(*, characteristics: int = 0x60000020) -> bytes:
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    struct.pack_into("<HHIIIHH", data, coff, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 4, 0x200)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<I", data, optional + 24, 0x2000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<H", data, optional + 40, 4)
    struct.pack_into("<H", data, optional + 48, 4)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + 72, 0x100000)
    struct.pack_into("<I", data, optional + 76, 0x1000)
    struct.pack_into("<I", data, optional + 80, 0x100000)
    struct.pack_into("<I", data, optional + 84, 0x1000)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 0xE0
    data[section:section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, section + 8, 0x200)
    struct.pack_into("<I", data, section + 12, 0x1000)
    struct.pack_into("<I", data, section + 16, 0x200)
    struct.pack_into("<I", data, section + 20, 0x200)
    struct.pack_into("<I", data, section + 36, characteristics)
    data[0x200:0x400] = b"\x90" * 0x200
    return bytes(data)


def _offline_root(base: Path) -> Path:
    root = base / "offline"
    config = root / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"SYSTEM-HIVE")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(
        _minimal_pe()
    )
    return root


def _scan(root: Path, output: Path, **kwargs):
    return rr3.scan_offline_windows(
        root,
        output,
        limits=rr3.OfflineScanLimits(max_files=128, max_file_bytes=1024 * 1024),
        **kwargs,
    )


def test_offline_scanner_embeds_accepted_pe_metadata_without_clean_claim(tmp_path: Path):
    root = _offline_root(tmp_path)
    sample = root / "Windows" / "System32" / "drivers" / "accepted.sys"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(_minimal_pe())

    report = _scan(root, tmp_path / "out")
    finding = next(item for item in report["findings"] if item["relative_path"].endswith("accepted.sys"))

    assert finding["pe_metadata_decision"] == "PE_METADATA_ACCEPTED"
    assert finding["pe_metadata_reasons"] == []
    assert finding["pe_sha256_matches"] is True
    assert finding["pe_clean_claimed"] is False
    assert finding["verdict"] == "observed"
    assert finding["automatic_action"] is False
    assert report["summary"]["pe_parsed_items"] >= 1
    assert report["safety"]["target_file_execution"] is False
    assert report["safety"]["quarantine_execution"] is False


def test_offline_scanner_promotes_wx_pe_metadata_to_review_only(tmp_path: Path):
    root = _offline_root(tmp_path)
    sample = root / "Users" / "Alice" / "AppData" / "Local" / "Temp" / "wx.exe"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(_minimal_pe(characteristics=0xE0000020))

    report = _scan(root, tmp_path / "out")
    finding = next(item for item in report["findings"] if item["relative_path"].endswith("wx.exe"))

    assert finding["pe_metadata_decision"] == "REVIEW_REQUIRED"
    assert "writable_executable_section" in finding["pe_metadata_reasons"]
    assert "pe_metadata:writable_executable_section" in finding["reasons"]
    assert finding["verdict"] == "review"
    assert finding["automatic_action"] is False
    assert report["summary"]["pe_review_items"] >= 1


def test_malformed_pe_is_visible_but_never_called_clean(tmp_path: Path):
    root = _offline_root(tmp_path)
    sample = root / "Windows" / "System32" / "drivers" / "broken.sys"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(b"MZ-not-valid")

    report = _scan(root, tmp_path / "out")
    finding = next(item for item in report["findings"] if item["relative_path"].endswith("broken.sys"))

    assert finding["pe_metadata_decision"] == "REJECTED"
    assert "malformed_pe" in finding["pe_metadata_reasons"]
    assert finding["pe_clean_claimed"] is False
    assert finding["verdict"] == "review"
    assert report["summary"]["pe_rejected_items"] >= 1


def test_artifact_change_during_static_scan_invalidates_deterministic_ioc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root = _offline_root(tmp_path)
    sample = root / "Windows" / "System32" / "drivers" / "changing.sys"
    sample.parent.mkdir(parents=True)
    raw = _minimal_pe()
    sample.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()

    catalog = tmp_path / "intel.json"
    catalog.write_text(
        json.dumps(
            {
                "schema": "bc-sentinel-offline-intel-v1",
                "approved": True,
                "sha256": [
                    {
                        "value": digest,
                        "name": "T2.Change.Binding.Test",
                        "source": "acceptance",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    real_inspect = pecheck.inspect_pe_metadata

    def changed_digest(path: Path, *, max_bytes: int = pecheck.MAX_PE_BYTES):
        result = real_inspect(path, max_bytes=max_bytes)
        if path.name == "changing.sys":
            return pecheck.PEMetadataPreflight(
                passed=result.passed,
                decision=result.decision,
                reasons=result.reasons,
                file_size=result.file_size,
                sha256="0" * 64,
                machine=result.machine,
                section_count=result.section_count,
                entrypoint_rva=result.entrypoint_rva,
                image_base=result.image_base,
                timestamp=result.timestamp,
                executable_sections=result.executable_sections,
                writable_executable_sections=result.writable_executable_sections,
                high_entropy_sections=result.high_entropy_sections,
            )
        return result

    monkeypatch.setattr(rr3.static_pe_preflight, "inspect_pe_metadata", changed_digest)

    report = _scan(root, tmp_path / "out", intel_catalog=catalog)
    finding = next(item for item in report["findings"] if item["relative_path"].endswith("changing.sys"))

    assert finding["ioc_name"] == "T2.Change.Binding.Test"
    assert finding["pe_sha256_matches"] is False
    assert "artifact_changed_during_static_scan" in finding["reasons"]
    assert finding["verdict"] == "review"
    assert finding["automatic_action"] is False
    assert report["summary"]["pe_unstable_items"] == 1


def test_script_candidates_do_not_fake_pe_metadata(tmp_path: Path):
    root = _offline_root(tmp_path)
    script = root / "ProgramData" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "safe.ps1"
    script.parent.mkdir(parents=True)
    script.write_text("Write-Output safe", encoding="utf-8")

    report = _scan(root, tmp_path / "out")
    finding = next(item for item in report["findings"] if item["relative_path"].endswith("safe.ps1"))

    assert finding["pe_metadata_decision"] == ""
    assert finding["pe_metadata_reasons"] == []
    assert finding["pe_sha256_matches"] is None
    assert finding["pe_clean_claimed"] is False


def test_unscanned_pe_hash_is_not_misreported_as_artifact_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root = _offline_root(tmp_path)
    sample = root / "Windows" / "System32" / "drivers" / "bounded.sys"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(_minimal_pe())

    real_inspect = pecheck.inspect_pe_metadata

    def bounded_reject(path: Path, *, max_bytes: int = pecheck.MAX_PE_BYTES):
        if path.name == "bounded.sys":
            return pecheck.PEMetadataPreflight(
                passed=False,
                decision="REJECTED",
                reasons=("pe_size_limit",),
                file_size=path.stat().st_size,
                sha256="",
                machine=0,
                section_count=0,
                entrypoint_rva=0,
                image_base=0,
                timestamp=0,
                executable_sections=(),
                writable_executable_sections=(),
                high_entropy_sections=(),
            )
        return real_inspect(path, max_bytes=max_bytes)

    monkeypatch.setattr(rr3.static_pe_preflight, "inspect_pe_metadata", bounded_reject)

    report = _scan(root, tmp_path / "out")
    finding = next(item for item in report["findings"] if item["relative_path"].endswith("bounded.sys"))

    assert finding["pe_metadata_decision"] == "REJECTED"
    assert finding["pe_sha256_matches"] is None
    assert "artifact_changed_during_static_scan" not in finding["reasons"]
    assert report["summary"]["pe_unstable_items"] == 0
