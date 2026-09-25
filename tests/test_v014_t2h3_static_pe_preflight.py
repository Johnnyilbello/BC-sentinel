from __future__ import annotations

import hashlib
from pathlib import Path
import struct

import pytest

from sentinel import static_pe_preflight as pecheck


def _minimal_pe(
    *,
    entrypoint: int = 0x1000,
    section_characteristics: int = 0x60000020,
    payload: bytes | None = None,
    declared_raw_size: int = 0x200,
) -> bytes:
    raw_pointer = 0x200
    physical_raw_size = 0x200
    data = bytearray(raw_pointer + physical_raw_size)

    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)

    pe_offset = 0x80
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    coff = pe_offset + 4
    struct.pack_into(
        "<HHIIIHH",
        data,
        coff,
        0x014C,  # IMAGE_FILE_MACHINE_I386
        1,
        0,
        0,
        0,
        0x00E0,
        0x0102,
    )

    optional = coff + 20
    struct.pack_into("<H", data, optional + 0, 0x010B)
    struct.pack_into("<I", data, optional + 4, 0x200)
    struct.pack_into("<I", data, optional + 16, entrypoint)
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<I", data, optional + 24, 0x2000)
    struct.pack_into("<I", data, optional + 28, 0x00400000)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<H", data, optional + 40, 4)
    struct.pack_into("<H", data, optional + 48, 4)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + 72, 0x00100000)
    struct.pack_into("<I", data, optional + 76, 0x00001000)
    struct.pack_into("<I", data, optional + 80, 0x00100000)
    struct.pack_into("<I", data, optional + 84, 0x00001000)
    struct.pack_into("<I", data, optional + 92, 16)

    section = optional + 0xE0
    data[section : section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, section + 8, 0x200)
    struct.pack_into("<I", data, section + 12, 0x1000)
    struct.pack_into("<I", data, section + 16, declared_raw_size)
    struct.pack_into("<I", data, section + 20, raw_pointer)
    struct.pack_into("<I", data, section + 36, section_characteristics)

    raw = payload if payload is not None else (b"\x90" * physical_raw_size)
    raw = (raw + (b"\x00" * physical_raw_size))[:physical_raw_size]
    data[raw_pointer : raw_pointer + physical_raw_size] = raw
    return bytes(data)


def _write(tmp_path: Path, data: bytes, name: str = "fixture.exe") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_minimal_pe_metadata_is_accepted_without_execution(tmp_path: Path):
    data = _minimal_pe()
    path = _write(tmp_path, data)
    before = hashlib.sha256(path.read_bytes()).hexdigest()

    report = pecheck.inspect_pe_metadata(path)

    assert report.passed is True
    assert report.decision == "PE_METADATA_ACCEPTED"
    assert report.reasons == ()
    assert report.machine == 0x014C
    assert report.section_count == 1
    assert report.entrypoint_rva == 0x1000
    assert report.executable_sections == (".text",)
    assert report.writable_executable_sections == ()
    assert report.content_executed is False
    assert report.image_loaded is False
    assert report.imports_resolved is False
    assert report.target_modified is False
    assert report.quarantine_performed is False
    assert report.clean_claimed is False
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


def test_writable_executable_section_requires_review(tmp_path: Path):
    path = _write(
        tmp_path,
        _minimal_pe(section_characteristics=0xE0000020),
        "wx.exe",
    )
    report = pecheck.inspect_pe_metadata(path)
    assert report.passed is False
    assert report.decision == "REVIEW_REQUIRED"
    assert "writable_executable_section" in report.reasons
    assert ".text" in report.writable_executable_sections


def test_high_entropy_section_requires_review(tmp_path: Path):
    payload = bytes(range(256)) * 2
    path = _write(tmp_path, _minimal_pe(payload=payload), "packed.exe")
    report = pecheck.inspect_pe_metadata(path)
    assert report.passed is False
    assert "high_entropy_section" in report.reasons
    assert ".text" in report.high_entropy_sections


def test_entrypoint_outside_sections_requires_review(tmp_path: Path):
    path = _write(tmp_path, _minimal_pe(entrypoint=0x5000), "outside.exe")
    report = pecheck.inspect_pe_metadata(path)
    assert report.passed is False
    assert "entrypoint_outside_sections" in report.reasons


def test_section_raw_bounds_are_checked(tmp_path: Path):
    path = _write(
        tmp_path,
        _minimal_pe(declared_raw_size=0x1000),
        "bad-bounds.exe",
    )
    report = pecheck.inspect_pe_metadata(path)
    assert report.passed is False
    assert "section_raw_bounds_invalid" in report.reasons


def test_malformed_pe_is_rejected_without_execution(tmp_path: Path):
    path = _write(tmp_path, b"MZ-not-a-valid-pe", "broken.exe")
    report = pecheck.inspect_pe_metadata(path)
    assert report.passed is False
    assert report.decision == "REJECTED"
    assert report.reasons == ("malformed_pe",)
    assert report.content_executed is False
    assert report.image_loaded is False


def test_unsupported_suffix_is_rejected(tmp_path: Path):
    path = _write(tmp_path, _minimal_pe(), "fixture.txt")
    report = pecheck.inspect_pe_metadata(path)
    assert report.passed is False
    assert report.reasons == ("unsupported_or_non_file",)


def test_pe_size_limit_is_enforced_before_parser(tmp_path: Path):
    path = _write(tmp_path, _minimal_pe(), "bounded.exe")
    report = pecheck.inspect_pe_metadata(path, max_bytes=512)
    assert report.passed is False
    assert report.reasons == ("pe_size_limit",)


@pytest.mark.parametrize("bad", [True, 0, -1, 1.5, "1024"])
def test_pe_limit_type_confusion_fails_closed(tmp_path: Path, bad):
    path = _write(tmp_path, _minimal_pe())
    report = pecheck.inspect_pe_metadata(path, max_bytes=bad)  # type: ignore[arg-type]
    assert report.passed is False
    assert report.reasons == ("pe_limit_invalid",)


def test_pe_sha256_is_of_exact_bounded_input(tmp_path: Path):
    data = _minimal_pe()
    path = _write(tmp_path, data)
    report = pecheck.inspect_pe_metadata(path)
    assert report.sha256 == hashlib.sha256(data).hexdigest()
