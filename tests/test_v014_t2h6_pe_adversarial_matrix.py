from __future__ import annotations

from pathlib import Path
import struct

from sentinel import static_pe_preflight as pecheck


def _build_pe(
    *,
    machine: int = 0x014C,
    optional_magic: int = 0x010B,
    entrypoint: int = 0x1000,
    file_alignment: int = 0x200,
    section_alignment: int = 0x1000,
    sections: list[dict] | None = None,
) -> bytes:
    sections = sections or [
        {
            "name": b".text",
            "virtual_size": 0x200,
            "virtual_address": 0x1000,
            "raw_size": 0x200,
            "raw_pointer": 0x200,
            "characteristics": 0x60000020,
            "payload": b"\x90" * 0x200,
        }
    ]
    optional_size = 0xE0 if optional_magic == 0x010B else 0xF0
    headers_end = 0x80 + 4 + 20 + optional_size + 40 * len(sections)
    size_of_headers = ((headers_end + 0x1FF) // 0x200) * 0x200

    file_end = size_of_headers
    for section in sections:
        raw_pointer = int(section["raw_pointer"])
        raw_size = int(section["raw_size"])
        file_end = max(file_end, raw_pointer + raw_size)
    data = bytearray(file_end)

    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"

    coff = 0x84
    struct.pack_into(
        "<HHIIIHH",
        data,
        coff,
        machine,
        len(sections),
        0,
        0,
        0,
        optional_size,
        0x0102,
    )

    optional = coff + 20
    struct.pack_into("<H", data, optional, optional_magic)
    struct.pack_into("<I", data, optional + 4, 0x200)
    struct.pack_into("<I", data, optional + 16, entrypoint)

    if optional_magic == 0x010B:
        struct.pack_into("<I", data, optional + 20, 0x1000)
        struct.pack_into("<I", data, optional + 24, 0x2000)
        struct.pack_into("<I", data, optional + 28, 0x00400000)
        image_base_offset = optional + 28
        section_alignment_offset = optional + 32
        file_alignment_offset = optional + 36
        size_image_offset = optional + 56
        size_headers_offset = optional + 60
        subsystem_offset = optional + 68
        num_dirs_offset = optional + 92
    else:
        struct.pack_into("<I", data, optional + 20, 0x1000)
        struct.pack_into("<Q", data, optional + 24, 0x0000000140000000)
        image_base_offset = optional + 24
        section_alignment_offset = optional + 32
        file_alignment_offset = optional + 36
        size_image_offset = optional + 56
        size_headers_offset = optional + 60
        subsystem_offset = optional + 68
        num_dirs_offset = optional + 108

    struct.pack_into("<I", data, section_alignment_offset, section_alignment)
    struct.pack_into("<I", data, file_alignment_offset, file_alignment)
    struct.pack_into("<H", data, optional + 40, 6)
    struct.pack_into("<H", data, optional + 48, 6)

    max_virtual_end = 0x1000
    for section in sections:
        max_virtual_end = max(
            max_virtual_end,
            int(section["virtual_address"]) + max(int(section["virtual_size"]), int(section["raw_size"])),
        )
    size_of_image = ((max_virtual_end + max(section_alignment, 1) - 1) // max(section_alignment, 1)) * max(section_alignment, 1)

    struct.pack_into("<I", data, size_image_offset, size_of_image)
    struct.pack_into("<I", data, size_headers_offset, size_of_headers)
    struct.pack_into("<H", data, subsystem_offset, 3)
    struct.pack_into("<I", data, num_dirs_offset, 16)

    section_table = optional + optional_size
    for index, section in enumerate(sections):
        offset = section_table + 40 * index
        name = bytes(section["name"])[:8]
        data[offset : offset + 8] = name.ljust(8, b"\x00")
        struct.pack_into("<I", data, offset + 8, int(section["virtual_size"]))
        struct.pack_into("<I", data, offset + 12, int(section["virtual_address"]))
        struct.pack_into("<I", data, offset + 16, int(section["raw_size"]))
        struct.pack_into("<I", data, offset + 20, int(section["raw_pointer"]))
        struct.pack_into("<I", data, offset + 36, int(section["characteristics"]))
        raw_pointer = int(section["raw_pointer"])
        raw_size = int(section["raw_size"])
        payload = bytes(section.get("payload", b""))
        if raw_size and raw_pointer >= size_of_headers:
            data[raw_pointer : raw_pointer + raw_size] = (payload + b"\x00" * raw_size)[:raw_size]

    return bytes(data)


def _write(tmp_path: Path, data: bytes, name: str) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_entrypoint_in_non_executable_section_requires_review(tmp_path: Path):
    data = _build_pe(
        sections=[
            {
                "name": b".data",
                "virtual_size": 0x200,
                "virtual_address": 0x1000,
                "raw_size": 0x200,
                "raw_pointer": 0x200,
                "characteristics": 0xC0000040,
                "payload": b"A" * 0x200,
            }
        ]
    )
    report = pecheck.inspect_pe_metadata(_write(tmp_path, data, "nonexec.exe"))
    assert report.passed is False
    assert "entrypoint_in_non_executable_section" in report.reasons
    assert report.clean_claimed is False


def test_overlapping_virtual_sections_require_review(tmp_path: Path):
    data = _build_pe(
        sections=[
            {
                "name": b".text",
                "virtual_size": 0x300,
                "virtual_address": 0x1000,
                "raw_size": 0x200,
                "raw_pointer": 0x200,
                "characteristics": 0x60000020,
                "payload": b"\x90" * 0x200,
            },
            {
                "name": b".data",
                "virtual_size": 0x300,
                "virtual_address": 0x1100,
                "raw_size": 0x200,
                "raw_pointer": 0x400,
                "characteristics": 0xC0000040,
                "payload": b"A" * 0x200,
            },
        ]
    )
    report = pecheck.inspect_pe_metadata(_write(tmp_path, data, "virt-overlap.exe"))
    assert report.passed is False
    assert "overlapping_virtual_sections" in report.reasons


def test_duplicate_section_names_require_review(tmp_path: Path):
    data = _build_pe(
        sections=[
            {
                "name": b".same",
                "virtual_size": 0x200,
                "virtual_address": 0x1000,
                "raw_size": 0x200,
                "raw_pointer": 0x200,
                "characteristics": 0x60000020,
                "payload": b"\x90" * 0x200,
            },
            {
                "name": b".same",
                "virtual_size": 0x200,
                "virtual_address": 0x2000,
                "raw_size": 0x200,
                "raw_pointer": 0x400,
                "characteristics": 0x40000040,
                "payload": b"B" * 0x200,
            },
        ]
    )
    report = pecheck.inspect_pe_metadata(_write(tmp_path, data, "duplicate.exe"))
    assert report.passed is False
    assert "duplicate_section_name" in report.reasons


def test_non_printable_section_name_is_sanitized_and_reviewed(tmp_path: Path):
    data = _build_pe(
        sections=[
            {
                "name": b".te\nxt",
                "virtual_size": 0x200,
                "virtual_address": 0x1000,
                "raw_size": 0x200,
                "raw_pointer": 0x200,
                "characteristics": 0x60000020,
                "payload": b"\x90" * 0x200,
            }
        ]
    )
    report = pecheck.inspect_pe_metadata(_write(tmp_path, data, "control-name.exe"))
    assert report.passed is False
    assert "section_name_non_printable" in report.reasons
    assert all("\n" not in name and "\r" not in name for name in report.executable_sections)


def test_unknown_machine_type_is_review_only(tmp_path: Path):
    data = _build_pe(machine=0x9999)
    report = pecheck.inspect_pe_metadata(_write(tmp_path, data, "unknown-machine.exe"))
    assert report.passed is False
    assert "unknown_machine_type" in report.reasons
    assert report.decision == "REVIEW_REQUIRED"


def test_alignment_inversion_requires_review(tmp_path: Path):
    data = _build_pe(file_alignment=0x1000, section_alignment=0x200)
    report = pecheck.inspect_pe_metadata(_write(tmp_path, data, "alignment.exe"))
    assert report.passed is False
    assert "section_alignment_smaller_than_file_alignment" in report.reasons


def test_pe32_plus_x64_fixture_is_supported_without_execution(tmp_path: Path):
    data = _build_pe(machine=0x8664, optional_magic=0x020B)
    report = pecheck.inspect_pe_metadata(_write(tmp_path, data, "x64.exe"))
    assert report.passed is True
    assert report.machine == 0x8664
    assert report.content_executed is False
    assert report.image_loaded is False
    assert report.imports_resolved is False
    assert report.clean_claimed is False


def test_arm64_machine_is_known_for_static_metadata(tmp_path: Path):
    data = _build_pe(machine=0xAA64, optional_magic=0x020B)
    report = pecheck.inspect_pe_metadata(_write(tmp_path, data, "arm64.exe"))
    assert "unknown_machine_type" not in report.reasons
    assert report.content_executed is False
